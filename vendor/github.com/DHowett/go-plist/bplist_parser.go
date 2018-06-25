package plist

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"runtime"
	"time"
	"unicode/utf16"
)

const (
	signedHighBits = 0xFFFFFFFFFFFFFFFF
)

type offset uint64

type bplistParser struct {
	buffer []byte

	reader        io.ReadSeeker
	version       int
	objects       []cfValue // object ID to object
	trailer       bplistTrailer
	trailerOffset uint64

	containerStack []offset // slice of object offsets; manipulated during container deserialization
}

func (p *bplistParser) validateDocumentTrailer() {
	if p.trailer.OffsetTableOffset >= p.trailerOffset {
		panic(fmt.Errorf("offset table beyond beginning of trailer (0x%x, trailer@0x%x)", p.trailer.OffsetTableOffset, p.trailerOffset))
	}

	if p.trailer.OffsetTableOffset < 9 {
		panic(fmt.Errorf("offset table begins inside header (0x%x)", p.trailer.OffsetTableOffset))
	}

	if p.trailerOffset > (p.trailer.NumObjects*uint64(p.trailer.OffsetIntSize))+p.trailer.OffsetTableOffset {
		panic(errors.New("garbage between offset table and trailer"))
	}

	if p.trailer.OffsetTableOffset+(uint64(p.trailer.OffsetIntSize)*p.trailer.NumObjects) > p.trailerOffset {
		panic(errors.New("offset table isn't long enough to address every object"))
	}

	maxObjectRef := uint64(1) << (8 * p.trailer.ObjectRefSize)
	if p.trailer.NumObjects > maxObjectRef {
		panic(fmt.Errorf("more objects (%v) than object ref size (%v bytes) can support", p.trailer.NumObjects, p.trailer.ObjectRefSize))
	}

	if p.trailer.OffsetIntSize < uint8(8) && (uint64(1)<<(8*p.trailer.OffsetIntSize)) <= p.trailer.OffsetTableOffset {
		panic(errors.New("offset size isn't big enough to address entire file"))
	}

	if p.trailer.TopObject >= p.trailer.NumObjects {
		panic(fmt.Errorf("top object #%d is out of range (only %d exist)", p.trailer.TopObject, p.trailer.NumObjects))
	}
}

func (p *bplistParser) parseDocument() (pval cfValue, parseError error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}

			parseError = plistParseError{"binary", r.(error)}
		}
	}()

	p.buffer, _ = ioutil.ReadAll(p.reader)

	l := len(p.buffer)
	if l < 40 {
		panic(errors.New("not enough data"))
	}

	if !bytes.Equal(p.buffer[0:6], []byte{'b', 'p', 'l', 'i', 's', 't'}) {
		panic(errors.New("incomprehensible magic"))
	}

	p.version = int(((p.buffer[6] - '0') * 10) + (p.buffer[7] - '0'))

	if p.version > 1 {
		panic(fmt.Errorf("unexpected version %d", p.version))
	}

	p.trailerOffset = uint64(l - 32)
	p.trailer = bplistTrailer{
		SortVersion:       p.buffer[p.trailerOffset+5],
		OffsetIntSize:     p.buffer[p.trailerOffset+6],
		ObjectRefSize:     p.buffer[p.trailerOffset+7],
		NumObjects:        binary.BigEndian.Uint64(p.buffer[p.trailerOffset+8:]),
		TopObject:         binary.BigEndian.Uint64(p.buffer[p.trailerOffset+16:]),
		OffsetTableOffset: binary.BigEndian.Uint64(p.buffer[p.trailerOffset+24:]),
	}

	p.validateDocumentTrailer()

	// INVARIANTS:
	// - Entire offset table is before trailer
	// - Offset table begins after header
	// - Offset table can address entire document
	// - Object IDs are big enough to support the number of objects in this plist
	// - Top object is in range

	p.objects = make([]cfValue, p.trailer.NumObjects)

	pval = p.objectAtIndex(p.trailer.TopObject)
	return
}

// parseSizedInteger returns a 128-bit integer as low64, high64
func (p *bplistParser) parseSizedInteger(off offset, nbytes int) (lo uint64, hi uint64, newOffset offset) {
	// Per comments in CoreFoundation, format version 00 requires that all
	// 1, 2 or 4-byte integers be interpreted as unsigned. 8-byte integers are
	// signed (always?) and therefore must be sign extended here.
	// negative 1, 2, or 4-byte integers are always emitted as 64-bit.
	switch nbytes {
	case 1:
		lo, hi = uint64(p.buffer[off]), 0
	case 2:
		lo, hi = uint64(binary.BigEndian.Uint16(p.buffer[off:])), 0
	case 4:
		lo, hi = uint64(binary.BigEndian.Uint32(p.buffer[off:])), 0
	case 8:
		lo = binary.BigEndian.Uint64(p.buffer[off:])
		if p.buffer[off]&0x80 != 0 {
			// sign extend if lo is signed
			hi = signedHighBits
		}
	case 16:
		lo, hi = binary.BigEndian.Uint64(p.buffer[off+8:]), binary.BigEndian.Uint64(p.buffer[off:])
	default:
		panic(errors.New("illegal integer size"))
	}
	newOffset = off + offset(nbytes)
	return
}

func (p *bplistParser) parseObjectRefAtOffset(off offset) (uint64, offset) {
	oid, _, next := p.parseSizedInteger(off, int(p.trailer.ObjectRefSize))
	return oid, next
}

func (p *bplistParser) parseOffsetAtOffset(off offset) (offset, offset) {
	parsedOffset, _, next := p.parseSizedInteger(off, int(p.trailer.OffsetIntSize))
	return offset(parsedOffset), next
}

func (p *bplistParser) objectAtIndex(index uint64) cfValue {
	if index >= p.trailer.NumObjects {
		panic(fmt.Errorf("invalid object#%d (max %d)", index, p.trailer.NumObjects))
	}

	if pval := p.objects[index]; pval != nil {
		return pval
	}

	off, _ := p.parseOffsetAtOffset(offset(p.trailer.OffsetTableOffset + (index * uint64(p.trailer.OffsetIntSize))))
	if off > offset(p.trailer.OffsetTableOffset-1) {
		panic(fmt.Errorf("object#%d starts beyond beginning of object table (0x%x, table@0x%x)", index, off, p.trailer.OffsetTableOffset))
	}

	pval := p.parseTagAtOffset(off)
	p.objects[index] = pval
	return pval

}

func (p *bplistParser) pushNestedObject(off offset) {
	for _, v := range p.containerStack {
		if v == off {
			p.panicNestedObject(off)
		}
	}
	p.containerStack = append(p.containerStack, off)
}

func (p *bplistParser) panicNestedObject(off offset) {
	ids := ""
	for _, v := range p.containerStack {
		ids += fmt.Sprintf("0x%x > ", v)
	}

	// %s0x%d: ids above ends with " > "
	panic(fmt.Errorf("self-referential collection@0x%x (%s0x%x) cannot be deserialized", off, ids, off))
}

func (p *bplistParser) popNestedObject() {
	p.containerStack = p.containerStack[:len(p.containerStack)-1]
}

func (p *bplistParser) parseTagAtOffset(off offset) cfValue {
	tag := p.buffer[off]

	switch tag & 0xF0 {
	case bpTagNull:
		switch tag & 0x0F {
		case bpTagBoolTrue, bpTagBoolFalse:
			return cfBoolean(tag == bpTagBoolTrue)
		}
	case bpTagInteger:
		lo, hi, _ := p.parseIntegerAtOffset(off)
		return &cfNumber{
			signed: hi == signedHighBits, // a signed integer is stored as a 128-bit integer with the top 64 bits set
			value:  lo,
		}
	case bpTagReal:
		nbytes := 1 << (tag & 0x0F)
		switch nbytes {
		case 4:
			bits := binary.BigEndian.Uint32(p.buffer[off+1:])
			return &cfReal{wide: false, value: float64(math.Float32frombits(bits))}
		case 8:
			bits := binary.BigEndian.Uint64(p.buffer[off+1:])
			return &cfReal{wide: true, value: math.Float64frombits(bits)}
		}
		panic(errors.New("illegal float size"))
	case bpTagDate:
		bits := binary.BigEndian.Uint64(p.buffer[off+1:])
		val := math.Float64frombits(bits)

		// Apple Epoch is 20110101000000Z
		// Adjust for UNIX Time
		val += 978307200

		sec, fsec := math.Modf(val)
		time := time.Unix(int64(sec), int64(fsec*float64(time.Second))).In(time.UTC)
		return cfDate(time)
	case bpTagData:
		data := p.parseDataAtOffset(off)
		return cfData(data)
	case bpTagASCIIString:
		str := p.parseASCIIStringAtOffset(off)
		return cfString(str)
	case bpTagUTF16String:
		str := p.parseUTF16StringAtOffset(off)
		return cfString(str)
	case bpTagUID: // Somehow different than int: low half is nbytes - 1 instead of log2(nbytes)
		lo, _, _ := p.parseSizedInteger(off+1, int(tag&0xF)+1)
		return cfUID(lo)
	case bpTagDictionary:
		return p.parseDictionaryAtOffset(off)
	case bpTagArray:
		return p.parseArrayAtOffset(off)
	}
	panic(fmt.Errorf("unexpected atom 0x%2.02x at offset 0x%x", tag, off))
}

func (p *bplistParser) parseIntegerAtOffset(off offset) (uint64, uint64, offset) {
	tag := p.buffer[off]
	return p.parseSizedInteger(off+1, 1<<(tag&0xF))
}

func (p *bplistParser) countForTagAtOffset(off offset) (uint64, offset) {
	tag := p.buffer[off]
	cnt := uint64(tag & 0x0F)
	if cnt == 0xF {
		cnt, _, off = p.parseIntegerAtOffset(off + 1)
		return cnt, off
	}
	return cnt, off + 1
}

func (p *bplistParser) parseDataAtOffset(off offset) []byte {
	len, start := p.countForTagAtOffset(off)
	if start+offset(len) > offset(p.trailer.OffsetTableOffset) {
		panic(fmt.Errorf("data@0x%x too long (%v bytes, max is %v)", off, len, p.trailer.OffsetTableOffset-uint64(start)))
	}
	return p.buffer[start : start+offset(len)]
}

func (p *bplistParser) parseASCIIStringAtOffset(off offset) string {
	len, start := p.countForTagAtOffset(off)
	if start+offset(len) > offset(p.trailer.OffsetTableOffset) {
		panic(fmt.Errorf("ascii string@0x%x too long (%v bytes, max is %v)", off, len, p.trailer.OffsetTableOffset-uint64(start)))
	}

	return zeroCopy8BitString(p.buffer, int(start), int(len))
}

func (p *bplistParser) parseUTF16StringAtOffset(off offset) string {
	len, start := p.countForTagAtOffset(off)
	bytes := len * 2
	if start+offset(bytes) > offset(p.trailer.OffsetTableOffset) {
		panic(fmt.Errorf("utf16 string@0x%x too long (%v bytes, max is %v)", off, bytes, p.trailer.OffsetTableOffset-uint64(start)))
	}

	u16s := make([]uint16, len)
	for i := offset(0); i < offset(len); i++ {
		u16s[i] = binary.BigEndian.Uint16(p.buffer[start+(i*2):])
	}
	runes := utf16.Decode(u16s)
	return string(runes)
}

func (p *bplistParser) parseObjectListAtOffset(off offset, count uint64) []cfValue {
	if off+offset(count*uint64(p.trailer.ObjectRefSize)) > offset(p.trailer.OffsetTableOffset) {
		panic(fmt.Errorf("list@0x%x length (%v) puts its end beyond the offset table at 0x%x", off, count, p.trailer.OffsetTableOffset))
	}
	objects := make([]cfValue, count)

	next := off
	var oid uint64
	for i := uint64(0); i < count; i++ {
		oid, next = p.parseObjectRefAtOffset(next)
		objects[i] = p.objectAtIndex(oid)
	}

	return objects
}

func (p *bplistParser) parseDictionaryAtOffset(off offset) *cfDictionary {
	p.pushNestedObject(off)
	defer p.popNestedObject()

	// a dictionary is an object list of [key key key val val val]
	cnt, start := p.countForTagAtOffset(off)
	objects := p.parseObjectListAtOffset(start, cnt*2)

	keys := make([]string, cnt)
	for i := uint64(0); i < cnt; i++ {
		if str, ok := objects[i].(cfString); ok {
			keys[i] = string(str)
		} else {
			panic(fmt.Errorf("dictionary@0x%x contains non-string key at index %d", off, i))
		}
	}

	return &cfDictionary{
		keys:   keys,
		values: objects[cnt:],
	}
}

func (p *bplistParser) parseArrayAtOffset(off offset) *cfArray {
	p.pushNestedObject(off)
	defer p.popNestedObject()

	// an array is just an object list
	cnt, start := p.countForTagAtOffset(off)
	return &cfArray{p.parseObjectListAtOffset(start, cnt)}
}

func newBplistParser(r io.ReadSeeker) *bplistParser {
	return &bplistParser{reader: r}
}
