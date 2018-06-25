package plist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf16"
)

func bplistMinimumIntSize(n uint64) int {
	switch {
	case n <= uint64(0xff):
		return 1
	case n <= uint64(0xffff):
		return 2
	case n <= uint64(0xffffffff):
		return 4
	default:
		return 8
	}
}

func bplistValueShouldUnique(pval cfValue) bool {
	switch pval.(type) {
	case cfString, *cfNumber, *cfReal, cfDate, cfData:
		return true
	}
	return false
}

type bplistGenerator struct {
	writer   *countedWriter
	objmap   map[interface{}]uint64 // maps pValue.hash()es to object locations
	objtable []cfValue
	trailer  bplistTrailer
}

func (p *bplistGenerator) flattenPlistValue(pval cfValue) {
	key := pval.hash()
	if bplistValueShouldUnique(pval) {
		if _, ok := p.objmap[key]; ok {
			return
		}
	}

	p.objmap[key] = uint64(len(p.objtable))
	p.objtable = append(p.objtable, pval)

	switch pval := pval.(type) {
	case *cfDictionary:
		pval.sort()
		for _, k := range pval.keys {
			p.flattenPlistValue(cfString(k))
		}
		for _, v := range pval.values {
			p.flattenPlistValue(v)
		}
	case *cfArray:
		for _, v := range pval.values {
			p.flattenPlistValue(v)
		}
	}
}

func (p *bplistGenerator) indexForPlistValue(pval cfValue) (uint64, bool) {
	v, ok := p.objmap[pval.hash()]
	return v, ok
}

func (p *bplistGenerator) generateDocument(root cfValue) {
	p.objtable = make([]cfValue, 0, 16)
	p.objmap = make(map[interface{}]uint64)
	p.flattenPlistValue(root)

	p.trailer.NumObjects = uint64(len(p.objtable))
	p.trailer.ObjectRefSize = uint8(bplistMinimumIntSize(p.trailer.NumObjects))

	p.writer.Write([]byte("bplist00"))

	offtable := make([]uint64, p.trailer.NumObjects)
	for i, pval := range p.objtable {
		offtable[i] = uint64(p.writer.BytesWritten())
		p.writePlistValue(pval)
	}

	p.trailer.OffsetIntSize = uint8(bplistMinimumIntSize(uint64(p.writer.BytesWritten())))
	p.trailer.TopObject = p.objmap[root.hash()]
	p.trailer.OffsetTableOffset = uint64(p.writer.BytesWritten())

	for _, offset := range offtable {
		p.writeSizedInt(offset, int(p.trailer.OffsetIntSize))
	}

	binary.Write(p.writer, binary.BigEndian, p.trailer)
}

func (p *bplistGenerator) writePlistValue(pval cfValue) {
	if pval == nil {
		return
	}

	switch pval := pval.(type) {
	case *cfDictionary:
		p.writeDictionaryTag(pval)
	case *cfArray:
		p.writeArrayTag(pval.values)
	case cfString:
		p.writeStringTag(string(pval))
	case *cfNumber:
		p.writeIntTag(pval.signed, pval.value)
	case *cfReal:
		if pval.wide {
			p.writeRealTag(pval.value, 64)
		} else {
			p.writeRealTag(pval.value, 32)
		}
	case cfBoolean:
		p.writeBoolTag(bool(pval))
	case cfData:
		p.writeDataTag([]byte(pval))
	case cfDate:
		p.writeDateTag(time.Time(pval))
	case cfUID:
		p.writeUIDTag(UID(pval))
	default:
		panic(fmt.Errorf("unknown plist type %t", pval))
	}
}

func (p *bplistGenerator) writeSizedInt(n uint64, nbytes int) {
	var val interface{}
	switch nbytes {
	case 1:
		val = uint8(n)
	case 2:
		val = uint16(n)
	case 4:
		val = uint32(n)
	case 8:
		val = n
	default:
		panic(errors.New("illegal integer size"))
	}
	binary.Write(p.writer, binary.BigEndian, val)
}

func (p *bplistGenerator) writeBoolTag(v bool) {
	tag := uint8(bpTagBoolFalse)
	if v {
		tag = bpTagBoolTrue
	}
	binary.Write(p.writer, binary.BigEndian, tag)
}

func (p *bplistGenerator) writeIntTag(signed bool, n uint64) {
	var tag uint8
	var val interface{}
	switch {
	case n <= uint64(0xff):
		val = uint8(n)
		tag = bpTagInteger | 0x0
	case n <= uint64(0xffff):
		val = uint16(n)
		tag = bpTagInteger | 0x1
	case n <= uint64(0xffffffff):
		val = uint32(n)
		tag = bpTagInteger | 0x2
	case n > uint64(0x7fffffffffffffff) && !signed:
		// 64-bit values are always *signed* in format 00.
		// Any unsigned value that doesn't intersect with the signed
		// range must be sign-extended and stored as a SInt128
		val = n
		tag = bpTagInteger | 0x4
	default:
		val = n
		tag = bpTagInteger | 0x3
	}

	binary.Write(p.writer, binary.BigEndian, tag)
	if tag&0xF == 0x4 {
		// SInt128; in the absence of true 128-bit integers in Go,
		// we'll just fake the top half. We only got here because
		// we had an unsigned 64-bit int that didn't fit,
		// so sign extend it with zeroes.
		binary.Write(p.writer, binary.BigEndian, uint64(0))
	}
	binary.Write(p.writer, binary.BigEndian, val)
}

func (p *bplistGenerator) writeUIDTag(u UID) {
	nbytes := bplistMinimumIntSize(uint64(u))
	tag := uint8(bpTagUID | (nbytes - 1))

	binary.Write(p.writer, binary.BigEndian, tag)
	p.writeSizedInt(uint64(u), nbytes)
}

func (p *bplistGenerator) writeRealTag(n float64, bits int) {
	var tag uint8 = bpTagReal | 0x3
	var val interface{} = n
	if bits == 32 {
		val = float32(n)
		tag = bpTagReal | 0x2
	}

	binary.Write(p.writer, binary.BigEndian, tag)
	binary.Write(p.writer, binary.BigEndian, val)
}

func (p *bplistGenerator) writeDateTag(t time.Time) {
	tag := uint8(bpTagDate) | 0x3
	val := float64(t.In(time.UTC).UnixNano()) / float64(time.Second)
	val -= 978307200 // Adjust to Apple Epoch

	binary.Write(p.writer, binary.BigEndian, tag)
	binary.Write(p.writer, binary.BigEndian, val)
}

func (p *bplistGenerator) writeCountedTag(tag uint8, count uint64) {
	marker := tag
	if count >= 0xF {
		marker |= 0xF
	} else {
		marker |= uint8(count)
	}

	binary.Write(p.writer, binary.BigEndian, marker)

	if count >= 0xF {
		p.writeIntTag(false, count)
	}
}

func (p *bplistGenerator) writeDataTag(data []byte) {
	p.writeCountedTag(bpTagData, uint64(len(data)))
	binary.Write(p.writer, binary.BigEndian, data)
}

func (p *bplistGenerator) writeStringTag(str string) {
	for _, r := range str {
		if r > 0x7F {
			utf16Runes := utf16.Encode([]rune(str))
			p.writeCountedTag(bpTagUTF16String, uint64(len(utf16Runes)))
			binary.Write(p.writer, binary.BigEndian, utf16Runes)
			return
		}
	}

	p.writeCountedTag(bpTagASCIIString, uint64(len(str)))
	binary.Write(p.writer, binary.BigEndian, []byte(str))
}

func (p *bplistGenerator) writeDictionaryTag(dict *cfDictionary) {
	// assumption: sorted already; flattenPlistValue did this.
	cnt := len(dict.keys)
	p.writeCountedTag(bpTagDictionary, uint64(cnt))
	vals := make([]uint64, cnt*2)
	for i, k := range dict.keys {
		// invariant: keys have already been "uniqued" (as PStrings)
		keyIdx, ok := p.objmap[cfString(k).hash()]
		if !ok {
			panic(errors.New("failed to find key " + k + " in object map during serialization"))
		}
		vals[i] = keyIdx
	}

	for i, v := range dict.values {
		// invariant: values have already been "uniqued"
		objIdx, ok := p.indexForPlistValue(v)
		if !ok {
			panic(errors.New("failed to find value in object map during serialization"))
		}
		vals[i+cnt] = objIdx
	}

	for _, v := range vals {
		p.writeSizedInt(v, int(p.trailer.ObjectRefSize))
	}
}

func (p *bplistGenerator) writeArrayTag(arr []cfValue) {
	p.writeCountedTag(bpTagArray, uint64(len(arr)))
	for _, v := range arr {
		objIdx, ok := p.indexForPlistValue(v)
		if !ok {
			panic(errors.New("failed to find value in object map during serialization"))
		}

		p.writeSizedInt(objIdx, int(p.trailer.ObjectRefSize))
	}
}

func (p *bplistGenerator) Indent(i string) {
	// There's nothing to indent.
}

func newBplistGenerator(w io.Writer) *bplistGenerator {
	return &bplistGenerator{
		writer: &countedWriter{Writer: mustWriter{w}},
	}
}
