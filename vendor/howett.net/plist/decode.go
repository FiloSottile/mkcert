package plist

import (
	"bytes"
	"io"
	"reflect"
	"runtime"
)

type parser interface {
	parseDocument() (cfValue, error)
}

// A Decoder reads a property list from an input stream.
type Decoder struct {
	// the format of the most-recently-decoded property list
	Format int

	reader io.ReadSeeker
	lax    bool
}

// Decode works like Unmarshal, except it reads the decoder stream to find property list elements.
//
// After Decoding, the Decoder's Format field will be set to one of the plist format constants.
func (p *Decoder) Decode(v interface{}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			err = r.(error)
		}
	}()

	header := make([]byte, 6)
	p.reader.Read(header)
	p.reader.Seek(0, 0)

	var parser parser
	var pval cfValue
	if bytes.Equal(header, []byte("bplist")) {
		parser = newBplistParser(p.reader)
		pval, err = parser.parseDocument()
		if err != nil {
			// Had a bplist header, but still got an error: we have to die here.
			return err
		}
		p.Format = BinaryFormat
	} else {
		parser = newXMLPlistParser(p.reader)
		pval, err = parser.parseDocument()
		if _, ok := err.(invalidPlistError); ok {
			// Rewind: the XML parser might have exhausted the file.
			p.reader.Seek(0, 0)
			// We don't use parser here because we want the textPlistParser type
			tp := newTextPlistParser(p.reader)
			pval, err = tp.parseDocument()
			if err != nil {
				return err
			}
			p.Format = tp.format
			if p.Format == OpenStepFormat {
				// OpenStep property lists can only store strings,
				// so we have to turn on lax mode here for the unmarshal step later.
				p.lax = true
			}
		} else {
			if err != nil {
				return err
			}
			p.Format = XMLFormat
		}
	}

	p.unmarshal(pval, reflect.ValueOf(v))
	return
}

// NewDecoder returns a Decoder that reads property list elements from a stream reader, r.
// NewDecoder requires a Seekable stream for the purposes of file type detection.
func NewDecoder(r io.ReadSeeker) *Decoder {
	return &Decoder{Format: InvalidFormat, reader: r, lax: false}
}

// Unmarshal parses a property list document and stores the result in the value pointed to by v.
//
// Unmarshal uses the inverse of the type encodings that Marshal uses, allocating heap-borne types as necessary.
//
// When given a nil pointer, Unmarshal allocates a new value for it to point to.
//
// To decode property list values into an interface value, Unmarshal decodes the property list into the concrete value contained
// in the interface value. If the interface value is nil, Unmarshal stores one of the following in the interface value:
//
//     string, bool, uint64, float64
//     plist.UID for "CoreFoundation Keyed Archiver UIDs" (convertible to uint64)
//     []byte, for plist data
//     []interface{}, for plist arrays
//     map[string]interface{}, for plist dictionaries
//
// If a property list value is not appropriate for a given value type, Unmarshal aborts immediately and returns an error.
//
// As Go does not support 128-bit types, and we don't want to pretend we're giving the user integer types (as opposed to
// secretly passing them structs), Unmarshal will drop the high 64 bits of any 128-bit integers encoded in binary property lists.
// (This is important because CoreFoundation serializes some large 64-bit values as 128-bit values with an empty high half.)
//
// When Unmarshal encounters an OpenStep property list, it will enter a relaxed parsing mode: OpenStep property lists can only store
// plain old data as strings, so we will attempt to recover integer, floating-point, boolean and date values wherever they are necessary.
// (for example, if Unmarshal attempts to unmarshal an OpenStep property list into a time.Time, it will try to parse the string it
// receives as a time.)
//
// Unmarshal returns the detected property list format and an error, if any.
func Unmarshal(data []byte, v interface{}) (format int, err error) {
	r := bytes.NewReader(data)
	dec := NewDecoder(r)
	err = dec.Decode(v)
	format = dec.Format
	return
}
