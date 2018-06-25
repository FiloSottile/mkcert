package plist

import (
	"bufio"
	"encoding/base64"
	"encoding/xml"
	"io"
	"math"
	"strconv"
	"time"
)

const (
	xmlHEADER     string = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
	xmlDOCTYPE           = `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n"
	xmlArrayTag          = "array"
	xmlDataTag           = "data"
	xmlDateTag           = "date"
	xmlDictTag           = "dict"
	xmlFalseTag          = "false"
	xmlIntegerTag        = "integer"
	xmlKeyTag            = "key"
	xmlPlistTag          = "plist"
	xmlRealTag           = "real"
	xmlStringTag         = "string"
	xmlTrueTag           = "true"

	// magic value used in the XML encoding of UIDs
	// (stored as a dictionary mapping CF$UID->integer)
	xmlCFUIDMagic = "CF$UID"
)

func formatXMLFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case math.IsNaN(f):
		return "nan"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

type xmlPlistGenerator struct {
	*bufio.Writer

	indent     string
	depth      int
	putNewline bool
}

func (p *xmlPlistGenerator) generateDocument(root cfValue) {
	p.WriteString(xmlHEADER)
	p.WriteString(xmlDOCTYPE)

	p.openTag(`plist version="1.0"`)
	p.writePlistValue(root)
	p.closeTag(xmlPlistTag)
	p.Flush()
}

func (p *xmlPlistGenerator) openTag(n string) {
	p.writeIndent(1)
	p.WriteByte('<')
	p.WriteString(n)
	p.WriteByte('>')
}

func (p *xmlPlistGenerator) closeTag(n string) {
	p.writeIndent(-1)
	p.WriteString("</")
	p.WriteString(n)
	p.WriteByte('>')
}

func (p *xmlPlistGenerator) element(n string, v string) {
	p.writeIndent(0)
	if len(v) == 0 {
		p.WriteByte('<')
		p.WriteString(n)
		p.WriteString("/>")
	} else {
		p.WriteByte('<')
		p.WriteString(n)
		p.WriteByte('>')

		err := xml.EscapeText(p.Writer, []byte(v))
		if err != nil {
			panic(err)
		}

		p.WriteString("</")
		p.WriteString(n)
		p.WriteByte('>')
	}
}

func (p *xmlPlistGenerator) writeDictionary(dict *cfDictionary) {
	dict.sort()
	p.openTag(xmlDictTag)
	for i, k := range dict.keys {
		p.element(xmlKeyTag, k)
		p.writePlistValue(dict.values[i])
	}
	p.closeTag(xmlDictTag)
}

func (p *xmlPlistGenerator) writeArray(a *cfArray) {
	p.openTag(xmlArrayTag)
	for _, v := range a.values {
		p.writePlistValue(v)
	}
	p.closeTag(xmlArrayTag)
}

func (p *xmlPlistGenerator) writePlistValue(pval cfValue) {
	if pval == nil {
		return
	}

	switch pval := pval.(type) {
	case cfString:
		p.element(xmlStringTag, string(pval))
	case *cfNumber:
		if pval.signed {
			p.element(xmlIntegerTag, strconv.FormatInt(int64(pval.value), 10))
		} else {
			p.element(xmlIntegerTag, strconv.FormatUint(pval.value, 10))
		}
	case *cfReal:
		p.element(xmlRealTag, formatXMLFloat(pval.value))
	case cfBoolean:
		if bool(pval) {
			p.element(xmlTrueTag, "")
		} else {
			p.element(xmlFalseTag, "")
		}
	case cfData:
		p.element(xmlDataTag, base64.StdEncoding.EncodeToString([]byte(pval)))
	case cfDate:
		p.element(xmlDateTag, time.Time(pval).In(time.UTC).Format(time.RFC3339))
	case *cfDictionary:
		p.writeDictionary(pval)
	case *cfArray:
		p.writeArray(pval)
	case cfUID:
		p.openTag(xmlDictTag)
		p.element(xmlKeyTag, xmlCFUIDMagic)
		p.element(xmlIntegerTag, strconv.FormatUint(uint64(pval), 10))
		p.closeTag(xmlDictTag)
	}
}

func (p *xmlPlistGenerator) writeIndent(delta int) {
	if len(p.indent) == 0 {
		return
	}

	if delta < 0 {
		p.depth--
	}

	if p.putNewline {
		// from encoding/xml/marshal.go; it seems to be intended
		// to suppress the first newline.
		p.WriteByte('\n')
	} else {
		p.putNewline = true
	}
	for i := 0; i < p.depth; i++ {
		p.WriteString(p.indent)
	}
	if delta > 0 {
		p.depth++
	}
}

func (p *xmlPlistGenerator) Indent(i string) {
	p.indent = i
}

func newXMLPlistGenerator(w io.Writer) *xmlPlistGenerator {
	return &xmlPlistGenerator{Writer: bufio.NewWriter(w)}
}
