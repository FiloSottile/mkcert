package plist

import (
	"encoding/hex"
	"io"
	"strconv"
	"time"
)

type textPlistGenerator struct {
	writer io.Writer
	format int

	quotableTable *characterSet

	indent string
	depth  int

	dictKvDelimiter, dictEntryDelimiter, arrayDelimiter []byte
}

var (
	textPlistTimeLayout = "2006-01-02 15:04:05 -0700"
	padding             = "0000"
)

func (p *textPlistGenerator) generateDocument(pval cfValue) {
	p.writePlistValue(pval)
}

func (p *textPlistGenerator) plistQuotedString(str string) string {
	if str == "" {
		return `""`
	}
	s := ""
	quot := false
	for _, r := range str {
		if r > 0xFF {
			quot = true
			s += `\U`
			us := strconv.FormatInt(int64(r), 16)
			s += padding[len(us):]
			s += us
		} else if r > 0x7F {
			quot = true
			s += `\`
			us := strconv.FormatInt(int64(r), 8)
			s += padding[1+len(us):]
			s += us
		} else {
			c := uint8(r)
			if p.quotableTable.ContainsByte(c) {
				quot = true
			}

			switch c {
			case '\a':
				s += `\a`
			case '\b':
				s += `\b`
			case '\v':
				s += `\v`
			case '\f':
				s += `\f`
			case '\\':
				s += `\\`
			case '"':
				s += `\"`
			case '\t', '\r', '\n':
				fallthrough
			default:
				s += string(c)
			}
		}
	}
	if quot {
		s = `"` + s + `"`
	}
	return s
}

func (p *textPlistGenerator) deltaIndent(depthDelta int) {
	if depthDelta < 0 {
		p.depth--
	} else if depthDelta > 0 {
		p.depth++
	}
}

func (p *textPlistGenerator) writeIndent() {
	if len(p.indent) == 0 {
		return
	}
	if len(p.indent) > 0 {
		p.writer.Write([]byte("\n"))
		for i := 0; i < p.depth; i++ {
			io.WriteString(p.writer, p.indent)
		}
	}
}

func (p *textPlistGenerator) writePlistValue(pval cfValue) {
	if pval == nil {
		return
	}

	switch pval := pval.(type) {
	case *cfDictionary:
		pval.sort()
		p.writer.Write([]byte(`{`))
		p.deltaIndent(1)
		for i, k := range pval.keys {
			p.writeIndent()
			io.WriteString(p.writer, p.plistQuotedString(k))
			p.writer.Write(p.dictKvDelimiter)
			p.writePlistValue(pval.values[i])
			p.writer.Write(p.dictEntryDelimiter)
		}
		p.deltaIndent(-1)
		p.writeIndent()
		p.writer.Write([]byte(`}`))
	case *cfArray:
		p.writer.Write([]byte(`(`))
		p.deltaIndent(1)
		for _, v := range pval.values {
			p.writeIndent()
			p.writePlistValue(v)
			p.writer.Write(p.arrayDelimiter)
		}
		p.deltaIndent(-1)
		p.writeIndent()
		p.writer.Write([]byte(`)`))
	case cfString:
		io.WriteString(p.writer, p.plistQuotedString(string(pval)))
	case *cfNumber:
		if p.format == GNUStepFormat {
			p.writer.Write([]byte(`<*I`))
		}
		if pval.signed {
			io.WriteString(p.writer, strconv.FormatInt(int64(pval.value), 10))
		} else {
			io.WriteString(p.writer, strconv.FormatUint(pval.value, 10))
		}
		if p.format == GNUStepFormat {
			p.writer.Write([]byte(`>`))
		}
	case *cfReal:
		if p.format == GNUStepFormat {
			p.writer.Write([]byte(`<*R`))
		}
		// GNUstep does not differentiate between 32/64-bit floats.
		io.WriteString(p.writer, strconv.FormatFloat(pval.value, 'g', -1, 64))
		if p.format == GNUStepFormat {
			p.writer.Write([]byte(`>`))
		}
	case cfBoolean:
		if p.format == GNUStepFormat {
			if pval {
				p.writer.Write([]byte(`<*BY>`))
			} else {
				p.writer.Write([]byte(`<*BN>`))
			}
		} else {
			if pval {
				p.writer.Write([]byte(`1`))
			} else {
				p.writer.Write([]byte(`0`))
			}
		}
	case cfData:
		var hexencoded [9]byte
		var l int
		var asc = 9
		hexencoded[8] = ' '

		p.writer.Write([]byte(`<`))
		b := []byte(pval)
		for i := 0; i < len(b); i += 4 {
			l = i + 4
			if l >= len(b) {
				l = len(b)
				// We no longer need the space - or the rest of the buffer.
				// (we used >= above to get this part without another conditional :P)
				asc = (l - i) * 2
			}
			// Fill the buffer (only up to 8 characters, to preserve the space we implicitly include
			// at the end of every encode)
			hex.Encode(hexencoded[:8], b[i:l])
			io.WriteString(p.writer, string(hexencoded[:asc]))
		}
		p.writer.Write([]byte(`>`))
	case cfDate:
		if p.format == GNUStepFormat {
			p.writer.Write([]byte(`<*D`))
			io.WriteString(p.writer, time.Time(pval).In(time.UTC).Format(textPlistTimeLayout))
			p.writer.Write([]byte(`>`))
		} else {
			io.WriteString(p.writer, p.plistQuotedString(time.Time(pval).In(time.UTC).Format(textPlistTimeLayout)))
		}
	}
}

func (p *textPlistGenerator) Indent(i string) {
	p.indent = i
	if i == "" {
		p.dictKvDelimiter = []byte(`=`)
	} else {
		// For pretty-printing
		p.dictKvDelimiter = []byte(` = `)
	}
}

func newTextPlistGenerator(w io.Writer, format int) *textPlistGenerator {
	table := &osQuotable
	if format == GNUStepFormat {
		table = &gsQuotable
	}
	return &textPlistGenerator{
		writer:             mustWriter{w},
		format:             format,
		quotableTable:      table,
		dictKvDelimiter:    []byte(`=`),
		arrayDelimiter:     []byte(`,`),
		dictEntryDelimiter: []byte(`;`),
	}
}
