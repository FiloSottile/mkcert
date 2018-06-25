package plist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

type textPlistParser struct {
	reader io.Reader
	format int

	input string
	start int
	pos   int
	width int
}

func convertU16(buffer []byte, bo binary.ByteOrder) (string, error) {
	if len(buffer)%2 != 0 {
		return "", errors.New("truncated utf16")
	}

	tmp := make([]uint16, len(buffer)/2)
	for i := 0; i < len(buffer); i += 2 {
		tmp[i/2] = bo.Uint16(buffer[i : i+2])
	}
	return string(utf16.Decode(tmp)), nil
}

func guessEncodingAndConvert(buffer []byte) (string, error) {
	if len(buffer) >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF {
		// UTF-8 BOM
		return zeroCopy8BitString(buffer, 3, len(buffer)-3), nil
	} else if len(buffer) >= 2 {
		// UTF-16 guesses

		switch {
		// stream is big-endian (BOM is FE FF or head is 00 XX)
		case (buffer[0] == 0xFE && buffer[1] == 0xFF):
			return convertU16(buffer[2:], binary.BigEndian)
		case (buffer[0] == 0 && buffer[1] != 0):
			return convertU16(buffer, binary.BigEndian)

		// stream is little-endian (BOM is FE FF or head is XX 00)
		case (buffer[0] == 0xFF && buffer[1] == 0xFE):
			return convertU16(buffer[2:], binary.LittleEndian)
		case (buffer[0] != 0 && buffer[1] == 0):
			return convertU16(buffer, binary.LittleEndian)
		}
	}

	// fallback: assume ASCII (not great!)
	return zeroCopy8BitString(buffer, 0, len(buffer)), nil
}

func (p *textPlistParser) parseDocument() (pval cfValue, parseError error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			// Wrap all non-invalid-plist errors.
			parseError = plistParseError{"text", r.(error)}
		}
	}()

	buffer, err := ioutil.ReadAll(p.reader)
	if err != nil {
		panic(err)
	}

	p.input, err = guessEncodingAndConvert(buffer)
	if err != nil {
		panic(err)
	}

	val := p.parsePlistValue()

	p.skipWhitespaceAndComments()
	if p.peek() != eof {
		if _, ok := val.(cfString); !ok {
			p.error("garbage after end of document")
		}

		p.start = 0
		p.pos = 0
		val = p.parseDictionary(true)
	}

	pval = val

	return
}

const eof rune = -1

func (p *textPlistParser) error(e string, args ...interface{}) {
	line := strings.Count(p.input[:p.pos], "\n")
	char := p.pos - strings.LastIndex(p.input[:p.pos], "\n") - 1
	panic(fmt.Errorf("%s at line %d character %d", fmt.Sprintf(e, args...), line, char))
}

func (p *textPlistParser) next() rune {
	if int(p.pos) >= len(p.input) {
		p.width = 0
		return eof
	}
	r, w := utf8.DecodeRuneInString(p.input[p.pos:])
	p.width = w
	p.pos += p.width
	return r
}

func (p *textPlistParser) backup() {
	p.pos -= p.width
}

func (p *textPlistParser) peek() rune {
	r := p.next()
	p.backup()
	return r
}

func (p *textPlistParser) emit() string {
	s := p.input[p.start:p.pos]
	p.start = p.pos
	return s
}

func (p *textPlistParser) ignore() {
	p.start = p.pos
}

func (p *textPlistParser) empty() bool {
	return p.start == p.pos
}

func (p *textPlistParser) scanUntil(ch rune) {
	if x := strings.IndexRune(p.input[p.pos:], ch); x >= 0 {
		p.pos += x
		return
	}
	p.pos = len(p.input)
}

func (p *textPlistParser) scanUntilAny(chs string) {
	if x := strings.IndexAny(p.input[p.pos:], chs); x >= 0 {
		p.pos += x
		return
	}
	p.pos = len(p.input)
}

func (p *textPlistParser) scanCharactersInSet(ch *characterSet) {
	for ch.Contains(p.next()) {
	}
	p.backup()
}

func (p *textPlistParser) scanCharactersNotInSet(ch *characterSet) {
	var r rune
	for {
		r = p.next()
		if r == eof || ch.Contains(r) {
			break
		}
	}
	p.backup()
}

func (p *textPlistParser) skipWhitespaceAndComments() {
	for {
		p.scanCharactersInSet(&whitespace)
		if strings.HasPrefix(p.input[p.pos:], "//") {
			p.scanCharactersNotInSet(&newlineCharacterSet)
		} else if strings.HasPrefix(p.input[p.pos:], "/*") {
			if x := strings.Index(p.input[p.pos:], "*/"); x >= 0 {
				p.pos += x + 2 // skip the */ as well
				continue       // consume more whitespace
			} else {
				p.error("unexpected eof in block comment")
			}
		} else {
			break
		}
	}
	p.ignore()
}

func (p *textPlistParser) parseOctalDigits(max int) uint64 {
	var val uint64

	for i := 0; i < max; i++ {
		r := p.next()

		if r >= '0' && r <= '7' {
			val <<= 3
			val |= uint64((r - '0'))
		} else {
			p.backup()
			break
		}
	}
	return val
}

func (p *textPlistParser) parseHexDigits(max int) uint64 {
	var val uint64

	for i := 0; i < max; i++ {
		r := p.next()

		if r >= 'a' && r <= 'f' {
			val <<= 4
			val |= 10 + uint64((r - 'a'))
		} else if r >= 'A' && r <= 'F' {
			val <<= 4
			val |= 10 + uint64((r - 'A'))
		} else if r >= '0' && r <= '9' {
			val <<= 4
			val |= uint64((r - '0'))
		} else {
			p.backup()
			break
		}
	}
	return val
}

// the \ has already been consumed
func (p *textPlistParser) parseEscape() string {
	var s string
	switch p.next() {
	case 'a':
		s = "\a"
	case 'b':
		s = "\b"
	case 'v':
		s = "\v"
	case 'f':
		s = "\f"
	case 't':
		s = "\t"
	case 'r':
		s = "\r"
	case 'n':
		s = "\n"
	case '\\':
		s = `\`
	case '"':
		s = `"`
	case 'x':
		s = string(rune(p.parseHexDigits(2)))
	case 'u', 'U':
		s = string(rune(p.parseHexDigits(4)))
	case '0', '1', '2', '3', '4', '5', '6', '7':
		p.backup() // we've already consumed one of the digits
		s = string(rune(p.parseOctalDigits(3)))
	default:
		p.backup() // everything else should be accepted
	}
	p.ignore() // skip the entire escape sequence
	return s
}

// the " has already been consumed
func (p *textPlistParser) parseQuotedString() cfString {
	p.ignore() // ignore the "

	slowPath := false
	s := ""

	for {
		p.scanUntilAny(`"\`)
		switch p.peek() {
		case eof:
			p.error("unexpected eof in quoted string")
		case '"':
			section := p.emit()
			p.pos++ // skip "
			if !slowPath {
				return cfString(section)
			} else {
				s += section
				return cfString(s)
			}
		case '\\':
			slowPath = true
			s += p.emit()
			p.next() // consume \
			s += p.parseEscape()
		}
	}
}

func (p *textPlistParser) parseUnquotedString() cfString {
	p.scanCharactersNotInSet(&gsQuotable)
	s := p.emit()
	if s == "" {
		p.error("invalid unquoted string (found an unquoted character that should be quoted?)")
	}

	return cfString(s)
}

// the { has already been consumed
func (p *textPlistParser) parseDictionary(ignoreEof bool) *cfDictionary {
	//p.ignore() // ignore the {
	var keypv cfValue
	keys := make([]string, 0, 32)
	values := make([]cfValue, 0, 32)
outer:
	for {
		p.skipWhitespaceAndComments()

		switch p.next() {
		case eof:
			if !ignoreEof {
				p.error("unexpected eof in dictionary")
			}
			fallthrough
		case '}':
			break outer
		case '"':
			keypv = p.parseQuotedString()
		default:
			p.backup()
			keypv = p.parseUnquotedString()
		}

		// INVARIANT: key can't be nil; parseQuoted and parseUnquoted
		// will panic out before they return nil.

		p.skipWhitespaceAndComments()

		var val cfValue
		n := p.next()
		if n == ';' {
			val = keypv
		} else if n == '=' {
			// whitespace is consumed within
			val = p.parsePlistValue()

			p.skipWhitespaceAndComments()

			if p.next() != ';' {
				p.error("missing ; in dictionary")
			}
		} else {
			p.error("missing = in dictionary")
		}

		keys = append(keys, string(keypv.(cfString)))
		values = append(values, val)
	}

	return &cfDictionary{keys: keys, values: values}
}

// the ( has already been consumed
func (p *textPlistParser) parseArray() *cfArray {
	//p.ignore() // ignore the (
	values := make([]cfValue, 0, 32)
outer:
	for {
		p.skipWhitespaceAndComments()

		switch p.next() {
		case eof:
			p.error("unexpected eof in array")
		case ')':
			break outer // done here
		case ',':
			continue // restart; ,) is valid and we don't want to blow it
		default:
			p.backup()
		}

		pval := p.parsePlistValue() // whitespace is consumed within
		if str, ok := pval.(cfString); ok && string(str) == "" {
			// Empty strings in arrays are apparently skipped?
			// TODO: Figure out why this was implemented.
			continue
		}
		values = append(values, pval)
	}
	return &cfArray{values}
}

// the <* have already been consumed
func (p *textPlistParser) parseGNUStepValue() cfValue {
	typ := p.next()
	p.ignore()
	p.scanUntil('>')

	if typ == eof || typ == '>' || p.empty() || p.peek() == eof {
		p.error("invalid GNUStep extended value")
	}

	v := p.emit()
	p.next() // consume the >

	switch typ {
	case 'I':
		if v[0] == '-' {
			n := mustParseInt(v, 10, 64)
			return &cfNumber{signed: true, value: uint64(n)}
		} else {
			n := mustParseUint(v, 10, 64)
			return &cfNumber{signed: false, value: n}
		}
	case 'R':
		n := mustParseFloat(v, 64)
		return &cfReal{wide: true, value: n} // TODO(DH) 32/64
	case 'B':
		b := v[0] == 'Y'
		return cfBoolean(b)
	case 'D':
		t, err := time.Parse(textPlistTimeLayout, v)
		if err != nil {
			p.error(err.Error())
		}

		return cfDate(t.In(time.UTC))
	}
	p.error("invalid GNUStep type " + string(typ))
	return nil
}

// The < has already been consumed
func (p *textPlistParser) parseHexData() cfData {
	buf := make([]byte, 256)
	i := 0
	c := 0

	for {
		r := p.next()
		switch r {
		case eof:
			p.error("unexpected eof in data")
		case '>':
			if c&1 == 1 {
				p.error("uneven number of hex digits in data")
			}
			p.ignore()
			return cfData(buf[:i])
		case ' ', '\t', '\n', '\r', '\u2028', '\u2029': // more lax than apple here: skip spaces
			continue
		}

		buf[i] <<= 4
		if r >= 'a' && r <= 'f' {
			buf[i] |= 10 + byte((r - 'a'))
		} else if r >= 'A' && r <= 'F' {
			buf[i] |= 10 + byte((r - 'A'))
		} else if r >= '0' && r <= '9' {
			buf[i] |= byte((r - '0'))
		} else {
			p.error("unexpected hex digit `%c'", r)
		}

		c++
		if c&1 == 0 {
			i++
			if i >= len(buf) {
				realloc := make([]byte, len(buf)*2)
				copy(realloc, buf)
				buf = realloc
			}
		}
	}
}

func (p *textPlistParser) parsePlistValue() cfValue {
	for {
		p.skipWhitespaceAndComments()

		switch p.next() {
		case eof:
			return &cfDictionary{}
		case '<':
			if p.next() == '*' {
				p.format = GNUStepFormat
				return p.parseGNUStepValue()
			}

			p.backup()
			return p.parseHexData()
		case '"':
			return p.parseQuotedString()
		case '{':
			return p.parseDictionary(false)
		case '(':
			return p.parseArray()
		default:
			p.backup()
			return p.parseUnquotedString()
		}
	}
}

func newTextPlistParser(r io.Reader) *textPlistParser {
	return &textPlistParser{
		reader: r,
		format: OpenStepFormat,
	}
}
