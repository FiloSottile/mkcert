package plist

import (
	"io"
	"strconv"
)

type mustWriter struct {
	io.Writer
}

func (w mustWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err != nil {
		panic(err)
	}
	return n, nil
}

func mustParseInt(str string, base, bits int) int64 {
	i, err := strconv.ParseInt(str, base, bits)
	if err != nil {
		panic(err)
	}
	return i
}

func mustParseUint(str string, base, bits int) uint64 {
	i, err := strconv.ParseUint(str, base, bits)
	if err != nil {
		panic(err)
	}
	return i
}

func mustParseFloat(str string, bits int) float64 {
	i, err := strconv.ParseFloat(str, bits)
	if err != nil {
		panic(err)
	}
	return i
}

func mustParseBool(str string) bool {
	i, err := strconv.ParseBool(str)
	if err != nil {
		panic(err)
	}
	return i
}
