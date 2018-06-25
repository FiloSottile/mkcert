package plist

import "io"

type countedWriter struct {
	io.Writer
	nbytes int
}

func (w *countedWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.nbytes += n
	return n, err
}

func (w *countedWriter) BytesWritten() int {
	return w.nbytes
}

func unsignedGetBase(s string) (string, int) {
	if len(s) > 1 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:], 16
	}
	return s, 10
}
