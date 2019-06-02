// +build appengine

package plist

func zeroCopy8BitString(buf []byte, off int, len int) string {
	return string(buf[off : off+len])
}
