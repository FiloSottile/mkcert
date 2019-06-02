// +build !appengine

package plist

import (
	"reflect"
	"unsafe"
)

func zeroCopy8BitString(buf []byte, off int, len int) string {
	if len == 0 {
		return ""
	}

	var s string
	hdr := (*reflect.StringHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(&buf[off]))
	hdr.Len = len
	return s
}
