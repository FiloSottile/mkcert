// +build gofuzz

package plist

import (
	"bytes"
)

func Fuzz(data []byte) int {
	buf := bytes.NewReader(data)

	var obj interface{}
	if err := NewDecoder(buf).Decode(&obj); err != nil {
		return 0
	}
	return 1
}
