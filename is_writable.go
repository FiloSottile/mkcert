package main

// +build !windows

import (
	"golang.org/x/sys/unix"
)

func IsWritable(path string) bool {
	if err := unix.Access(path, unix.W_OK); err == nil {
		return true
	}
	return false
}
