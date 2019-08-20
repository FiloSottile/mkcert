package main

import (
	"os"
)

// thanks to https://stackoverflow.com/a/49148866/215713
func IsWritable(path string) bool {
	isWritable = false
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	err = nil
	if !info.IsDir() {
		return false
	}

	// Check if the user bit is enabled in file permission
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		return false
	}
	return true
}
