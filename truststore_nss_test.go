// Copyright 2026 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultNSSDBsIncludesChromiumLocalSharePath(t *testing.T) {
	home := filepath.Join("home", "testuser")
	want := filepath.Join(home, ".local/share/pki/nssdb")

	if !contains(defaultNSSDBs(home), want) {
		t.Fatalf("defaultNSSDBs(%q) does not include %q", home, want)
	}
}

func TestForEachNSSProfileFindsChromiumLocalSharePath(t *testing.T) {
	oldNSSDBs := nssDBs
	oldFirefoxProfiles := FirefoxProfiles
	t.Cleanup(func() {
		nssDBs = oldNSSDBs
		FirefoxProfiles = oldFirefoxProfiles
	})

	home := t.TempDir()
	nssDBs = defaultNSSDBs(home)
	FirefoxProfiles = nil

	profileDir := filepath.Join(home, ".local/share/pki/nssdb")
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "cert9.db"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	var got []string
	found := new(mkcert).forEachNSSProfile(func(profile string) {
		got = append(got, profile)
	})

	want := "sql:" + profileDir
	if !contains(got, want) {
		t.Fatalf("forEachNSSProfile found %d profiles %v, want %q", found, got, want)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
