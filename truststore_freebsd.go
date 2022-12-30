// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const _certstore = "/etc/ssl/certs"

var (
	FirefoxProfiles     = []string{os.Getenv("HOME") + "/.mozilla/firefox/*"}
	NSSBrowsers         = "Firefox and/or Chrome/Chromium"
	SystemTrustFilename string
	SystemTrustCommand  []string
	CertutilInstallHelp string
)

func (m *mkcert) systemTrustFilename() string {
	return fmt.Sprintf(SystemTrustFilename, strings.Replace(m.caUniqueName(), " ", "_", -1))
}

func (m *mkcert) installPlatform() bool {
	if !pathExists(_certstore) {
		log.Print("FreeBSD caroot base pkg is missing.")
		log.Printf("You can manually install the root certificate at %q.", filepath.Join(m.CAROOT, rootName))
		return false
	}
	cert, err := os.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")
	os.WriteFile(filepath.Join(_certstore, rootName), cert, 0o444)
	return true
}

func (m *mkcert) uninstallPlatform() bool {
	err := os.Remove(filepath.Join(_certstore, "rootCA.pem"))
	fatalIfErr(err, "failed to remove certificate")
	return true
}
