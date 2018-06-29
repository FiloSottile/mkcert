// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"os"
	"path/filepath"
)

var (
	FirefoxPath         = "/usr/bin/firefox"
	FirefoxProfile      = os.Getenv("HOME") + "/.mozilla/firefox/*"
	CertutilInstallHelp = "apt install libnss3-tools"
)

func (m *mkcert) installPlatform() {
	log.Println("  -install is not yet fully supported on Linux  😣")
	log.Printf("You can manually install the root certificate at %q in the meantime.", filepath.Join(m.CAROOT, rootName))
}

func (m *mkcert) uninstallPlatform() {}
