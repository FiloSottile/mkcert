// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	FirefoxPath         = "/usr/bin/firefox"
	FirefoxProfile      = os.Getenv("HOME") + "/.mozilla/firefox/*"
	CertutilInstallHelp = "apt install libnss3-tools"

	SystemTrustFilename string
	SystemTrustCommand  []string
)

func init() {
	_, err := os.Stat("/etc/pki/ca-trust/source/anchors/")
	if !os.IsNotExist(err) {
		SystemTrustFilename = "/etc/pki/ca-trust/source/anchors/mkcert-rootCA.pem"
		SystemTrustCommand = []string{"update-ca-trust", "extract"}
		return
	}

	_, err = os.Stat("/usr/local/share/ca-certificates/")
	if !os.IsNotExist(err) {
		SystemTrustFilename = "/usr/local/share/ca-certificates/mkcert-rootCA.crt"
		SystemTrustCommand = []string{"update-ca-certificates"}
	}
}

func (m *mkcert) installPlatform() {
	if SystemTrustCommand == nil {
		log.Fatalf("-install is not yet supported on this Linux 😣\nYou can manually install the root certificate at %q in the meantime.", filepath.Join(m.CAROOT, rootName))
	}

	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")

	cmd := exec.Command("sudo", "tee", SystemTrustFilename)
	cmd.Stdin = bytes.NewReader(cert)
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "tee", out)

	cmd = exec.Command("sudo", SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)
}

func (m *mkcert) uninstallPlatform() {
	if SystemTrustCommand == nil {
		log.Fatal("-uninstall is not yet supported on this Linux 😣")
	}

	cmd := exec.Command("sudo", "rm", SystemTrustFilename)
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "rm", out)

	cmd = exec.Command("sudo", SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)
}
