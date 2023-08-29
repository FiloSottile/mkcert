// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var (
	FirefoxProfiles = []string{os.Getenv("HOME") + "/.mozilla/firefox/*"}
	NSSBrowsers = "Firefox and/or Chrome/Chromium"

	SystemTrustFilename string
	SystemTrustCommand  []string
	CertutilInstallHelp string
)

func init() {
	cmd := commandWithSudo("mkdir", "-p", "/usr/local/etc/ssl/certs")
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "mkdir -p /usr/local/etc/ssl/certs", out)

	SystemTrustFilename = "/usr/local/etc/ssl/certs/%s.pem"
	SystemTrustCommand = []string{"certctl", "rehash"}
}

func (m *mkcert) systemTrustFilename() string {
	return fmt.Sprintf(SystemTrustFilename, strings.Replace(m.caUniqueName(), " ", "_", -1))
}

func (m *mkcert) installPlatform() bool {
	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")

	cmd := commandWithSudo("tee", m.systemTrustFilename())
	cmd.Stdin = bytes.NewReader(cert)
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "tee", out)

	cmd = commandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)

	return true
}

func (m *mkcert) uninstallPlatform() bool {
	if SystemTrustCommand == nil {
		return false
	}

	cmd := commandWithSudo("rm", "-f", m.systemTrustFilename())
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "rm", out)

	// We used to install under non-unique filenames.
	legacyFilename := fmt.Sprintf(SystemTrustFilename, "mkcert-rootCA")
	if pathExists(legacyFilename) {
		cmd := commandWithSudo("rm", "-f", legacyFilename)
		out, err := cmd.CombinedOutput()
		fatalIfCmdErr(err, "rm (legacy filename)", out)
	}

	cmd = commandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)

	return true
}
