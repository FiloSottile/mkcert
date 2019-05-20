// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	FirefoxProfile      = os.Getenv("HOME") + "/.mozilla/firefox/*"
	CertutilInstallHelp = `pkg_add nss`
	NSSBrowsers         = "Firefox and/or Chromium"

	SystemTrustFilename string
	SystemTrustCommand  []string
)

func init() {
	SystemTrustCommand = nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (m *mkcert) systemTrustFilename() string {
	return fmt.Sprintf(SystemTrustFilename, strings.Replace(m.caUniqueName(), " ", "_", -1))
}

func (m *mkcert) installPlatform() bool {
	if SystemTrustCommand == nil {
		log.Printf("Installing to the system store is not yet supported on OpenBSD but %s will still work.", NSSBrowsers)
		log.Printf("You can also manually install the root certificate at %q.", filepath.Join(m.CAROOT, rootName))
		return false
	}

	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")

	cmd := CommandWithSudo("tee", m.systemTrustFilename())
	cmd.Stdin = bytes.NewReader(cert)
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "tee", out)

	cmd = CommandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)

	return true
}

func (m *mkcert) uninstallPlatform() bool {
	if SystemTrustCommand == nil {
		return false
	}

	cmd := CommandWithSudo("rm", "-f", m.systemTrustFilename())
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "rm", out)

	// We used to install under non-unique filenames.
	legacyFilename := fmt.Sprintf(SystemTrustFilename, "mkcert-rootCA")
	if pathExists(legacyFilename) {
		cmd := CommandWithSudo("rm", "-f", legacyFilename)
		out, err := cmd.CombinedOutput()
		fatalIfCmdErr(err, "rm (legacy filename)", out)
	}

	cmd = CommandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)

	return true
}

func CommandWithSudo(cmd ...string) *exec.Cmd {
	if _, err := exec.LookPath("doas"); err != nil {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("doas", append([]string{"--"}, cmd...)...)
}
