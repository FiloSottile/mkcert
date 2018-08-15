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
	CertutilInstallHelp = `apt install libnss3-tools" or "yum install nss-tools`
	NSSBrowsers         = "Firefox and/or Chrome/Chromium"

	SystemTrustBaseDir    string
	SystemTrustFileSuffix string
	SystemTrustCommand    []string
)

func init() {
	_, err := os.Stat("/etc/pki/ca-trust/source/anchors/")
	if err == nil {
		SystemTrustBaseDir = "/etc/pki/ca-trust/source/anchors"
		SystemTrustFileSuffix = "pem"
		SystemTrustCommand = []string{"update-ca-trust", "extract"}
	} else {
		_, err = os.Stat("/usr/local/share/ca-certificates/")
		if err == nil {
			SystemTrustBaseDir = "/usr/local/share/ca-certificates"
			SystemTrustFileSuffix = "crt"
			SystemTrustCommand = []string{"update-ca-certificates"}
		}
	}
	if SystemTrustCommand != nil {
		_, err := exec.LookPath(SystemTrustCommand[0])
		if err != nil {
			SystemTrustCommand = nil
		}
	}
}

func (m *mkcert) systemTrustPath() string {
	systemTrustFilename := fmt.Sprintf("%s.%s", strings.Replace(m.caUniqueName(), " ", "_", -1), SystemTrustFileSuffix)
	return filepath.Join(SystemTrustBaseDir, systemTrustFilename)
}

func (m *mkcert) installPlatform() bool {
	if SystemTrustCommand == nil {
		log.Printf("Installing to the system store is not yet supported on this Linux 😣 but %s will still work.", NSSBrowsers)
		log.Printf("You can also manually install the root certificate at %q.", filepath.Join(m.CAROOT, rootName))
		return false
	}

	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")

	cmd := CommandWithSudo("tee", m.systemTrustPath())
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

	cmd := CommandWithSudo("rm", m.systemTrustPath())
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "rm", out)

	cmd = CommandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)

	return true
}

func CommandWithSudo(cmd ...string) *exec.Cmd {
	if _, err := exec.LookPath("sudo"); err != nil {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--"}, cmd...)...)
}
