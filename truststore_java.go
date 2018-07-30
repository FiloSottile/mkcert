// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"hash"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

var (
	hasJava    bool
	hasKeytool bool

	javaHome    string
	cacertsPath string
	keytoolPath string
	storePass   string = "changeit"
)

func init() {
	if v := os.Getenv("JAVA_HOME"); v != "" {
		hasJava = true
		javaHome = v

		_, err := os.Stat(path.Join(v, "bin/keytool"))
		if err == nil {
			hasKeytool = true
			keytoolPath = path.Join(v, "bin/keytool")
		}

		cacertsPath = path.Join(v, "jre/lib/security/cacerts")
	}
}

func (m *mkcert) checkJava() bool {
	// exists returns true if the given x509.Certificate's fingerprint
	// is in the keytool -list output
	exists := func(c *x509.Certificate, h hash.Hash, keytoolOutput []byte) bool {
		h.Write(c.Raw)
		fp := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		return bytes.Contains(keytoolOutput, []byte(fp))
	}

	keytoolOutput, err := exec.Command(keytoolPath, "-list", "-keystore", cacertsPath, "-storepass", storePass).CombinedOutput()
	fatalIfCmdErr(err, "keytool -list", keytoolOutput)
	// keytool outputs SHA1 and SHA256 (Java 9+) certificates in uppercase hex
	// with each octet pair delimitated by ":". Drop them from the keytool output
	keytoolOutput = bytes.Replace(keytoolOutput, []byte(":"), nil, -1)

	// pre-Java 9 uses SHA1 fingerprints
	s1, s256 := sha1.New(), sha256.New()
	return exists(m.caCert, s1, keytoolOutput) || exists(m.caCert, s256, keytoolOutput)
}

func (m *mkcert) installJava() {
	args := []string{
		"-importcert", "-noprompt",
		"-keystore", cacertsPath,
		"-storepass", storePass,
		"-file", filepath.Join(m.CAROOT, rootName),
		"-alias", m.caUniqueName(),
	}

	out, err := m.execKeytool(exec.Command(keytoolPath, args...))
	fatalIfCmdErr(err, "keytool -importcert", out)
}

func (m *mkcert) uninstallJava() {
	args := []string{
		"-delete",
		"-alias", m.caUniqueName(),
		"-keystore", cacertsPath,
		"-storepass", storePass,
	}
	out, err := m.execKeytool(exec.Command(keytoolPath, args...))
	if bytes.Contains(out, []byte("does not exist")) {
		return // cert didn't exist
	}
	fatalIfCmdErr(err, "keytool -delete", out)
}

// execKeytool will execute a "keytool" command and if needed re-execute
// the command wrapped in 'sudo' to work around file permissions.
func (m *mkcert) execKeytool(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("java.io.FileNotFoundException")) {
		origArgs := cmd.Args[1:]
		cmd = exec.Command("sudo", keytoolPath)
		cmd.Args = append(cmd.Args, origArgs...)
		cmd.Env = []string{
			"JAVA_HOME=" + javaHome,
		}
		out, err = cmd.CombinedOutput()
	}
	return out, err
}
