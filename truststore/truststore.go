// Package truststore adds and removes certificates from the system truststore.
package truststore

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"sync"
)

// Truststore installs, uninstalls, & enumerates certificates on the store.
type Truststore interface {
	// Install installs the PEM-encoded certificate at path.
	Install(path string) error
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var sudoWarningOnce sync.Once

func commandWithSudo(cmd ...string) (*exec.Cmd, error) {
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return exec.Command(cmd[0], cmd[1:]...), nil
	}
	if !binaryExists("sudo") {
		return nil, errors.New("sudo not available")
	}
	return exec.Command("sudo", append([]string{"--prompt=Sudo password:", "--"}, cmd...)...), nil
}

func decodeCert(path string) (*x509.Certificate, error) {
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(d)
	return x509.ParseCertificate(b.Bytes)
}

func firefoxProfile() string {
	switch runtime.GOOS {
	case "darwin":
		return os.Getenv("HOME") + "/Library/Application Support/Firefox/Profiles/*"
	case "linux":
		return os.Getenv("HOME") + "/.mozilla/firefox/*"
	case "windows":
		return os.Getenv("USERPROFILE") + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
	}

	return ""
}
