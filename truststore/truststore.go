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
	"sync"
)

// Installer installs a certificate to the system truststore.
type Installer struct{}

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
