package truststore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	nssDBs = []string{
		filepath.Join(os.Getenv("HOME"), ".pki/nssdb"),
		filepath.Join(os.Getenv("HOME"), "snap/chromium/current/.pki/nssdb"), // Snapcraft
		"/etc/pki/nssdb", // CentOS 7
	}
	firefoxPaths = []string{
		"/usr/bin/firefox", "/Applications/Firefox.app",
		"/Applications/Firefox Developer Edition.app",
		"/Applications/Firefox Nightly.app",
		"C:\\Program Files\\Mozilla Firefox",
	}
)

type nss struct {
	certutilPath string
}

func (n *nss) Install(path string) error {
	c, err := decodeCert(path)
	if err != nil {
		return fmt.Errorf("failed to parse root certificate: %v", err)
	}
	uniqueName := strings.Replace("mkcert development CA "+c.SerialNumber.String(), " ", "_", -1)

	found, err := n.forEachNSSProfile(func(profile string) error {
		if _, err := n.execCertutil("-A", "-d", profile, "-t", "C,,", "-n", uniqueName, "-i", path); err != nil {
			return fmt.Errorf("command %q failed: %v", "certutil -A -d "+profile, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if found == 0 {
		return errors.New("no NSS databases found")
	}

	return nil
}

// certutilPath returns an absolute path to the certutil binary, or
// the empty string if the binary was not found.
func certutilPath() string {
	switch runtime.GOOS {
	case "darwin":
		switch {
		case binaryExists("certutil"):
			p, _ := exec.LookPath("certutil")
			return p
		case binaryExists("/usr/local/opt/nss/bin/certutil"):
			// Check the default Homebrew path, to save executing Ruby. #135
			return "/usr/local/opt/nss/bin/certutil"
		default:
			out, err := exec.Command("brew", "--prefix", "nss").Output()
			if err == nil {
				certutilPath := filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")
				if pathExists(certutilPath) {
					return certutilPath
				}
			}
		}

	case "linux":
		if binaryExists("certutil") {
			p, _ := exec.LookPath("certutil")
			return p
		}
	}

	return ""
}

func usesNSS() bool {
	for _, path := range append(append([]string{}, nssDBs...), firefoxPaths...) {
		if pathExists(path) {
			return true
		}
	}
	return false
}

// NSS returns the truststore used by NSS.
func NSS() (Truststore, error) {
	if !usesNSS() {
		return nil, errors.New("no NSS-compatible application or database")
	}
	certutilPath := certutilPath()
	if certutilPath == "" {
		return nil, errors.New("certutil binary not found")
	}

	return &nss{certutilPath: certutilPath}, nil
}

func (n *nss) forEachNSSProfile(f func(profile string) error) (found int, err error) {
	profiles, _ := filepath.Glob(firefoxProfile())
	profiles = append(profiles, nssDBs...)
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if pathExists(filepath.Join(profile, "cert9.db")) {
			if err := f("sql:" + profile); err != nil {
				return 0, err
			}
			found++
		} else if pathExists(filepath.Join(profile, "cert8.db")) {
			if err := f("dbm:" + profile); err != nil {
				return 0, err
			}
			found++
		}
	}
	return found, nil
}

// execCertutil will execute a "execCertutil" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func (n *nss) execCertutil(args ...string) ([]byte, error) {
	cmd := exec.Command(n.certutilPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("SEC_ERROR_READ_ONLY")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd, err = commandWithSudo(cmd.Path)
		if err != nil {
			return nil, err
		}
		cmd.Args = append(cmd.Args, origArgs...)
		out, err = cmd.CombinedOutput()
	}
	return out, err
}
