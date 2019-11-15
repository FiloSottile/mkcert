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

const storePass string = "changeit"

type javaTruststore struct {
	javaHome    string
	cacertsPath string
	keytoolPath string
}

// Java returns the truststore used by Java.
func Java() (Truststore, error) {
	var (
		javaHome    string
		cacertsPath string
		keytoolPath string
	)

	if runtime.GOOS == "windows" {
		keytoolPath = filepath.Join("bin", "keytool.exe")
	} else {
		keytoolPath = filepath.Join("bin", "keytool")
	}

	javaHome = os.Getenv("JAVA_HOME")
	if javaHome == "" {
		return nil, errors.New("could not determine JAVA_HOME")
	}
	if !pathExists(filepath.Join(javaHome, keytoolPath)) {
		return nil, fmt.Errorf("JAVA_HOME/%s not present", keytoolPath)
	}
	keytoolPath = filepath.Join(javaHome, keytoolPath)

	if pathExists(filepath.Join(javaHome, "lib", "security", "cacerts")) {
		cacertsPath = filepath.Join(javaHome, "lib", "security", "cacerts")
	}
	if pathExists(filepath.Join(javaHome, "jre", "lib", "security", "cacerts")) {
		cacertsPath = filepath.Join(javaHome, "jre", "lib", "security", "cacerts")
	}

	return &javaTruststore{
		cacertsPath: cacertsPath,
		javaHome:    javaHome,
		keytoolPath: keytoolPath,
	}, nil
}

// Install installs the pem-encoded root certificate at the provided path
// to the Java trust store.
func (j *javaTruststore) Install(path string) error {
	c, err := decodeCert(path)
	if err != nil {
		return fmt.Errorf("failed to parse root certificate: %v", err)
	}

	_, err = j.execKeytool(
		"-importcert", "-noprompt",
		"-keystore", j.cacertsPath,
		"-storepass", storePass,
		"-file", path,
		"-alias", strings.Replace("mkcert development CA "+c.SerialNumber.String(), " ", "_", -1),
	)
	if err != nil {
		return fmt.Errorf("command %q failed: %v", "keytool -import", err)
	}
	return nil
}

// execKeytool will execute a "keytool" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func (j *javaTruststore) execKeytool(args ...string) ([]byte, error) {
	cmd := exec.Command(j.keytoolPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("java.io.FileNotFoundException")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd, err = commandWithSudo(cmd.Path)
		if err != nil {
			return nil, err
		}
		cmd.Args = append(cmd.Args, origArgs...)
		cmd.Env = []string{
			"JAVA_HOME=" + j.javaHome,
		}
		out, err = cmd.CombinedOutput()
	}
	return out, err
}
