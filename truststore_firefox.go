package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	hasFirefox   bool
	hasCertutil  bool
	certutilPath string
)

func init() {
	_, err := os.Stat(FirefoxPath)
	hasFirefox = !os.IsNotExist(err)

	out, err := exec.Command("brew", "--prefix", "nss").Output()
	if err != nil {
		return
	}
	certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")

	_, err = os.Stat(certutilPath)
	hasCertutil = !os.IsNotExist(err)
}

func (m *mkcert) checkFirefox() bool {
	if !hasCertutil {
		return false
	}
	success := true
	if m.forEachFirefoxProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			success = false
		}
	}) == 0 {
		success = false
	}
	return success
}

func (m *mkcert) installFirefox() {
	if m.forEachFirefoxProfile(func(profile string) {
		cmd := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", m.caUniqueName(), "-i", filepath.Join(m.CAROOT, rootName))
		out, err := cmd.CombinedOutput()
		fatalIfCmdErr(err, "certutil -A", out)
	}) == 0 {
		log.Println("ERROR: no Firefox security databases found")
	}
	if !m.checkFirefox() {
		log.Println("Installing in Firefox failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎")
		log.Println("Note that if you never started Firefox, you need to do that at least once.")
	}
}

func (m *mkcert) uninstallFirefox() {
	m.forEachFirefoxProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			return
		}
		cmd := exec.Command(certutilPath, "-D", "-d", profile, "-n", m.caUniqueName())
		out, err := cmd.CombinedOutput()
		fatalIfCmdErr(err, "certutil -D", out)
	})
}

func (m *mkcert) forEachFirefoxProfile(f func(profile string)) (found int) {
	profiles, _ := filepath.Glob(FirefoxProfile)
	if len(profiles) == 0 {
		return
	}
	for _, profile := range profiles {
		if _, err := os.Stat(filepath.Join(profile, "cert8.db")); !os.IsNotExist(err) {
			f(profile)
			found++
		}
		if _, err := os.Stat(filepath.Join(profile, "cert9.db")); !os.IsNotExist(err) {
			f("sql:" + profile)
			found++
		}
	}
	return
}
