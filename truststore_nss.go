package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	hasNSS       bool
	hasCertutil  bool
	certutilPath string
	nssDB        = filepath.Join(os.Getenv("HOME"), ".pki/nssdb")
)

func init() {
	for _, path := range []string{
		"/usr/local/bin/firefox", "/usr/bin/firefox", nssDB,
		"/Applications/Firefox.app",
		"/Applications/Firefox Developer Edition.app",
		"/Applications/Firefox Nightly.app",
		"C:\\Program Files\\Mozilla Firefox",
	} {
		_, err := os.Stat(path)
		hasNSS = hasNSS || err == nil
	}

	switch runtime.GOOS {
	case "darwin":
		var err error
		certutilPath, err = exec.LookPath("certutil")
		if err != nil {
			var out []byte
			out, err = exec.Command("brew", "--prefix", "nss").Output()
			if err != nil {
				return
			}
			certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")
			_, err = os.Stat(certutilPath)
		}
		hasCertutil = err == nil

	case "linux":
	case "openbsd":
		var err error
		certutilPath, err = exec.LookPath("certutil")
		hasCertutil = err == nil
	}
}

func (m *mkcert) checkNSS() bool {
	if !hasCertutil {
		return false
	}
	success := true
	if m.forEachNSSProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			success = false
		}
	}) == 0 {
		success = false
	}
	return success
}

func (m *mkcert) installNSS() bool {
	if m.forEachNSSProfile(func(profile string) {
		cmd := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", m.caUniqueName(), "-i", filepath.Join(m.CAROOT, rootName))
		out, err := cmd.CombinedOutput()
		fatalIfCmdErr(err, "certutil -A", out)
	}) == 0 {
		log.Printf("ERROR: no %s security databases found", NSSBrowsers)
		return false
	}
	if !m.checkNSS() {
		log.Printf("Installing in %s failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎", NSSBrowsers)
		log.Printf("Note that if you never started %s, you need to do that at least once.", NSSBrowsers)
		return false
	}
	return true
}

func (m *mkcert) uninstallNSS() {
	m.forEachNSSProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			return
		}
		cmd := exec.Command(certutilPath, "-D", "-d", profile, "-n", m.caUniqueName())
		out, err := cmd.CombinedOutput()
		fatalIfCmdErr(err, "certutil -D", out)
	})
}

func (m *mkcert) forEachNSSProfile(f func(profile string)) (found int) {
	profiles, _ := filepath.Glob(FirefoxProfile)
	if _, err := os.Stat(nssDB); err == nil {
		profiles = append(profiles, nssDB)
	}
	if len(profiles) == 0 {
		return
	}
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(profile, "cert9.db")); err == nil {
			f("sql:" + profile)
			found++
			continue
		}
		if _, err := os.Stat(filepath.Join(profile, "cert8.db")); err == nil {
			f("dbm:" + profile)
			found++
		}
	}
	return
}
