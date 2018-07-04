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
	_, err := os.Stat(FirefoxPath)
	hasNSS = !os.IsNotExist(err)

	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("brew", "--prefix", "nss").Output()
		if err != nil {
			return
		}
		certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")

		_, err = os.Stat(certutilPath)
		hasCertutil = !os.IsNotExist(err)

	case "linux":
		_, err := os.Stat(nssDB)
		hasNSS = hasNSS && !os.IsNotExist(err)

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

func (m *mkcert) installNSS() {
	if m.forEachNSSProfile(func(profile string) {
		cmd := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", m.caUniqueName(), "-i", filepath.Join(m.CAROOT, rootName))
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("!!! You've hit a known issue. Please report the entire command output at https://github.com/FiloSottile/mkcert/issues/12\nProfile path: %s\nOS: %s/%s\ncertutil: %s\n", profile, runtime.GOOS, runtime.GOARCH, certutilPath)
			cmd := exec.Command("ls", "-l", profile[4:])
			cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
			cmd.Run()
		}
		fatalIfCmdErr(err, "certutil -A", out)
	}) == 0 {
		log.Printf("ERROR: no %s security databases found", NSSBrowsers)
	}
	if !m.checkNSS() {
		log.Printf("Installing in %s failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎", NSSBrowsers)
		log.Printf("Note that if you never started %s, you need to do that at least once.", NSSBrowsers)
	}
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
	if _, err := os.Stat(nssDB); !os.IsNotExist(err) {
		profiles = append(profiles, nssDB)
	}
	if len(profiles) == 0 {
		return
	}
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(profile, "cert8.db")); !os.IsNotExist(err) {
			f("dbm:" + profile)
			found++
		}
		if _, err := os.Stat(filepath.Join(profile, "cert9.db")); !os.IsNotExist(err) {
			f("sql:" + profile)
			found++
		}
	}
	return
}
