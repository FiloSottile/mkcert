// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	nssDBs       = []string{
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

func init() {
	allPaths := append(append([]string{}, nssDBs...), firefoxPaths...)
	for _, path := range allPaths {
		if pathExists(path) {
			hasNSS = true
			break
		}
	}

	switch runtime.GOOS {
	case "darwin":
		if hasCertutil = binaryExists("certutil"); hasCertutil {
			certutilPath, _ = exec.LookPath("certutil")
		} else {
			out, err := exec.Command("brew", "--prefix", "nss").Output()
			if err == nil {
				certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")
				hasCertutil = pathExists(certutilPath)
			}
		}

	case "linux":
		if hasCertutil = binaryExists("certutil"); hasCertutil {
			certutilPath, _ = exec.LookPath("certutil")
		}
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
	profiles = append(profiles, nssDBs...)
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if pathExists(filepath.Join(profile, "cert9.db")) {
			f("sql:" + profile)
			found++
		} else if pathExists(filepath.Join(profile, "cert8.db")) {
			f("dbm:" + profile)
			found++
		}
	}
	return
}
