// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mkcert is a simple zero-config tool to make development certificates.
package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"golang.org/x/net/idna"
)

func main() {
	log.SetFlags(0)
	var installFlag = flag.Bool("install", false, "install the local root CA in the system trust store")
	var uninstallFlag = flag.Bool("uninstall", false, "uninstall the local root CA from the system trust store")
	var carootFlag = flag.Bool("CAROOT", false, "print the CAROOT path")
	flag.Parse()
	if *carootFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: you can't set -[un]install and -CAROOT at the same time")
		}
		fmt.Println(getCAROOT())
		return
	}
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	(&mkcert{
		installMode: *installFlag, uninstallMode: *uninstallFlag,
	}).Run(flag.Args())
}

const rootName = "rootCA.pem"
const keyName = "rootCA-key.pem"

type mkcert struct {
	installMode, uninstallMode bool

	CAROOT string
	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool
}

func (m *mkcert) Run(args []string) {
	m.CAROOT = getCAROOT()
	if m.CAROOT == "" {
		log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
	}
	fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
	m.loadCA()

	if m.installMode {
		m.install()
		if len(args) == 0 {
			return
		}
	} else if m.uninstallMode {
		m.uninstall()
		return
	} else {
		var warning bool
		if !m.checkPlatform() {
			warning = true
			log.Println("Warning: the local CA is not installed in the system trust store! ⚠️")
		}
		if hasChrome && !m.checkChrome() {
			warning = true
			log.Println("Warning: the local CA is not installed in the Chrome/Chromium trust store! ⚠️")
		}
		if hasFirefox && !m.checkFirefox() {
			warning = true
			log.Println("Warning: the local CA is not installed in the Firefox trust store! ⚠️")
		}
		if warning {
			log.Println("Run \"mkcert -install\" to avoid verification errors ‼️")
		}
	}

	if len(args) == 0 {
		log.Printf(`
Usage:

	$ mkcert -install
	Install the local CA in the system trust store.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ mkcert '*.example.com'
	Generate "_wildcard.example.com.pem" and "_wildcard.example.com-key.pem".

	$ mkcert -uninstall
	Uninstall the local CA (but do not delete it).

Change the CA certificate and key storage location by setting $CAROOT,
print it with "mkcert -CAROOT".
`)
		return
	}

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)
	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			log.Fatalf("ERROR: %q is not a valid hostname or IP: %s", name, err)
		}
		args[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			log.Fatalf("ERROR: %q is not a valid hostname or IP", name)
		}
	}

	m.makeCert(args)
}

func getCAROOT() string {
	if env := os.Getenv("CAROOT"); env != "" {
		return env
	}

	var dir string
	switch runtime.GOOS {
	case "windows":
		dir = os.Getenv("LocalAppData")
	case "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("XDG_DATA_HOME")
		if dir == "" {
			dir = os.Getenv("HOME")
			if dir == "" {
				return ""
			}
			dir = filepath.Join(dir, ".local", "share")
		}
	}
	return filepath.Join(dir, "mkcert")
}

func (m *mkcert) install() {
	var printed bool
	if !m.checkPlatform() {
		m.installPlatform()

		// TODO: replace with a check for a successful install, drop OS check
		m.ignoreCheckFailure = true
		if runtime.GOOS != "linux" {
			log.Print("The local CA is now installed in the system trust store! ⚡️")
		}

		printed = true
	}
	if hasChrome && !m.checkChrome() {
		if hasCertutil {
			m.installChrome()
			log.Print("The local CA is now installed in the Chrome/Chromiumtrust store! 🦊")
		} else {
			log.Println(`Warning: "certutil" is not available, so the CA can't be automatically installed in Chrome/Chromium! ⚠️`)
			log.Printf(`Install "certutil" with "%s" and re-run "mkcert -install" 👈`, CertutilInstallHelp)
		}
		printed = true
	}
	if hasFirefox && !m.checkFirefox() {
		if hasCertutil {
			m.installFirefox()
			log.Print("The local CA is now installed in the Firefox trust store (requires restart)! 🦊")
		} else {
			log.Println(`Warning: "certutil" is not available, so the CA can't be automatically installed in Firefox! ⚠️`)
			log.Printf(`Install "certutil" with "%s" and re-run "mkcert -install" 👈`, CertutilInstallHelp)
		}
		printed = true
	}
	if printed {
		log.Print("")
	}
}

func (m *mkcert) uninstall() {
	m.uninstallPlatform()
	if hasFirefox {
		if hasCertutil {
			m.uninstallChrome()
			m.uninstallFirefox()
		} else {
			log.Print("")
			log.Println(`Warning: "certutil" is not available, so the CA can't be automatically uninstalled from Firefox and/or Chrome/Chromium (if it was ever installed)! ⚠️`)
			log.Printf(`You can install "certutil" with "%s" and re-run "mkcert -uninstall" 👈`, CertutilInstallHelp)
			log.Print("")
		}
	}
	log.Print("The local CA is now uninstalled from the system trust store(s)! 👋")
	log.Print("")
}

func (m *mkcert) checkPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		log.Fatalf("ERROR: failed to execute \"%s\": %s\n\n%s\n", cmd, err, out)
	}
}
