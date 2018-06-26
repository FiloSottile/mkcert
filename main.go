// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mkcert is a simple zero-config tool to make development certificates.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)
	var installFlag = flag.Bool("install", false, "install the local root CA in the system trust store")
	var uninstallFlag = flag.Bool("uninstall", false, "uninstall the local root CA from the system trust store")
	flag.Parse()
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	(&mkcert{
		installMode: *installFlag, uninstallMode: *uninstallFlag,
	}).Run(flag.Args())
}

const rootName = "rootCA.pem"
const keyName = "rootCA-key.pem"

var rootSubject = pkix.Name{
	Organization: []string{"mkcert development CA"},
}

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
	} else if !m.check() {
		log.Println("Warning: the local CA is not installed in the system trust store! ⚠️")
		log.Println("Run \"mkcert -install\" to avoid verification errors ‼️")
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

	$ mkcert -uninstall
	Unnstall the local CA (but do not delete it).

Change the CA certificate and key storage location by setting $CAROOT.
`)
		return
	}

	re := regexp.MustCompile(`^[0-9A-Za-z._-]+$`)
	for _, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if re.MatchString(name) {
			continue
		}
		log.Fatalf("ERROR: %q is not a valid hostname or IP", name)
	}

	m.makeCert(args)
}

func (m *mkcert) makeCert(hosts []string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	fatalIfErr(err, "failed to generate certificate key")

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"mkcert development certificate"},
		},

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now().AddDate(0, 0, -1),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	pub := priv.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, &pub, m.caKey)
	fatalIfErr(err, "failed to generate certificate")

	filename := strings.Replace(hosts[0], ":", ".", -1)
	if len(hosts) > 1 {
		filename += "+" + strconv.Itoa(len(hosts)-1)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode certificate key")
	err = ioutil.WriteFile(filename+"-key.pem", pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0644)
	fatalIfErr(err, "failed to save certificate key")

	err = ioutil.WriteFile(filename+".pem", pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0600)
	fatalIfErr(err, "failed to save certificate key")

	log.Printf("\nCreated a new certificate valid for the following names 📜")
	for _, h := range hosts {
		log.Printf(" - %q", h)
	}
	log.Printf("\nThe certificate is at \"./%s.pem\" and the key at \"./%s-key.pem\" ✅\n\n", filename, filename)
}

// loadCA will load or create the CA at CAROOT.
func (m *mkcert) loadCA() {
	if _, err := os.Stat(filepath.Join(m.CAROOT, rootName)); os.IsNotExist(err) {
		m.newCA()
	} else {
		log.Printf("Using the local CA at \"%s\" ✨\n", m.CAROOT)
	}

	certPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read the CA certificate")
	keyPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, keyName))
	fatalIfErr(err, "failed to read the CA key")

	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	m.caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")

	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil || keyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the CA key: unexpected content")
	}
	m.caKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA key")
}

func (m *mkcert) newCA() {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	fatalIfErr(err, "failed to generate the CA key")

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      rootSubject,

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now().AddDate(0, 0, -1),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA: true,
	}

	pub := priv.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &pub, priv)
	fatalIfErr(err, "failed to generate CA certificate")

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")
	err = ioutil.WriteFile(filepath.Join(m.CAROOT, keyName), pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	fatalIfErr(err, "failed to save CA key")

	err = ioutil.WriteFile(filepath.Join(m.CAROOT, rootName), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0400)
	fatalIfErr(err, "failed to save CA key")

	log.Printf("Created a new local CA at \"%s\" 💥\n", m.CAROOT)
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
	if m.check() {
		return
	}

	m.installPlatform()
	m.ignoreCheckFailure = true

	/*
		switch runtime.GOOS {
		case "darwin":
			m.installDarwin()
		default:
			log.Println("Installing is not available on your platform 👎")
			log.Fatalf("If you know how, you can install the certificate at \"%s\" in your system trust store", filepath.Join(m.CAROOT, rootName))
		}
	*/

	if m.check() { // useless, see comment on ignoreCheckFailure
		log.Print("The local CA is now installed in the system trust store! ⚡️\n\n")
	} else {
		log.Fatal("Installing failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎\n\n")
	}
}

func (m *mkcert) uninstall() {
	m.uninstallPlatform()
	log.Print("The local CA is now uninstalled from the system trust store! 👋\n\n")
}

func (m *mkcert) check() bool {
	if m.ignoreCheckFailure {
		return true
	}

	/*
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		fatalIfErr(err, "failed to generate the test key")

		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(42),
			DNSNames:     []string{"test.mkcert.invalid"},

			NotAfter:  time.Now().AddDate(0, 0, 1),
			NotBefore: time.Now().AddDate(0, 0, -1),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		pub := priv.PublicKey
		cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, &pub, m.caKey)
		fatalIfErr(err, "failed to generate test certificate")

		c, err := x509.ParseCertificate(cert)
		fatalIfErr(err, "failed to parse test certificate")
	*/

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}
