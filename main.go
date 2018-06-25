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
	"os"
	"path/filepath"
	"runtime"
	"time"
)

var installFlag = flag.Bool("install", false, "install the local root CA in the system trust store")

func main() {
	log.SetFlags(0)
	flag.Parse()
	(&mkcert{}).Run()
}

const rootName = "rootCA.pem"
const keyName = "rootCA-key.pem"

var rootSubject = pkix.Name{
	Organization: []string{"mkcert development CA"},
}

type mkcert struct {
	CAROOT string
	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool
}

func (m *mkcert) Run() {
	m.CAROOT = getCAROOT()
	if m.CAROOT == "" {
		log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
	}
	fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
	m.loadCA()
	if *installFlag {
		m.install()
	} else if !m.check() {
		log.Println("Warning: the local CA is not installed in the system trust store! ⚠️")
		log.Println("Run \"mkcert -install\" to avoid verification errors ‼️")
	}
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
		log.Println("The local CA is now installed in the system trust store! ⚡️")
	} else {
		log.Fatalln("Installing failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎")
	}
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
