// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

var userAndHostname string

func init() {
	u, _ := user.Current()
	if u != nil {
		userAndHostname = u.Username + "@"
	}
	out, _ := exec.Command("hostname").Output()
	userAndHostname += strings.TrimSpace(string(out))
}

func (m *mkcert) makeCert(hosts []string) {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	fatalIfErr(err, "failed to generate certificate key")

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"mkcert development certificate"},
			OrganizationalUnit: []string{userAndHostname},
		},

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

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

	filename := strings.Replace(hosts[0], ":", "_", -1)
	filename = strings.Replace(filename, "*", "_wildcard", -1)
	if len(hosts) > 1 {
		filename += "+" + strconv.Itoa(len(hosts)-1)
	}

	if !m.pkcs12 {
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		fatalIfErr(err, "failed to encode certificate key")
		err = ioutil.WriteFile(filename+"-key.pem", pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600)
		fatalIfErr(err, "failed to save certificate key")

		err = ioutil.WriteFile(filename+".pem", pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
		fatalIfErr(err, "failed to save certificate key")
	} else {
		domainCert, _ := x509.ParseCertificate(cert)
		pfxData, err := pkcs12.Encode(rand.Reader, priv, domainCert, []*x509.Certificate{m.caCert}, "changeit")
		fatalIfErr(err, "failed to generate PKCS#12")
		err = ioutil.WriteFile(filename+".p12", pfxData, 0644)
		fatalIfErr(err, "failed to save PKCS#12")
	}

	secondLvlWildcardRegexp := regexp.MustCompile(`(?i)^\*\.[0-9a-z_-]+$`)
	log.Printf("\nCreated a new certificate valid for the following names 📜")
	for _, h := range hosts {
		log.Printf(" - %q", h)
		if secondLvlWildcardRegexp.MatchString(h) {
			log.Printf("   Warning: many browsers don't support second-level wildcards like %q ⚠️", h)
		}
	}

	if !m.pkcs12 {
		log.Printf("\nThe certificate is at \"./%s.pem\" and the key at \"./%s-key.pem\" ✅\n\n", filename, filename)
	} else {
		log.Printf("\nThe PKCS#12 bundle is at \"./%s.p12\" ✅\n\n", filename)
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
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	m.caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")

	if _, err := os.Stat(filepath.Join(m.CAROOT, keyName)); os.IsNotExist(err) {
		return // keyless mode, where only -install works
	}

	keyPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, keyName))
	fatalIfErr(err, "failed to read the CA key")
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
	pub := priv.PublicKey

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")

	spkiASN1, err := x509.MarshalPKIXPublicKey(&pub)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"mkcert development CA"},
			OrganizationalUnit: []string{userAndHostname},

			// The CommonName is required by iOS to show the certificate in the
			// "Certificate Trust Settings" menu.
			// https://github.com/FiloSottile/mkcert/issues/47
			CommonName: "mkcert " + userAndHostname,
		},
		SubjectKeyId: skid[:],

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:           true,
		MaxPathLenZero: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &pub, priv)
	fatalIfErr(err, "failed to generate CA certificate")

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")
	err = ioutil.WriteFile(filepath.Join(m.CAROOT, keyName), pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	fatalIfErr(err, "failed to save CA key")

	err = ioutil.WriteFile(filepath.Join(m.CAROOT, rootName), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save CA key")

	log.Printf("Created a new local CA at \"%s\" 💥\n", m.CAROOT)
}

func (m *mkcert) signCSR() {
	csrPEMBlock, err := ioutil.ReadFile(m.csr)
	fatalIfErr(err, "failed to read the CSR")
	csrDERBlock, _ := pem.Decode(csrPEMBlock)
	if csrDERBlock == nil {
		log.Fatalln("ERROR: failed to read the CSR: unexpected content")
	}
	if csrDERBlock.Type != "CERTIFICATE REQUEST" {
		log.Fatalln("ERROR: failed to read the CSR: Must be CERTIFICATE REQUEST not " + csrDERBlock.Type)
	}
	csr, err := x509.ParseCertificateRequest(csrDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA key")

	err = csr.CheckSignature()
	fatalIfErr(err, "invalid CSR signature")

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")

	tpl := &x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            csr.Subject,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		Version:            csr.Version,
		Extensions:         csr.Extensions,
		ExtraExtensions:    csr.ExtraExtensions,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, csr.PublicKey, m.caKey)
	fatalIfErr(err, "failed to sign certificate")

	filename := strings.Replace(tpl.Subject.CommonName, ":", "_", -1)
	filename = strings.Replace(filename, "*", "_wildcard", -1)
	sans := len(tpl.IPAddresses) + len(tpl.DNSNames) + len(tpl.EmailAddresses) + len(tpl.URIs)
	if sans > 1 {
		filename += "+" + strconv.Itoa(sans-1)
	}

	log.Printf("Filename: %s", filename)

	if !m.pkcs12 {
		err = ioutil.WriteFile(filename+".pem", pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
		fatalIfErr(err, "failed to save certificate key")
	} else {
		domainCert, _ := x509.ParseCertificate(cert)
		pfxData, err := pkcs12.Encode(rand.Reader, nil, domainCert, []*x509.Certificate{m.caCert}, "changeit")
		fatalIfErr(err, "failed to generate PKCS#12")
		err = ioutil.WriteFile(filename+".p12", pfxData, 0644)
		fatalIfErr(err, "failed to save PKCS#12")
	}

	log.Printf("\nSuccessfully signed CSR 📜")

	if !m.pkcs12 {
		log.Printf("\nThe certificate is at \"./%s.pem\" ✅\n\n", filename)
	} else {
		log.Printf("\nThe PKCS#12 is at \"./%s.p12\" ✅\n\n", filename)
	}
}

func (m *mkcert) caUniqueName() string {
	return "mkcert development CA " + m.caCert.SerialNumber.String()
}
