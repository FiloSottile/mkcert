// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27

package main

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateMLDSAKey(t *testing.T) {
	m := &mkcert{mldsa: true}
	priv, err := m.generateKey(false)
	if err != nil {
		t.Fatalf("generateKey(false) with mldsa: %v", err)
	}
	if _, ok := priv.(*mldsa.PrivateKey); !ok {
		t.Fatalf("expected *mldsa.PrivateKey, got %T", priv)
	}

	// Root CA key should also be ML-DSA when flag is set.
	privCA, err := m.generateKey(true)
	if err != nil {
		t.Fatalf("generateKey(true) with mldsa: %v", err)
	}
	if _, ok := privCA.(*mldsa.PrivateKey); !ok {
		t.Fatalf("expected *mldsa.PrivateKey for root CA, got %T", privCA)
	}
}

func TestMLDSARootCA(t *testing.T) {
	dir := t.TempDir()
	m := &mkcert{
		mldsa:  true,
		CAROOT: dir,
	}
	m.newCA()

	// Verify root cert exists and is ML-DSA.
	certPEM, err := os.ReadFile(filepath.Join(dir, rootName))
	if err != nil {
		t.Fatalf("reading root cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode root cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing root cert: %v", err)
	}
	if _, ok := cert.PublicKey.(*mldsa.PublicKey); !ok {
		t.Fatalf("root CA public key: expected *mldsa.PublicKey, got %T", cert.PublicKey)
	}
	if !cert.IsCA {
		t.Fatal("root cert is not a CA")
	}

	// Verify key exists and is parseable.
	keyPEM, err := os.ReadFile(filepath.Join(dir, rootKeyName))
	if err != nil {
		t.Fatalf("reading root key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode root key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing root key: %v", err)
	}
	if _, ok := key.(*mldsa.PrivateKey); !ok {
		t.Fatalf("root CA key: expected *mldsa.PrivateKey, got %T", key)
	}
}

func TestMLDSALeafCert(t *testing.T) {
	dir := t.TempDir()
	m := &mkcert{
		mldsa:  true,
		CAROOT: dir,
	}

	// Create CA and load it.
	m.newCA()
	m.loadCA()

	// Generate leaf cert.
	hosts := []string{"localhost", "127.0.0.1"}
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	m.makeCert(hosts)

	// Check leaf cert file.
	certFile := filepath.Join(dir, "localhost+1.pem")
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("reading leaf cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode leaf cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing leaf cert: %v", err)
	}
	if _, ok := cert.PublicKey.(*mldsa.PublicKey); !ok {
		t.Fatalf("leaf cert public key: expected *mldsa.PublicKey, got %T", cert.PublicKey)
	}
	if cert.IsCA {
		t.Fatal("leaf cert should not be a CA")
	}

	// Verify the leaf is signed by the CA.
	roots := x509.NewCertPool()
	roots.AddCert(m.caCert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "localhost",
	})
	if err != nil {
		t.Fatalf("leaf cert verification failed: %v", err)
	}

	// Verify KeyUsage does not include KeyEncipherment.
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Fatal("ML-DSA leaf cert should not have KeyUsageKeyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("ML-DSA leaf cert should have KeyUsageDigitalSignature")
	}

	// Check leaf key file.
	keyFile := filepath.Join(dir, "localhost+1-key.pem")
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("reading leaf key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode leaf key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing leaf key: %v", err)
	}
	if _, ok := key.(*mldsa.PrivateKey); !ok {
		t.Fatalf("leaf key: expected *mldsa.PrivateKey, got %T", key)
	}
}

func TestMLDSALoadCA(t *testing.T) {
	dir := t.TempDir()
	m := &mkcert{
		mldsa:  true,
		CAROOT: dir,
	}

	// Create, then reload from disk.
	m.newCA()
	m2 := &mkcert{
		mldsa:  true,
		CAROOT: dir,
	}
	m2.loadCA()

	if m2.caCert == nil {
		t.Fatal("loadCA did not load the certificate")
	}
	if m2.caKey == nil {
		t.Fatal("loadCA did not load the key")
	}
	if _, ok := m2.caCert.PublicKey.(*mldsa.PublicKey); !ok {
		t.Fatalf("loaded CA cert public key: expected *mldsa.PublicKey, got %T", m2.caCert.PublicKey)
	}
	if _, ok := m2.caKey.(*mldsa.PrivateKey); !ok {
		t.Fatalf("loaded CA key: expected *mldsa.PrivateKey, got %T", m2.caKey)
	}
}

func TestMLDSANotECDSA(t *testing.T) {
	// When mldsa is set, generateKey should not return ECDSA.
	m := &mkcert{mldsa: true, ecdsa: false}
	priv, err := m.generateKey(false)
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if _, ok := priv.(*mldsa.PrivateKey); !ok {
		t.Fatalf("expected ML-DSA key, got %T", priv)
	}
}

func TestECDSAStillWorks(t *testing.T) {
	m := &mkcert{ecdsa: true}
	priv, err := m.generateKey(false)
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if _, ok := priv.(*mldsa.PrivateKey); ok {
		t.Fatal("ecdsa flag should not produce ML-DSA key")
	}
}

func TestRSAStillWorks(t *testing.T) {
	m := &mkcert{}
	priv, err := m.generateKey(false)
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if _, ok := priv.(*mldsa.PrivateKey); ok {
		t.Fatal("default should not produce ML-DSA key")
	}
}
