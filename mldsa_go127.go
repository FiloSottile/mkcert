// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27

package main

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"log"
)

const mldsaSupported = true

func generateMLDSAKey() (crypto.PrivateKey, error) {
	return mldsa.GenerateKey(mldsa.MLDSA65())
}

func marshalMLDSAPrivateKey(priv crypto.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(priv)
}

func marshalMLDSAPublicKey(pub crypto.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

func parseMLDSAPrivateKey(derBytes []byte) (crypto.PrivateKey, error) {
	return x509.ParsePKCS8PrivateKey(derBytes)
}

func isMLDSAKey(key crypto.PrivateKey) bool {
	_, ok := key.(*mldsa.PrivateKey)
	return ok
}

func pemBlockTypeForMLDSAKey() string {
	return "PRIVATE KEY"
}

func logMLDSAKeyType() {
	log.Printf("Using ML-DSA-65 (FIPS 204) post-quantum key\n")
}

func encodeMLDSAPrivateKeyPEM(priv crypto.PrivateKey) []byte {
	privDER, err := marshalMLDSAPrivateKey(priv)
	fatalIfErr(err, "failed to encode ML-DSA private key")
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
}
