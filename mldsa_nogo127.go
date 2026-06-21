// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !go1.27

package main

import (
	"crypto"
	"errors"
)

const mldsaSupported = false

func generateMLDSAKey() (crypto.PrivateKey, error) {
	return nil, errors.New("ML-DSA support requires Go 1.27 or later")
}

func marshalMLDSAPrivateKey(priv crypto.PrivateKey) ([]byte, error) {
	return nil, errors.New("ML-DSA support requires Go 1.27 or later")
}

func marshalMLDSAPublicKey(pub crypto.PublicKey) ([]byte, error) {
	return nil, errors.New("ML-DSA support requires Go 1.27 or later")
}

func parseMLDSAPrivateKey(derBytes []byte) (crypto.PrivateKey, error) {
	return nil, errors.New("ML-DSA support requires Go 1.27 or later")
}

func isMLDSAKey(key crypto.PrivateKey) bool {
	return false
}

func pemBlockTypeForMLDSAKey() string {
	return "PRIVATE KEY"
}

func logMLDSAKeyType() {
}

func encodeMLDSAPrivateKeyPEM(priv crypto.PrivateKey) []byte {
	return nil
}
