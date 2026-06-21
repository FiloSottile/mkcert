// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27

package main

import (
	"crypto"
	"crypto/mldsa"
)

const mldsaSupported = true

func generateMLDSAKey() (crypto.PrivateKey, error) {
	return mldsa.GenerateKey(mldsa.MLDSA65())
}
