// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

type pkcs8 struct { // Duplicated from x509 package
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

var ( // Duplicated from x509 package
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

var ( // Duplicated from x509 package
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) { // Duplicated from x509 package
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

func marshalPKCS8PrivateKey(key interface{}) (der []byte, err error) {
	var privKey pkcs8
	switch key := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is technically
		// superfluous, but most other code includes it.
		privKey.Algo.Parameters = asn1.RawValue{
			Tag: 5,
		}
		privKey.PrivateKey = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		privKey.Algo.Algorithm = oidPublicKeyECDSA
		namedCurveOID, ok := oidFromNamedCurve(key.Curve)
		if !ok {
			return nil, errors.New("pkcs12: unknown elliptic curve")
		}
		if privKey.Algo.Parameters.FullBytes, err = asn1.Marshal(namedCurveOID); err != nil {
			return nil, errors.New("pkcs12: failed to embed OID of named curve in PKCS#8: " + err.Error())
		}
		if privKey.PrivateKey, err = x509.MarshalECPrivateKey(key); err != nil {
			return nil, errors.New("pkcs12: failed to embed EC private key in PKCS#8: " + err.Error())
		}
	default:
		return nil, errors.New("pkcs12: only RSA and ECDSA private keys supported")
	}
	return asn1.Marshal(privKey)
}
