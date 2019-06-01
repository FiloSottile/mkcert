// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	FirefoxProfile      = os.Getenv("USERPROFILE") + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
	CertutilInstallHelp = "" // certutil unsupported on Windows
	NSSBrowsers         = "Firefox"
)

var (
	modcrypt32                           = syscall.NewLazyDLL("crypt32.dll")
	procCertAddEncodedCertificateToStore = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertCloseStore                   = modcrypt32.NewProc("CertCloseStore")
	procCertDeleteCertificateFromStore   = modcrypt32.NewProc("CertDeleteCertificateFromStore")
	procCertDuplicateCertificateContext  = modcrypt32.NewProc("CertDuplicateCertificateContext")
	procCertEnumCertificatesInStore      = modcrypt32.NewProc("CertEnumCertificatesInStore")
	procCertOpenSystemStoreW             = modcrypt32.NewProc("CertOpenSystemStoreW")
)

func (m *mkcert) installPlatform() bool {
	// Load cert
	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")
	// Decode PEM
	if certBlock, _ := pem.Decode(cert); certBlock == nil || certBlock.Type != "CERTIFICATE" {
		fatalIfErr(fmt.Errorf("Invalid PEM data"), "decode pem")
	} else {
		cert = certBlock.Bytes
	}
	// Open root store
	store, err := openWindowsRootStore()
	fatalIfErr(err, "open root store")
	defer store.close()
	// Add cert
	fatalIfErr(store.addCert(cert), "add cert")
	return true
}

func (m *mkcert) uninstallPlatform() bool {
	// We'll just remove all certs with the same serial number
	// Open root store
	store, err := openWindowsRootStore()
	fatalIfErr(err, "open root store")
	defer store.close()
	// Do the deletion
	deletedAny, err := store.deleteCertsWithSerial(m.caCert.SerialNumber)
	if err == nil && !deletedAny {
		err = fmt.Errorf("No certs found")
	}
	fatalIfErr(err, "delete cert")
	return true
}

type windowsRootStore uintptr

func openWindowsRootStore() (windowsRootStore, error) {
	store, _, err := procCertOpenSystemStoreW.Call(0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ROOT"))))
	if store != 0 {
		return windowsRootStore(store), nil
	}
	return 0, fmt.Errorf("Failed to open windows root store: %v", err)
}

func (w windowsRootStore) close() error {
	ret, _, err := procCertCloseStore.Call(uintptr(w), 0)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("Failed to close windows root store: %v", err)
}

func (w windowsRootStore) addCert(cert []byte) error {
	// TODO: ok to always overwrite?
	ret, _, err := procCertAddEncodedCertificateToStore.Call(
		uintptr(w), // HCERTSTORE hCertStore
		uintptr(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING), // DWORD dwCertEncodingType
		uintptr(unsafe.Pointer(&cert[0])),                              // const BYTE *pbCertEncoded
		uintptr(len(cert)),                                             // DWORD cbCertEncoded
		3,                                                              // DWORD dwAddDisposition (CERT_STORE_ADD_REPLACE_EXISTING is 3)
		0,                                                              // PCCERT_CONTEXT *ppCertContext
	)
	if ret != 0 {
		return nil
	}
	return fmt.Errorf("Failed adding cert: %v", err)
}

func (w windowsRootStore) deleteCertsWithSerial(serial *big.Int) (bool, error) {
	// Go over each, deleting the ones we find
	var cert *syscall.CertContext
	deletedAny := false
	for {
		// Next enum
		certPtr, _, err := procCertEnumCertificatesInStore.Call(uintptr(w), uintptr(unsafe.Pointer(cert)))
		if cert = (*syscall.CertContext)(unsafe.Pointer(certPtr)); cert == nil {
			if errno, ok := err.(syscall.Errno); ok && errno == 0x80092004 {
				break
			}
			return deletedAny, fmt.Errorf("Failed enumerating certs: %v", err)
		}
		// Parse cert
		certBytes := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:cert.Length]
		parsedCert, err := x509.ParseCertificate(certBytes)
		// We'll just ignore parse failures for now
		if err == nil && parsedCert.SerialNumber != nil && parsedCert.SerialNumber.Cmp(serial) == 0 {
			// Duplicate the context so it doesn't stop the enum when we delete it
			dupCertPtr, _, err := procCertDuplicateCertificateContext.Call(uintptr(unsafe.Pointer(cert)))
			if dupCertPtr == 0 {
				return deletedAny, fmt.Errorf("Failed duplicating context: %v", err)
			}
			if ret, _, err := procCertDeleteCertificateFromStore.Call(dupCertPtr); ret == 0 {
				return deletedAny, fmt.Errorf("Failed deleting certificate: %v", err)
			}
			deletedAny = true
		}
	}
	return deletedAny, nil
}
