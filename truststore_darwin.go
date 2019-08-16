// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/asn1"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"howett.net/plist"
)

var (
	FirefoxProfile      = os.Getenv("HOME") + "/Library/Application Support/Firefox/Profiles/*"
	CertutilInstallHelp = "brew install nss"
	NSSBrowsers         = "Firefox"
)

// https://github.com/golang/go/issues/24652#issuecomment-399826583
var trustSettings []interface{}
var _, _ = plist.Unmarshal(trustSettingsData, &trustSettings)
var trustSettingsData = []byte(`
<array>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAED
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>sslServer</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAEC
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>basicX509</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
</array>
`)

func (m *mkcert) installPlatform() bool {
	cmd := commandWithSudo("security", "add-trusted-cert", "-d", "-k", "/Library/Keychains/System.keychain", filepath.Join(m.CAROOT, rootName))
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "security add-trusted-cert", out)

	// Make trustSettings explicit, as older Go does not know the defaults.
	// https://github.com/golang/go/issues/24652

	plistFile, err := ioutil.TempFile("", "trust-settings")
	fatalIfErr(err, "failed to create temp file")
	defer os.Remove(plistFile.Name())

	cmd = commandWithSudo("security", "trust-settings-export", "-d", plistFile.Name())
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, "security trust-settings-export", out)

	plistData, err := ioutil.ReadFile(plistFile.Name())
	fatalIfErr(err, "failed to read trust settings")
	var plistRoot map[string]interface{}
	_, err = plist.Unmarshal(plistData, &plistRoot)
	fatalIfErr(err, "failed to parse trust settings")

	rootSubjectASN1, _ := asn1.Marshal(m.caCert.Subject.ToRDNSequence())

	if plistRoot["trustVersion"].(uint64) != 1 {
		log.Fatalln("ERROR: unsupported trust settings version:", plistRoot["trustVersion"])
	}
	trustList := plistRoot["trustList"].(map[string]interface{})
	for key := range trustList {
		entry := trustList[key].(map[string]interface{})
		if _, ok := entry["issuerName"]; !ok {
			continue
		}
		issuerName := entry["issuerName"].([]byte)
		if !bytes.Equal(rootSubjectASN1, issuerName) {
			continue
		}
		entry["trustSettings"] = trustSettings
		break
	}

	plistData, err = plist.MarshalIndent(plistRoot, plist.XMLFormat, "\t")
	fatalIfErr(err, "failed to serialize trust settings")
	err = ioutil.WriteFile(plistFile.Name(), plistData, 0600)
	fatalIfErr(err, "failed to write trust settings")

	cmd = commandWithSudo("security", "trust-settings-import", "-d", plistFile.Name())
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, "security trust-settings-import", out)

	return true
}

func (m *mkcert) uninstallPlatform() bool {
	cmd := commandWithSudo("security", "remove-trusted-cert", "-d", filepath.Join(m.CAROOT, rootName))
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "security remove-trusted-cert", out)

	return true
}
