package truststore

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"os"

	"howett.net/plist"
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

type darwinStore struct{}

// Platform returns the truststore for the current platform.
func Platform() (Truststore, error) {
	return &darwinStore{}, nil
}

func platformTrustSettings() (map[string]interface{}, error) {
	plistFile, err := ioutil.TempFile("", "trust-settings")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer os.Remove(plistFile.Name())

	cmd, err := commandWithSudo("security", "trust-settings-export", "-d", plistFile.Name())
	if err != nil {
		return nil, err
	}
	if _, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("command %q failed: %v", "security trust-settings-export", err)
	}

	plistData, err := ioutil.ReadFile(plistFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read trust settings: %v", err)
	}
	var plistRoot map[string]interface{}
	if _, err := plist.Unmarshal(plistData, &plistRoot); err != nil {
		return nil, fmt.Errorf("failed to parse trust settings: %v", err)
	}

	if plistRoot["trustVersion"].(uint64) != 1 {
		return nil, fmt.Errorf("unsupported trust settings version: %v", plistRoot["trustVersion"])
	}
	return plistRoot, nil
}

func updatePlatformTrustSettings(root map[string]interface{}) error {
	plistFile, err := ioutil.TempFile("", "trust-settings")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer os.Remove(plistFile.Name())

	plistData, err := plist.MarshalIndent(root, plist.XMLFormat, "\t")
	if err != nil {
		return fmt.Errorf("failed to serialize trust settings: %v", err)
	}
	if err := ioutil.WriteFile(plistFile.Name(), plistData, 0600); err != nil {
		return fmt.Errorf("failed to write trust settings: %v", err)
	}

	cmd, err := commandWithSudo("security", "trust-settings-import", "-d", plistFile.Name())
	if err != nil {
		return err
	}
	if _, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("command %q failed: %v", "security trust-settings-import", err)
	}
	return nil
}

// Install installs the pem-encoded root certificate at the provided path
// to the system store.
func (i *darwinStore) Install(path string) error {
	cert, err := decodeCert(path)
	if err != nil {
		return err
	}
	cmd, err := commandWithSudo("security", "add-trusted-cert", "-d", "-k", "/Library/Keychains/System.keychain", path)
	if err != nil {
		return err
	}
	if _, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("command %q failed: %v", "security add-trusted-cert", err)
	}

	// Make trustSettings explicit, as older Go does not know the defaults.
	// https://github.com/golang/go/issues/24652
	plistRoot, err := platformTrustSettings()
	if err != nil {
		return err
	}
	rootSubjectASN1, _ := asn1.Marshal(cert.Subject.ToRDNSequence())
	// Update the trust settings to our defaults for any key which has the
	// same subject as our new cert,
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
	return updatePlatformTrustSettings(plistRoot)
}

// Uninstall removes the PEM-encoded certificate at path from the system store.
func (i *darwinStore) Uninstall(path string) error {
	cmd, err := commandWithSudo("security", "remove-trusted-cert", "-d", path)
	if err != nil {
		return err
	}
	if _, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("command %q failed: %v", "security remove-trusted-cert", err)
	}
	return nil
}
