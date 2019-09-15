package main

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log"
	"math/rand"
	"os"
	"path/filepath"

	"io/ioutil"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

const httpsPort = "8443"

// MkcertFullPath is the full rooted path to the mkcert built by this TestMain
var MkcertFullPath string

// TestMain is used only to do a one-off build of the actual mkcert binary before running tests
// since this set of tests actually uses the binary.
func TestMain(m *testing.M) {
	testTmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatalf("Failed to make tmpdir: %v", err)
	}
	// Build mkcert from code for this OS
	_ = os.Setenv("CGO_ENABLED", "0")
	MkcertFullPath = filepath.Join(testTmpDir, "mkcert")
	out, err := exec.Command("go", "build", "-o", MkcertFullPath).CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to build mkcert: %v output=%s", err, out)
	}

	err = os.Chdir(testTmpDir)
	if err != nil {
		log.Fatalf("Failed to chdir to tmpdir: %v", err)
	}

	testRun := m.Run()
	_ = os.RemoveAll(testTmpDir)
	os.Exit(testRun)
}

// TestMkcert does simple from-command-line test of built mkcert binary and then tests simple client/server interaction
func TestMkcert_Run(t *testing.T) {

	// mkcert -install and then create a cert for localhost
	_, err := exec.Command(MkcertFullPath, "-install").CombinedOutput()
	assert.NoError(t, err)
	_, err = exec.Command(MkcertFullPath, "localhost").CombinedOutput()
	assert.NoError(t, err)
	assert.FileExists(t, "localhost.pem")
	assert.FileExists(t, "localhost-key.pem")

	// Listen with https server, handle all requests
	server := &http.Server{Addr: ":" + httpsPort, Handler: nil}
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "OK: %s\n", r.URL.Path)
		})
		_ = server.ListenAndServeTLS("localhost.pem", "localhost-key.pem")
	}()

	// Use the client to hit a random URL
	time.Sleep(time.Second)
	randomURI := rand.Intn(100)
	resp, err := http.Get(fmt.Sprintf("https://localhost:%s/%d", httpsPort, randomURI))
	assert.NoError(t, err)
	require.NotNil(t, resp)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.EqualValues(t, fmt.Sprintf("OK: /%d\n", randomURI), string(body))

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	err = server.Shutdown(ctx)
	assert.NoError(t, err)
}
