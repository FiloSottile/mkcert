package main

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/rand"

	"io/ioutil"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

const httpsPort = "8443"

// TestMkcert does simple from-command-line test of built mkcert binary and then tests simple client/server interaction
func TestMkcert_Run(t *testing.T) {

	// mkcert -install and then create a cert for localhost
	_, err := exec.Command("mkcert", "-install").CombinedOutput()
	assert.NoError(t, err)
	_, err = exec.Command("mkcert", "localhost").CombinedOutput()
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

	t.Logf("About to shutdown")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	err = server.Shutdown(ctx)
	t.Logf("Shutdown done")
	assert.NoError(t, err)
}
