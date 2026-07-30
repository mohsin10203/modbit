package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

func testServer(t *testing.T) http.Handler {
	t.Helper()
	b, _ := testBroker(t)
	return (&server{broker: b}).routes()
}

func get(t *testing.T, h http.Handler, path string) (*http.Response, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	res := rec.Result()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	_ = res.Body.Close()
	return res, string(body)
}

// INV-2, INV-11. No response from any route may contain credential material.
//
// The broker's own tests prove the secret cannot escape *it*. This proves it does not escape the
// surface built on top, which is a separate claim: a handler that ranged over the wrong map, or an
// error that wrapped a broker failure verbatim, would disclose it without the broker doing anything
// wrong. Every route is swept rather than the ones that look risky.
func TestSecurityNoResponseCarriesCredentialMaterial(t *testing.T) {
	h := testServer(t)
	for _, path := range []string{"/healthz", "/v1/providers", "/v1/unknown", "/", "/v1/complete"} {
		res, body := get(t, h, path)
		if strings.Contains(body, testSecret) {
			t.Fatalf("%s disclosed the secret (status %d): %s", path, res.StatusCode, body)
		}
		if strings.Contains(body, "sk-ant-second-secret") {
			t.Fatalf("%s disclosed the second secret: %s", path, body)
		}
	}
}

// Discovery lists provider ids and nothing else.
//
// A capability endpoint is the natural place for a credential to leak, because the thing being
// enumerated is keyed by provider. `Providers()` reads a different structure than the secret map,
// and this asserts the result carries only what that method returns.
func TestProviderDiscoveryListsIdsOnly(t *testing.T) {
	h := testServer(t)
	res, body := get(t, h, "/v1/providers")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var decoded struct {
		Providers []string `json:"providers"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v (%s)", err, body)
	}
	if len(decoded.Providers) != 2 || decoded.Providers[0] != "anthropic" || decoded.Providers[1] != "openai" {
		t.Fatalf("providers = %v, want [anthropic openai]", decoded.Providers)
	}
}

// Health reports liveness and does not describe the configuration.
//
// A health endpoint is reachable by anything that can open a socket, and this one carries no
// authorization. Enumerating what is configured here would make it a discovery endpoint with no
// gate on it.
func TestSecurityHealthDoesNotDescribeConfiguration(t *testing.T) {
	h := testServer(t)
	res, body := get(t, h, "/healthz")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	for _, leak := range []string{"openai", "anthropic", "provider", credentialEnvPrefix} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(leak)) {
			t.Fatalf("health disclosed configuration (%q): %s", leak, body)
		}
	}
}

// An unknown route is refused rather than absorbed.
//
// `/v1/complete` is deliberately absent until a model catalog contract exists, and it must 404
// rather than return a plausible empty success — a client cannot tell "not implemented" from
// "completed with nothing" if both are 200.
func TestUnknownRoutesAreRefused(t *testing.T) {
	h := testServer(t)
	for _, path := range []string{"/v1/complete", "/v1/unknown", "/admin"} {
		res, _ := get(t, h, path)
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s returned %d, want 404", path, res.StatusCode)
		}
	}
}

// The error envelope carries a stable code and a message, and not the wrapped cause.
//
// R-ERR-02: a response is read by a client and often logged by it. The chain can carry a provider
// or filesystem detail from inside the boundary, and `Message()` is the part meant to leave it.
func TestErrorEnvelopeCarriesTheCodeAndNotTheCause(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, modberr.Wrap(
		io.ErrUnexpectedEOF, modberr.CodeProviderUnavailable, "the provider is unavailable").
		WithDetail("constraint", "credential_source"))

	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	var decoded struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v (%s)", err, body)
	}
	if decoded.Error.Code != string(modberr.CodeProviderUnavailable) {
		t.Fatalf("code = %q, want %q", decoded.Error.Code, modberr.CodeProviderUnavailable)
	}
	if strings.Contains(string(body), io.ErrUnexpectedEOF.Error()) {
		t.Fatalf("the envelope leaked the wrapped cause: %s", body)
	}
	if res.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("content-type = %q", res.Header.Get("Content-Type"))
	}
}

// The process starts, serves, and shuts down on cancellation.
//
// Every test above drives the handler directly, which proves the routes and skips the wiring. This
// drives `run` — the actual startup path, including the credential scrub, the listener and the
// signal-shutdown branch — because the wiring is where a service usually breaks and it is the part
// no handler test touches.
func TestTheProcessServesAndShutsDownCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Port 0 lets the OS choose, so the test cannot collide with a real gateway or another run.
	addrs := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{credentialEnvPrefix + "OPENAI=" + testSecret}, "127.0.0.1:0",
			func(a net.Addr) { addrs <- a })
	}()

	var addr net.Addr
	select {
	case addr = <-addrs:
	case err := <-done:
		t.Fatalf("run exited before serving: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("run never reported a bound address")
	}

	// A real request over a real socket. Without this the test would prove only that cancellation
	// returns, which is the half that was never in doubt.
	res, err := http.Get("http://" + addr.String() + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	// The credential sweep applies over the wire too, not only through the handler.
	if strings.Contains(string(body), testSecret) {
		t.Fatalf("the served response disclosed the secret: %s", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want a clean shutdown", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after cancellation")
	}
}

// The process refuses to start with no credentials, rather than serving an unusable gateway.
func TestTheProcessRefusesToStartWithoutCredentials(t *testing.T) {
	err := run(context.Background(), []string{"PATH=/usr/bin"}, "127.0.0.1:0", nil)
	if err == nil {
		t.Fatal("run started with no credentials configured")
	}
	if !modberr.Is(err, modberr.CodeSettingInvalid) {
		t.Fatalf("err = %v, want CodeSettingInvalid", err)
	}
}
