package main

import (
	"encoding/json"
	"net/http"

	"github.com/modbit/modbit/pkg/modberr"
)

// server is the gateway's HTTP surface.
//
// What is here is health and capability discovery. What is deliberately *not* here is
// `/v1/complete`: constructing a `gateway.Gateway` needs an `inference.Registry`, which needs a
// model catalog, and no contract defines one yet. Inventing that shape would be introducing product
// scope, which `.agents.md` §3 forbids — the catalog belongs in `contracts/` first.
//
// So this serves the two endpoints whose contract is already settled, and the completion endpoint
// arrives when the catalog does. A half-configured gateway that answered `/v1/complete` with a
// guess would be worse than one that does not answer it.
type server struct {
	broker *envBroker
}

// routes returns the handler. Unknown paths 404 rather than falling through to a catch-all, so a
// typo in a client is a client error rather than a silent success.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/providers", s.handleProviders)
	return mux
}

// handleHealth reports liveness.
//
// It says nothing about configuration. A health endpoint that enumerated what is configured would
// be a discovery endpoint with no authorization on it, and this one is reachable by anything that
// can open a socket.
func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleProviders lists configured provider ids.
//
// Ids only, from `Providers()`, which reads a different structure than the secret map. That
// separation is the point: a handler cannot range over the credentials by accident because the
// method that would let it does not exist.
func (s *server) handleProviders(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"providers": s.broker.Providers()})
}

// writeJSON encodes a body, and fails loudly rather than half-writing.
//
// Encoding after WriteHeader cannot un-send the status, so the body is built first. A partial JSON
// document with a 200 already on the wire is the failure mode this avoids.
func writeJSON(w http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		writeError(w, modberr.Wrap(err, modberr.CodeInternal, "the response could not be encoded"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

// writeError renders a Modbit error as the stable envelope.
//
// It sends `Message()` rather than `Error()`. The full chain can carry a wrapped cause from a
// provider or the filesystem, and R-ERR-02 keeps that off a response a client reads: the code is
// what a caller branches on, and the detail belongs in a log that stays inside the boundary.
func writeError(w http.ResponseWriter, err error) {
	code := modberr.CodeOf(err)
	status := http.StatusInternalServerError
	message := "an internal error occurred"
	if typed, ok := err.(*modberr.Error); ok {
		status = typed.HTTPStatus()
		message = typed.Message()
	}
	encoded, marshalErr := json.Marshal(map[string]any{
		"error": map[string]string{"code": string(code), "message": message},
	})
	if marshalErr != nil {
		// Nothing left to serialize with. A bare status beats a malformed body.
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}
