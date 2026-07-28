package openai_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/inference/conformance"
	"github.com/modbit/modbit/pkg/inference/openai"
)

// fakeProvider is an OpenAI-compatible server that behaves the way a conformant provider does.
//
// The shared suite (MOD-A01e) is the ADP-5/ADP-6 evidence artifact, and running it against a fake
// adapter only proves the suite works. Running it against the real adapter over real HTTP proves the
// adapter does — which is the whole point of the suite existing, and the reason it was written to
// take an inference.Adapter rather than a fake.
type fakeProvider struct {
	// latency delays each streamed delta so a cancellation has something to interrupt.
	latency time.Duration
}

func (p fakeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/models") {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[]}`)
		return
	}

	var req struct {
		Model          string `json:"model"`
		Stream         bool   `json:"stream"`
		Messages       []any  `json:"messages"`
		Tools          []any  `json:"tools"`
		ResponseFormat *struct {
			Type string `json:"type"`
		} `json:"response_format"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"bad json","type":"invalid_request_error"}}`)
		return
	}
	// The suite sends a request with no messages to exercise error classification; a real provider
	// rejects it, and the adapter must map that onto a stable Modbit code rather than MODBIT_INTERNAL.
	if len(req.Messages) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"messages is required","type":"invalid_request_error"}}`)
		return
	}

	content := "The answer is 4."
	if req.ResponseFormat != nil && req.ResponseFormat.Type == "json_schema" {
		content = `{"answer":4}`
	}
	toolCalls := p.toolCallsFor(req.Tools)

	if req.Stream {
		p.stream(w, r, content, toolCalls)
		return
	}

	message := map[string]any{"role": "assistant"}
	finish := "stop"
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
		finish = "tool_calls"
	} else {
		message["content"] = content
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":      "cmpl-conformance",
		"model":   testModel().Revision,
		"choices": []map[string]any{{"index": 0, "message": message, "finish_reason": finish}},
		"usage": map[string]any{
			"prompt_tokens":         42,
			"completion_tokens":     8,
			"prompt_tokens_details": map[string]any{"cached_tokens": 12},
		},
	})
}

// toolCallsFor answers a tool-bearing request with one call per declared tool, which is what lets
// the suite reach Pass rather than Inconclusive on the serial and parallel tool-call cases.
func (p fakeProvider) toolCallsFor(tools []any) []map[string]any {
	var out []map[string]any
	for i, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		fn, ok := tool["function"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := fn["name"].(string)
		out = append(out, map[string]any{
			"index": i,
			"id":    "call_" + name,
			"type":  "function",
			"function": map[string]any{
				"name":      name,
				"arguments": `{"path":"a.go"}`,
			},
		})
	}
	return out
}

func (p fakeProvider) stream(w http.ResponseWriter, r *http.Request, content string, toolCalls []map[string]any) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")

	emit := func(payload map[string]any) bool {
		encoded, _ := json.Marshal(payload)
		if _, err := io.WriteString(w, "data: "+string(encoded)+"\n\n"); err != nil {
			return false
		}
		flusher.Flush()
		if p.latency > 0 {
			select {
			case <-time.After(p.latency):
			case <-r.Context().Done():
				return false
			}
		}
		return true
	}

	if !emit(map[string]any{
		"model":   testModel().Revision,
		"choices": []map[string]any{{"delta": map[string]any{"role": "assistant"}}},
	}) {
		return
	}

	if len(toolCalls) > 0 {
		for _, call := range toolCalls {
			if !emit(map[string]any{"choices": []map[string]any{{"delta": map[string]any{
				"tool_calls": []map[string]any{call},
			}}}}) {
				return
			}
		}
		_, _ = io.WriteString(w, `data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":42,"completion_tokens":8}}`+"\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
		return
	}

	for _, word := range strings.Fields(content) {
		if !emit(map[string]any{"choices": []map[string]any{{"delta": map[string]any{
			"content": word + " ",
		}}}}) {
			return
		}
	}
	_, _ = io.WriteString(w, `data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":42,"completion_tokens":8}}`+"\n\n")
	flusher.Flush()
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// conformanceModel declares only what this adapter and the fake provider actually support.
//
// A capability record that over-declares is the failure the suite exists to catch: a declared path
// the provider never exercises is Inconclusive, not Pass, and Inconclusive blocks production
// readiness. Trimming the record to the truth is the point, not a way of dodging the check.
func conformanceModel() inference.Capabilities {
	m := testModel()
	// No resolver is wired, so no modality is claimed. Declaring vision here would be exactly the
	// over-declaration described above.
	m.SupportsVision, m.SupportsAudio, m.SupportsFiles = false, false, false
	m.SupportsPromptCache = true
	m.PromptCacheTTL = 5 * time.Minute
	return m
}

// ADP-6 requires a recorded evidence artifact, and CI needs a machine-readable gate. This is that
// gate for the OpenAI-compatible adapter.
func TestAdapterPassesTheSharedConformanceSuite(t *testing.T) {
	server := httptest.NewServer(fakeProvider{latency: 5 * time.Millisecond})
	defer server.Close()

	model := conformanceModel()
	adapter, err := openai.New(openai.Options{
		Provider:   providerID,
		BaseURL:    server.URL + "/v1",
		HTTPClient: server.Client(),
		Models:     []inference.Capabilities{model},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	report := conformance.RunWithOptions(context.Background(), adapter, model, conformance.Options{
		StreamTimeout: 10 * time.Second,
		CancelTimeout: 5 * time.Second,
	})

	for _, result := range report.Failures() {
		t.Errorf("conformance failure: %s (%s): %s", result.Case, result.Requirement, result.Detail)
	}
	for _, result := range report.Inconclusive() {
		t.Errorf("conformance inconclusive: %s (%s): %s — a declared capability whose path the "+
			"provider did not exercise is not a pass", result.Case, result.Requirement, result.Detail)
	}
	if !report.ProductionReady() {
		t.Fatalf("adapter is not production ready: %s", report.Summary())
	}
	t.Logf("conformance: %s", report.Summary())
}

// R-ERR-02, asserted against the real adapter rather than the fake: a report is an artifact that
// gets stored and shared, so upstream content reaching it is a durable disclosure.
func TestConformanceReportCarriesNoUpstreamContent(t *testing.T) {
	marker := "sk-upstream-leak-4a91"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":{"message":"failed at 10.0.0.5 with key `+marker+`","type":"server_error"}}`)
	}))
	defer server.Close()

	model := conformanceModel()
	adapter, err := openai.New(openai.Options{
		Provider:   providerID,
		BaseURL:    server.URL + "/v1",
		HTTPClient: server.Client(),
		Models:     []inference.Capabilities{model},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	report := conformance.RunWithOptions(context.Background(), adapter, model, conformance.Options{
		StreamTimeout: 2 * time.Second,
		CancelTimeout: time.Second,
	})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(encoded), marker) {
		t.Fatal("an upstream credential reached the conformance report")
	}
	if strings.Contains(string(encoded), "10.0.0.5") {
		t.Fatal("an upstream address reached the conformance report")
	}
}
