package openai_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/inference/openai"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

const (
	providerID = "local-openai"
	modelID    = "test-model"
	secret     = "sk-test-DO-NOT-LEAK-8f3a2b"
)

func testModel() inference.Capabilities {
	return inference.Capabilities{
		ProviderID:               providerID,
		ModelID:                  modelID,
		Revision:                 "test-model-2026-01-01",
		ReleaseDate:              time.Unix(1700000000, 0).UTC(),
		Aliases:                  []string{"fast"},
		MaxContextTokens:         8192,
		MaxOutputTokens:          2048,
		SupportsTools:            true,
		SupportsParallelToolCall: true,
		ToolSchemaDialect:        inference.DialectJSONSchemaDraft202012,
		SupportsStructuredOutput: true,
		SupportsStrictSchema:     true,
		SupportsStreaming:        true,
		SupportsCancellation:     true,
		StreamEventKinds:         []string{"message_start", "text_delta", "message_stop"},
		Regions:                  []string{"local"},
		ProviderRetentionDays:    0,
		RequestsPerMinute:        60,
		TokensPerMinute:          100000,
		MaxConcurrency:           4,
		TypicalLatency:           time.Second,
		ReliabilityScore:         0.99,
		Pricing: inference.Pricing{
			InputPerMillion:  inference.Money{Micros: 1000, Currency: "USD"},
			OutputPerMillion: inference.Money{Micros: 2000, Currency: "USD"},
		},
		SafetyFilterBehavior: inference.SafetyRefusalPart,
	}
}

func testCredential() inference.Credential {
	return inference.NewCredential(providerID, "lease-1", secret, time.Now().Add(time.Hour))
}

func testRequest() inference.Request {
	return inference.Request{
		IRVersion: inference.Version,
		Alias:     "fast",
		Messages: []inference.Message{{
			Role: inference.RoleUser,
			Parts: []inference.Part{{
				Kind: inference.PartText, Text: "hello", Provenance: taint.UserTrusted,
			}},
		}},
		RunID:  id.MustNew(id.Run),
		StepID: id.MustNew(id.RunStep),
	}
}

// recorder captures what the adapter actually sent, so a test can assert on the wire rather than on
// the adapter's own account of itself.
type recorder struct {
	mu       chan struct{}
	path     string
	auth     string
	rawQuery string
	body     map[string]any
}

func newRecorder() *recorder { return &recorder{mu: make(chan struct{}, 1)} }

func (r *recorder) capture(req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.path = req.URL.Path
	r.auth = req.Header.Get("Authorization")
	r.rawQuery = req.URL.RawQuery
	r.body = map[string]any{}
	_ = json.Unmarshal(body, &r.body)
}

// newAdapter wires an adapter to a test server. The client is explicit because the adapter refuses
// to build one (O1).
func newAdapter(t *testing.T, handler http.HandlerFunc, opts ...func(*openai.Options)) (*openai.Adapter, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	o := openai.Options{
		Provider:   providerID,
		BaseURL:    server.URL + "/v1",
		HTTPClient: server.Client(),
		Models:     []inference.Capabilities{testModel()},
	}
	for _, fn := range opts {
		fn(&o)
	}
	adapter, err := openai.New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return adapter, server
}

func jsonResponse(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

func simpleCompletion() map[string]any {
	return map[string]any{
		"id":    "cmpl-1",
		"model": "test-model-2026-01-01",
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": "hi there"},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 3},
	}
}

// O1. MOD-A01k puts the egress allowlist in the adapter's transport. A client the adapter built for
// itself would carry http.DefaultTransport and reach any host the process can — the allowlist would
// still be configured, still be tested, and no longer be in the path.
func TestSecurityAdapterRefusesToBuildItsOwnHTTPClient(t *testing.T) {
	_, err := openai.New(openai.Options{
		Provider: providerID,
		BaseURL:  "https://example.invalid/v1",
		Models:   []inference.Capabilities{testModel()},
	})
	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal when no HTTP client is supplied", err)
	}
	if !strings.Contains(err.Error(), "egress") {
		t.Fatalf("the refusal should say why a client is required: %v", err)
	}
}

// O1, second half: an egress refusal from the transport must surface as the policy denial it is,
// not as a provider outage — the gateway fails over on retryable classes, and the next attempt would
// reach the same blocked destination.
func TestSecurityEgressRefusalIsNotReportedAsAnOutage(t *testing.T) {
	denied := modberr.New(modberr.CodePolicyDenied, "destination is not on the provider allowlist")
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, denied
	})}

	adapter, err := openai.New(openai.Options{
		Provider:   providerID,
		BaseURL:    "https://blocked.invalid/v1",
		HTTPClient: client,
		Models:     []inference.Capabilities{testModel()},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = adapter.Complete(context.Background(), testRequest(), testModel(), testCredential())
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v, want the policy denial preserved", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// O2. The secret belongs in the Authorization header and nowhere else. A URL is logged by proxies,
// servers, and Go's own error strings, so a credential in a query parameter is a credential in
// somebody's log.
func TestSecurityCredentialTravelsOnlyInTheAuthorizationHeader(t *testing.T) {
	rec := newRecorder()
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		rec.capture(r)
		jsonResponse(t, w, simpleCompletion())
	})

	if _, err := adapter.Complete(context.Background(), testRequest(), testModel(), testCredential()); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if rec.auth != "Bearer "+secret {
		t.Fatalf("authorization header = %q", rec.auth)
	}
	if strings.Contains(rec.path, secret) || strings.Contains(rec.rawQuery, secret) {
		t.Fatalf("the credential reached the URL: path=%q query=%q", rec.path, rec.rawQuery)
	}
	encoded, _ := json.Marshal(rec.body)
	if strings.Contains(string(encoded), secret) {
		t.Fatal("the credential reached the request body")
	}
}

// O2, second half: a missing, mismatched, or expired credential is refused before any request is
// made. An adapter that fell back to an ambient value would make INV-2 unobservable.
func TestSecurityCredentialsAreCheckedBeforeAnyRequest(t *testing.T) {
	contacted := false
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		contacted = true
		jsonResponse(t, w, simpleCompletion())
	})

	cases := map[string]inference.Credential{
		"missing":        {},
		"wrong provider": inference.NewCredential("someone-else", "lease", secret, time.Now().Add(time.Hour)),
		"expired":        inference.NewCredential(providerID, "lease", secret, time.Now().Add(-time.Minute)),
	}
	for name, cred := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := adapter.Complete(context.Background(), testRequest(), testModel(), cred); err == nil {
				t.Fatal("expected a refusal")
			}
			if contacted {
				t.Fatal("a provider was contacted despite an unusable credential")
			}
		})
	}
}

// O3. A provider error body routinely echoes the request — including the prompt, and occasionally
// the credential that was rejected — so it must never reach a Modbit error (R-ERR-02).
func TestSecurityUpstreamErrorBodiesNeverReachTheError(t *testing.T) {
	leak := "prompt was: hello, and your key sk-test-DO-NOT-LEAK-8f3a2b is invalid"

	for _, tc := range []struct {
		name   string
		status int
		want   modberr.Code
	}{
		{"unauthorized", http.StatusUnauthorized, modberr.CodeUnauthenticated},
		{"forbidden", http.StatusForbidden, modberr.CodeUnauthenticated},
		{"not found", http.StatusNotFound, modberr.CodeNoEligibleRoute},
		{"rate limited", http.StatusTooManyRequests, modberr.CodeRateLimited},
		{"server error", http.StatusInternalServerError, modberr.CodeProviderUnavailable},
		{"bad request", http.StatusBadRequest, modberr.CodeInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"error":{"message":"`+leak+`","type":"server_error"}}`)
			})

			_, err := adapter.Complete(context.Background(), testRequest(), testModel(), testCredential())
			if !modberr.Is(err, tc.want) {
				t.Fatalf("error = %v, want %s", err, tc.want)
			}
			// R-ERR-01: an unclassified error crossing a boundary cannot be retried or budgeted.
			if modberr.Is(err, modberr.CodeInternal) {
				t.Fatalf("provider failure was not classified: %v", err)
			}
			if msg := err.Error(); strings.Contains(msg, secret) || strings.Contains(msg, "prompt was") {
				t.Fatalf("upstream body content reached the error: %s", msg)
			}
		})
	}
}

// O4. A capability gap is either a refusal or a declared Loss. A silent drop is what lets a
// downgraded completion pass as a clean one (MOD-A01 decision 4).
func TestCapabilityGapsAreRefusedOrDeclared(t *testing.T) {
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(t, w, simpleCompletion())
	})

	t.Run("unsupported tools are refused", func(t *testing.T) {
		model := testModel()
		model.SupportsTools = false
		req := testRequest()
		req.Tools = []inference.ToolDefinition{{Name: "read", InputSchema: json.RawMessage(`{"type":"object"}`)}}

		_, err := adapter.Complete(context.Background(), req, model, testCredential())
		if !modberr.Is(err, modberr.CodeCapabilityUnavailable) {
			t.Fatalf("error = %v, want capability unavailable", err)
		}
	})

	t.Run("strict schema downgrade is declared", func(t *testing.T) {
		model := testModel()
		model.SupportsStrictSchema = false
		req := testRequest()
		req.StructuredOutput = &inference.StructuredOutput{
			SchemaID: "review.finding.v2", Version: 2,
			Schema: json.RawMessage(`{"type":"object"}`), Strict: true,
		}

		resp, err := adapter.Complete(context.Background(), req, model, testCredential())
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if !hasLoss(resp.Losses, inference.LossDowngraded, "structured_output.strict") {
			t.Fatalf("strict downgrade was not declared: %+v", resp.Losses)
		}
	})

	t.Run("developer role merge is declared", func(t *testing.T) {
		req := testRequest()
		req.Developer = []inference.Part{{
			Kind: inference.PartText, Text: "follow the rules", Provenance: taint.UserTrusted,
		}}

		resp, err := adapter.Complete(context.Background(), req, testModel(), testCredential())
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if !hasLoss(resp.Losses, inference.LossReshaped, "messages.developer") {
			t.Fatalf("developer merge was not declared: %+v", resp.Losses)
		}
	})

	// An unsupported modality is a refusal, not a Loss. This originally asserted the opposite and
	// the shared conformance suite disagreed — see the comment in encodeMedia. Omitting an image is
	// not a degraded answer, it is an answer to a different question, and it comes back looking
	// entirely successful.
	t.Run("unsupported modality is refused", func(t *testing.T) {
		model := testModel()
		model.SupportsVision = false
		req := testRequest()
		req.Messages[0].Parts = append(req.Messages[0].Parts, inference.Part{
			Kind: inference.PartImage,
			Media: &inference.MediaRef{
				ObjectRef: id.MustNew(id.Artifact), MediaType: "image/png",
				Digest: "sha256:" + strings.Repeat("a", 64), Bytes: 100,
			},
			Provenance: taint.UserTrusted,
		})

		_, err := adapter.Complete(context.Background(), req, model, testCredential())
		if !modberr.Is(err, modberr.CodeCapabilityUnavailable) {
			t.Fatalf("error = %v, want a refusal; dropping the image would answer a different question", err)
		}
	})
}

func hasLoss(losses []inference.Loss, kind inference.LossKind, feature string) bool {
	for _, l := range losses {
		if l.Kind == kind && l.Feature == feature {
			return true
		}
	}
	return false
}

// O8. A prompt sent without its image gets a confident answer to a question nobody asked, and
// nothing downstream can tell. Refusing beats dropping when the model *can* take the modality.
func TestMediaWithoutAResolverIsRefusedNotDropped(t *testing.T) {
	model := testModel()
	model.SupportsVision = true
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(t, w, simpleCompletion())
	})

	req := testRequest()
	req.Messages[0].Parts = append(req.Messages[0].Parts, inference.Part{
		Kind: inference.PartImage,
		Media: &inference.MediaRef{
			ObjectRef: id.MustNew(id.Artifact), MediaType: "image/png",
			Digest: "sha256:" + strings.Repeat("b", 64), Bytes: 100,
		},
		Provenance: taint.UserTrusted,
	})

	_, err := adapter.Complete(context.Background(), req, model, testCredential())
	if !modberr.Is(err, modberr.CodeCapabilityUnavailable) {
		t.Fatalf("error = %v, want a refusal when media cannot be resolved", err)
	}
}

// With a resolver the bytes are inlined, and the IR still never carried them (MOD-A01 decision 2).
func TestMediaIsInlinedThroughTheResolver(t *testing.T) {
	rec := newRecorder()
	model := testModel()
	model.SupportsVision = true
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		rec.capture(r)
		jsonResponse(t, w, simpleCompletion())
	}, func(o *openai.Options) { o.Media = fixedResolver{payload: []byte{0x89, 'P', 'N', 'G'}} })

	req := testRequest()
	req.Messages[0].Parts = append(req.Messages[0].Parts, inference.Part{
		Kind: inference.PartImage,
		Media: &inference.MediaRef{
			ObjectRef: id.MustNew(id.Artifact), MediaType: "image/png",
			Digest: "sha256:" + strings.Repeat("c", 64), Bytes: 4,
		},
		Provenance: taint.UserTrusted,
	})

	if _, err := adapter.Complete(context.Background(), req, model, testCredential()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	encoded, _ := json.Marshal(rec.body)
	if !strings.Contains(string(encoded), "data:image/png;base64,") {
		t.Fatalf("the image was not inlined: %s", encoded)
	}
}

type fixedResolver struct{ payload []byte }

func (f fixedResolver) Resolve(context.Context, inference.MediaRef) ([]byte, error) {
	return f.payload, nil
}

// O7. The gateway pairs a tool result with its call on the id, so an id lost in translation makes
// the result unattachable and the conversation unresumable.
func TestToolCallsRoundTrip(t *testing.T) {
	rec := newRecorder()
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		rec.capture(r)
		jsonResponse(t, w, map[string]any{
			"model": "test-model-2026-01-01",
			"choices": []map[string]any{{
				"message": map[string]any{
					"role": "assistant",
					"tool_calls": []map[string]any{{
						"id": "call_abc", "type": "function",
						"function": map[string]any{"name": "read_file", "arguments": `{"path":"a.go"}`},
					}},
				},
				"finish_reason": "tool_calls",
			}},
			"usage": map[string]any{"prompt_tokens": 5, "completion_tokens": 7},
		})
	})

	req := testRequest()
	req.Tools = []inference.ToolDefinition{{
		Name: "read_file", Description: "reads a file",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`),
	}}
	req.ToolChoice = &inference.ToolChoice{Mode: inference.ToolChoiceRequired}

	resp, err := adapter.Complete(context.Background(), req, testModel(), testCredential())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.FinishReason != inference.FinishToolUse {
		t.Fatalf("finish reason = %q, want tool_use", resp.FinishReason)
	}

	var call *inference.ToolCall
	for _, p := range resp.Parts {
		if p.Kind == inference.PartToolCall {
			call = p.ToolCall
		}
	}
	if call == nil {
		t.Fatal("no tool call part in the response")
	}
	if call.ID != "call_abc" || call.Name != "read_file" {
		t.Fatalf("tool call = %+v, want id call_abc name read_file", call)
	}
	if string(call.Input) != `{"path":"a.go"}` {
		t.Fatalf("arguments = %s", call.Input)
	}

	// The outbound half: the tool definition and the required choice must have reached the wire.
	if rec.body["tool_choice"] != "required" {
		t.Fatalf("tool_choice = %v, want required", rec.body["tool_choice"])
	}
	tools, _ := rec.body["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools on the wire = %v", rec.body["tools"])
	}

	// And a result replayed back must carry its call id.
	req.Messages = append(req.Messages, inference.Message{
		Role: inference.RoleTool,
		Parts: []inference.Part{{
			Kind: inference.PartToolResult,
			ToolResult: &inference.ToolResult{
				CallID: "call_abc",
				Parts:  []inference.Part{{Kind: inference.PartText, Text: "package a", Provenance: taint.ToolResult}},
			},
			Provenance: taint.ToolResult,
		}},
	})
	if _, err := adapter.Complete(context.Background(), req, testModel(), testCredential()); err != nil {
		t.Fatalf("replay: %v", err)
	}
	messages, _ := rec.body["messages"].([]any)
	last, _ := messages[len(messages)-1].(map[string]any)
	if last["tool_call_id"] != "call_abc" {
		t.Fatalf("replayed tool result lost its call id: %+v", last)
	}
}

// O10. The revision comes from what answered, not from what was asked for. Their divergence is what
// makes a silent provider model change detectable (MOD-6).
func TestObservedRevisionComesFromTheResponse(t *testing.T) {
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		payload := simpleCompletion()
		payload["model"] = "test-model-2026-07-01" // the provider rolled the model
		jsonResponse(t, w, payload)
	})

	resp, err := adapter.Complete(context.Background(), testRequest(), testModel(), testCredential())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.ModelRevision != "test-model-2026-07-01" {
		t.Fatalf("revision = %q, want the one the provider reported", resp.ModelRevision)
	}
	if resp.ModelRevision == testModel().Revision {
		t.Fatal("the declared revision was echoed instead of the observed one")
	}
}

// A provider that reports no model at all must be recorded as a loss rather than silently attributed
// to the declared revision, or drift detection would compare a value against itself.
func TestAMissingRevisionIsDeclaredAsALoss(t *testing.T) {
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		payload := simpleCompletion()
		delete(payload, "model")
		jsonResponse(t, w, payload)
	})

	resp, err := adapter.Complete(context.Background(), testRequest(), testModel(), testCredential())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !hasLoss(resp.Losses, inference.LossUnsupported, "model_revision") {
		t.Fatalf("a missing revision was not declared: %+v", resp.Losses)
	}
}

// O9. A budget decision made on an estimate must say so rather than presenting it as measured.
func TestTokenCountsDeclareThemselvesEstimates(t *testing.T) {
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {})

	count, err := adapter.CountTokens(context.Background(), testRequest(), testModel())
	if err != nil {
		t.Fatalf("CountTokens: %v", err)
	}
	if count.Exact {
		t.Fatal("the chat-completions protocol has no counting endpoint; this cannot be exact")
	}
	if count.Tokens <= 0 {
		t.Fatalf("tokens = %d, want a positive estimate", count.Tokens)
	}
}

// Cached and reasoning tokens are reported by the protocol as subsets of the prompt and completion
// totals; the canonical Usage keeps them separate and sums all four. Failing to subtract would bill
// a cached call twice for the same tokens.
func TestUsageSplitsCachedAndReasoningTokensWithoutDoubleCounting(t *testing.T) {
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(t, w, map[string]any{
			"model": "test-model-2026-01-01",
			"choices": []map[string]any{{
				"message": map[string]any{"role": "assistant", "content": "ok"}, "finish_reason": "stop",
			}},
			"usage": map[string]any{
				"prompt_tokens":             100,
				"completion_tokens":         40,
				"prompt_tokens_details":     map[string]any{"cached_tokens": 60},
				"completion_tokens_details": map[string]any{"reasoning_tokens": 25},
			},
		})
	})

	resp, err := adapter.Complete(context.Background(), testRequest(), testModel(), testCredential())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	u := resp.Usage
	if u.InputTokens != 40 || u.CachedInputTokens != 60 {
		t.Fatalf("input split = %d/%d, want 40 fresh and 60 cached", u.InputTokens, u.CachedInputTokens)
	}
	if u.OutputTokens != 15 || u.ReasoningTokens != 25 {
		t.Fatalf("output split = %d/%d, want 15 output and 25 reasoning", u.OutputTokens, u.ReasoningTokens)
	}
	if u.Total() != 140 {
		t.Fatalf("total = %d, want 140 — the provider's own prompt+completion sum", u.Total())
	}
}

func sseHandler(t *testing.T, chunks []string, delay time.Duration) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("test server does not support flushing")
		}
		for _, chunk := range chunks {
			if _, err := io.WriteString(w, "data: "+chunk+"\n\n"); err != nil {
				return
			}
			flusher.Flush()
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-r.Context().Done():
					return
				}
			}
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
	}
}

// drain enforces O5 on every use: exactly one terminal event, always before close.
func drain(t *testing.T, events <-chan inference.StreamEvent) (deltas []string, final *inference.Response, streamErr error) {
	t.Helper()
	terminals := 0
	for e := range events {
		switch e.Kind {
		case inference.StreamTextDelta:
			deltas = append(deltas, e.Text)
		case inference.StreamMessageStop:
			terminals++
			final = e.Final
		case inference.StreamError:
			terminals++
			streamErr = e.Err
		}
	}
	if terminals != 1 {
		t.Fatalf("stream carried %d terminal events, want exactly 1", terminals)
	}
	return deltas, final, streamErr
}

// O5. Exactly one terminal event, always before close, on every exit path.
func TestStreamingAssemblesDeltasAndTerminatesOnce(t *testing.T) {
	adapter, _ := newAdapter(t, sseHandler(t, []string{
		`{"model":"test-model-2026-07-01","choices":[{"delta":{"role":"assistant"}}]}`,
		`{"choices":[{"delta":{"content":"Hello"}}]}`,
		`{"choices":[{"delta":{"content":", world"}}]}`,
		`{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}`,
	}, 0))

	events, err := adapter.Stream(context.Background(), testRequest(), testModel(), testCredential())
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	deltas, final, streamErr := drain(t, events)
	if streamErr != nil {
		t.Fatalf("stream error: %v", streamErr)
	}
	if strings.Join(deltas, "") != "Hello, world" {
		t.Fatalf("deltas = %q", deltas)
	}
	if final == nil {
		t.Fatal("no final response")
	}
	if got := textOf(final); got != "Hello, world" {
		t.Fatalf("assembled text = %q", got)
	}
	if final.ModelRevision != "test-model-2026-07-01" {
		t.Fatalf("streamed revision = %q, want the observed one", final.ModelRevision)
	}
	if final.Usage.InputTokens != 4 || final.Usage.OutputTokens != 2 {
		t.Fatalf("streamed usage = %+v; without stream_options a streamed call is unbillable", final.Usage)
	}
}

func textOf(r *inference.Response) string {
	var sb strings.Builder
	for _, p := range r.Parts {
		if p.Kind == inference.PartText {
			sb.WriteString(p.Text)
		}
	}
	return sb.String()
}

// O5, the hard case: a stream that ends without content is a failure, not an empty success.
// Reporting it as success would let a truncated answer pass as a whole one (gateway decision 30).
func TestAStreamThatProducesNothingIsAFailure(t *testing.T) {
	adapter, _ := newAdapter(t, sseHandler(t, []string{
		`{"choices":[{"delta":{"role":"assistant"}}]}`,
	}, 0))

	events, err := adapter.Stream(context.Background(), testRequest(), testModel(), testCredential())
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	_, final, streamErr := drain(t, events)
	if streamErr == nil {
		t.Fatal("a stream with no content must terminate with an error")
	}
	if final != nil {
		t.Fatal("a failed stream must not carry a final response")
	}
}

// O6. Cancellation abandons the upstream rather than draining it, and the terminal event still
// arrives — cancelling the work must not cancel the notification that the work ended.
func TestCancellationTerminatesTheStreamPromptly(t *testing.T) {
	chunks := make([]string, 200)
	for i := range chunks {
		chunks[i] = `{"choices":[{"delta":{"content":"tick "}}]}`
	}
	adapter, _ := newAdapter(t, sseHandler(t, chunks, 5*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	events, err := adapter.Stream(ctx, testRequest(), testModel(), testCredential())
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Read a couple of deltas so cancellation lands mid-stream, then cancel and drain.
	<-events
	<-events
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		terminals := 0
		for e := range events {
			if e.Kind == inference.StreamMessageStop || e.Kind == inference.StreamError {
				terminals++
			}
		}
		if terminals != 1 {
			t.Errorf("cancelled stream carried %d terminal events, want exactly 1", terminals)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled stream did not close within 5s; it is draining rather than abandoning")
	}
}

// A tool call arriving in fragments must reassemble into one call. Splitting it would hand the
// harness two half-formed calls whose arguments parse as nothing.
func TestStreamedToolCallFragmentsReassemble(t *testing.T) {
	adapter, _ := newAdapter(t, sseHandler(t, []string{
		`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"read_file","arguments":"{\"pa"}}]}}]}`,
		`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"th\":\"a.go\"}"}}]}}]}`,
		`{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`,
	}, 0))

	events, err := adapter.Stream(context.Background(), testRequest(), testModel(), testCredential())
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	_, final, streamErr := drain(t, events)
	if streamErr != nil {
		t.Fatalf("stream error: %v", streamErr)
	}

	var call *inference.ToolCall
	for _, p := range final.Parts {
		if p.Kind == inference.PartToolCall {
			call = p.ToolCall
		}
	}
	if call == nil {
		t.Fatalf("no tool call assembled from fragments: %+v", final.Parts)
	}
	if call.ID != "call_1" || call.Name != "read_file" {
		t.Fatalf("call = %+v", call)
	}
	if string(call.Input) != `{"path":"a.go"}` {
		t.Fatalf("fragments did not reassemble: %s", call.Input)
	}
	if final.FinishReason != inference.FinishToolUse {
		t.Fatalf("finish reason = %q, want tool_use", final.FinishReason)
	}
}

// A stream refused at establishment returns an error and allocates no channel, so a caller never has
// to drain something that was never going to produce anything.
func TestAStreamRefusedAtEstablishmentAllocatesNoChannel(t *testing.T) {
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	events, err := adapter.Stream(context.Background(), testRequest(), testModel(), testCredential())
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if events != nil {
		t.Fatal("a refused stream must not allocate a channel")
	}

	model := testModel()
	model.SupportsStreaming = false
	events, err = adapter.Stream(context.Background(), testRequest(), model, testCredential())
	if !modberr.Is(err, modberr.CodeCapabilityUnavailable) {
		t.Fatalf("error = %v, want capability unavailable", err)
	}
	if events != nil {
		t.Fatal("a non-streaming model must not allocate a channel")
	}
}

// The request must reach the documented path. A base URL with a trailing slash is the ordinary
// configuration mistake, and it must not produce a double slash the provider 404s on.
func TestRequestsReachTheChatCompletionsPath(t *testing.T) {
	rec := newRecorder()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.capture(r)
		jsonResponse(t, w, simpleCompletion())
	}))
	defer server.Close()

	adapter, err := openai.New(openai.Options{
		Provider:   providerID,
		BaseURL:    server.URL + "/v1/",
		HTTPClient: server.Client(),
		Models:     []inference.Capabilities{testModel()},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := adapter.Complete(context.Background(), testRequest(), testModel(), testCredential()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if rec.path != "/v1/chat/completions" {
		t.Fatalf("path = %q, want /v1/chat/completions", rec.path)
	}
}

// A construction that could never route is refused up front rather than costing a failover attempt
// at request time.
func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	client := &http.Client{}
	base := openai.Options{
		Provider: providerID, BaseURL: "https://example.invalid/v1",
		HTTPClient: client, Models: []inference.Capabilities{testModel()},
	}

	mutate := map[string]func(*openai.Options){
		"no provider": func(o *openai.Options) { o.Provider = "" },
		"no base url": func(o *openai.Options) { o.BaseURL = "" },
		"no models":   func(o *openai.Options) { o.Models = nil },
		"model belongs to another provider": func(o *openai.Options) {
			m := testModel()
			m.ProviderID = "somebody-else"
			o.Models = []inference.Capabilities{m}
		},
	}
	for name, fn := range mutate {
		t.Run(name, func(t *testing.T) {
			opts := base
			fn(&opts)
			if _, err := openai.New(opts); !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want a refusal", err)
			}
		})
	}
}

// A cancelled request must stay cancellation rather than becoming a provider fault: the gateway
// fails over on retryable classes, and retrying a call the caller cancelled spends budget
// reproducing a result nobody wants.
func TestCancellationIsNotReportedAsAProviderFault(t *testing.T) {
	// The handler must have a way out that does not depend on the client's cancellation reaching it:
	// httptest.Server.Close waits for outstanding handlers, and a handler parked on a request context
	// that never fires deadlocks the whole package. Registered after newAdapter so cleanup order
	// (LIFO) releases the handler before the server is closed.
	release := make(chan struct{})
	adapter, _ := newAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	_, err := adapter.Complete(ctx, testRequest(), testModel(), testCredential())
	if !modberr.Is(err, modberr.CodeCancelled) {
		t.Fatalf("error = %v, want cancelled", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the cause was lost: %v", err)
	}
}
