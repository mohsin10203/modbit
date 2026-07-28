package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Options configure an Adapter.
type Options struct {
	// Provider is the stable provider identifier used in routing and evidence. It must match the
	// identifier the egress policy and the capability records use, or a call would be checked
	// against one provider's allowlist and billed to another.
	Provider string
	// BaseURL is the API root, for example "https://api.example.com/v1" or "http://127.0.0.1:11434/v1".
	BaseURL string
	// HTTPClient performs every request.
	//
	// O1. It is required rather than defaulted. MOD-A01k puts the egress allowlist in the adapter's
	// own transport, so a client the adapter built for itself would carry http.DefaultTransport and
	// reach any host the process can — the allowlist would still be configured, still be tested, and
	// no longer be in the path. Making the caller supply it means the guard cannot be forgotten
	// silently; it has to be removed deliberately.
	HTTPClient *http.Client
	// Models are the capability records this adapter serves.
	Models []inference.Capabilities
	// Media resolves media references to bytes. Optional; without it a media part is refused rather
	// than dropped (O8).
	Media MediaResolver
	// RequestTimeout bounds a non-streaming call. Zero leaves it to the client and the context.
	RequestTimeout time.Duration
}

// Adapter speaks the OpenAI chat-completions protocol.
type Adapter struct {
	provider string
	baseURL  string
	client   *http.Client
	models   []inference.Capabilities
	media    MediaResolver
	timeout  time.Duration
}

var _ inference.Adapter = (*Adapter)(nil)

// New returns an Adapter, refusing an incomplete configuration.
func New(opts Options) (*Adapter, error) {
	bad := func(msg, field string) (*Adapter, error) {
		return nil, modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", field)
	}
	if opts.Provider == "" {
		return bad("adapter requires a provider identifier", "provider")
	}
	if opts.BaseURL == "" {
		return bad("adapter requires a base URL", "base_url")
	}
	if opts.HTTPClient == nil {
		// O1. See Options.HTTPClient: defaulting this would quietly remove the egress guard.
		return bad("adapter requires an HTTP client carrying the egress-guarded transport", "http_client")
	}
	if len(opts.Models) == 0 {
		// An adapter serving no models is not a degraded adapter; it is one that can never route,
		// and discovering that at request time costs a failover attempt for nothing.
		return bad("adapter requires at least one capability record", "models")
	}
	for _, m := range opts.Models {
		if m.ProviderID != opts.Provider {
			return bad("every capability record must name this adapter's provider", "models")
		}
		if err := m.Validate(); err != nil {
			return nil, err
		}
	}
	return &Adapter{
		provider: opts.Provider,
		baseURL:  strings.TrimRight(opts.BaseURL, "/"),
		client:   opts.HTTPClient,
		models:   opts.Models,
		media:    opts.Media,
		timeout:  opts.RequestTimeout,
	}, nil
}

// Provider implements inference.Adapter.
func (a *Adapter) Provider() string { return a.provider }

// Capabilities implements inference.Adapter.
func (a *Adapter) Capabilities(context.Context) ([]inference.Capabilities, error) {
	out := make([]inference.Capabilities, len(a.models))
	copy(out, a.models)
	return out, nil
}

// Complete implements inference.Adapter.
func (a *Adapter) Complete(ctx context.Context, req inference.Request, model inference.Capabilities, cred inference.Credential) (inference.Response, error) {
	if err := a.checkCredential(cred); err != nil {
		return inference.Response{}, err
	}
	body, losses, err := a.translateRequest(ctx, req, model, false)
	if err != nil {
		return inference.Response{}, err
	}
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}

	resp, err := a.post(ctx, body, cred, false)
	if err != nil {
		return inference.Response{}, err
	}
	defer resp.Body.Close()

	if err := statusError(resp); err != nil {
		return inference.Response{}, err
	}
	var raw chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return inference.Response{}, modberr.Wrap(err, modberr.CodeProviderUnavailable,
			"provider response could not be decoded")
	}
	if raw.Error != nil {
		return inference.Response{}, providerError(resp.StatusCode, raw.Error)
	}
	return translateResponse(req, model, raw, losses)
}

// Stream implements inference.Adapter.
//
// O5. The returned channel is closed exactly once and carries exactly one terminal event on every
// exit path, which is what the gateway's S1–S10 protocol is built on top of.
func (a *Adapter) Stream(ctx context.Context, req inference.Request, model inference.Capabilities, cred inference.Credential) (<-chan inference.StreamEvent, error) {
	if err := a.checkCredential(cred); err != nil {
		return nil, err
	}
	if !model.SupportsStreaming {
		return nil, modberr.New(modberr.CodeCapabilityUnavailable, "model does not support streaming").
			WithDetail("capability", "streaming")
	}
	body, losses, err := a.translateRequest(ctx, req, model, true)
	if err != nil {
		return nil, err
	}
	// Establishment is synchronous: a refused call returns an error and allocates no channel, so a
	// caller never has to drain a stream that was never going to produce anything.
	resp, err := a.post(ctx, body, cred, true)
	if err != nil {
		return nil, err
	}
	if err := statusError(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}

	events := make(chan inference.StreamEvent)
	go a.pump(ctx, resp, req, model, losses, events)
	return events, nil
}

// pump decodes the SSE body into normalized events. It owns resp.Body and the channel.
func (a *Adapter) pump(ctx context.Context, resp *http.Response, req inference.Request, model inference.Capabilities, losses []inference.Loss, events chan<- inference.StreamEvent) {
	defer close(events)
	defer resp.Body.Close()

	send := func(e inference.StreamEvent) bool {
		select {
		case events <- e:
			return true
		case <-ctx.Done():
			// O6. Abandon rather than drain: continuing to decode a cancelled stream spends the
			// provider's tokens and the caller's budget on a result nobody will read.
			return false
		}
	}
	// terminal delivers the one terminal event this stream is allowed (O5).
	//
	// It does not consult ctx, and it is not a non-blocking send. Both are the same mistake in
	// different clothing: cancelling the work must not cancel the notification that the work ended,
	// and dropping the event because the consumer was momentarily busy closes the channel with no
	// terminal event at all. That is B-7 in the gateway, found there by a drain helper enforcing S4;
	// the same trap is one line away in every adapter that streams.
	terminal := func(e inference.StreamEvent) {
		select {
		case events <- e:
		case <-time.After(terminalSendTimeout):
		}
	}
	fail := func(err error) {
		terminal(inference.StreamEvent{Kind: inference.StreamError, Err: err})
	}

	if !send(inference.StreamEvent{Kind: inference.StreamMessageStart}) {
		fail(modberr.New(modberr.CodeCancelled, "stream cancelled"))
		return
	}

	var (
		text      strings.Builder
		reasoning strings.Builder
		refusal   string
		calls     = map[int]*inference.ToolCall{}
		order     []int
		usage     *chatUsage
		finish    string
		revision  string
		scanner   = bufio.NewScanner(resp.Body)
	)
	// SSE lines can be long; the default 64KiB limit truncates a large tool-call argument fragment
	// mid-JSON, which decodes as a parse error rather than as the truncation it is.
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			break
		}

		var chunk chatResponse
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			fail(modberr.Wrap(err, modberr.CodeProviderUnavailable, "stream chunk could not be decoded"))
			return
		}
		if chunk.Error != nil {
			fail(providerError(resp.StatusCode, chunk.Error))
			return
		}
		if chunk.Model != "" {
			revision = chunk.Model
		}
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		choice := chunk.Choices[0]
		if choice.FinishReason != "" {
			finish = choice.FinishReason
		}
		delta := choice.Delta
		if delta == nil {
			continue
		}

		if delta.Content != "" {
			text.WriteString(delta.Content)
			if !send(inference.StreamEvent{Kind: inference.StreamTextDelta, Text: delta.Content}) {
				fail(modberr.New(modberr.CodeCancelled, "stream cancelled"))
				return
			}
		}
		if delta.Reasoning != "" {
			reasoning.WriteString(delta.Reasoning)
			if !send(inference.StreamEvent{Kind: inference.StreamReasoningDelta, Text: delta.Reasoning}) {
				fail(modberr.New(modberr.CodeCancelled, "stream cancelled"))
				return
			}
		}
		if delta.Refusal != "" {
			refusal += delta.Refusal
		}

		for _, call := range delta.ToolCalls {
			// The protocol indexes tool calls per choice and sends the id and name once, on the
			// first fragment; later fragments carry only arguments. Accumulating by index is what
			// keeps a multi-fragment argument object from being split across two calls.
			idx := 0
			if call.Index != nil {
				idx = *call.Index
			}
			existing := calls[idx]
			if existing == nil {
				existing = &inference.ToolCall{Input: json.RawMessage{}}
				calls[idx] = existing
				order = append(order, idx)
			}
			if call.ID != "" {
				existing.ID = call.ID
			}
			if call.Function.Name != "" {
				existing.Name = call.Function.Name
			}
			if call.Function.Arguments != "" {
				existing.Input = append(existing.Input, call.Function.Arguments...)
			}
			if !send(inference.StreamEvent{
				Kind:       inference.StreamToolCallDelta,
				Index:      idx + 1,
				ToolCallID: existing.ID,
				ToolName:   existing.Name,
				InputDelta: call.Function.Arguments,
			}) {
				fail(modberr.New(modberr.CodeCancelled, "stream cancelled"))
				return
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fail(modberr.Wrap(err, modberr.CodeProviderUnavailable, "stream ended abnormally"))
		return
	}

	final, err := a.assembleFinal(req, model, assembled{
		text: text.String(), reasoning: reasoning.String(), refusal: refusal,
		calls: calls, order: order, usage: usage, finish: finish, revision: revision,
		losses: losses,
	})
	if err != nil {
		fail(err)
		return
	}
	terminal(inference.StreamEvent{Kind: inference.StreamMessageStop, Final: &final})
}

// terminalSendTimeout bounds delivery of the terminal event to a consumer that stopped reading. The
// gateway enforces its own stall timeout; this only stops the goroutine leaking if it does not.
const terminalSendTimeout = 30 * time.Second

type assembled struct {
	text      string
	reasoning string
	refusal   string
	calls     map[int]*inference.ToolCall
	order     []int
	usage     *chatUsage
	finish    string
	revision  string
	losses    []inference.Loss
}

func (a *Adapter) assembleFinal(req inference.Request, model inference.Capabilities, s assembled) (inference.Response, error) {
	var parts []inference.Part
	if s.text != "" {
		parts = append(parts, inference.Part{Kind: inference.PartText, Text: s.text, Provenance: taint.Generated})
	}
	if s.reasoning != "" {
		parts = append(parts, inference.Part{
			Kind:       inference.PartReasoning,
			Reasoning:  &inference.Reasoning{Summary: s.reasoning},
			Provenance: taint.Generated,
		})
	}
	if s.refusal != "" {
		parts = append(parts, inference.Part{Kind: inference.PartRefusal, Refusal: s.refusal, Provenance: taint.Generated})
	}
	for _, idx := range s.order {
		call := s.calls[idx]
		if call.Name == "" {
			continue
		}
		if len(call.Input) == 0 {
			call.Input = json.RawMessage("{}")
		}
		parts = append(parts, inference.Part{
			Kind: inference.PartToolCall, ToolCall: call, Provenance: taint.Generated,
		})
	}
	if len(parts) == 0 {
		// A provider stream that closed without producing anything is a failure, not an empty
		// success: reporting it as success would let a truncated answer pass as a whole one
		// (gateway decision 30).
		return inference.Response{}, modberr.New(modberr.CodeProviderUnavailable,
			"stream ended without producing content")
	}

	revision := s.revision
	losses := s.losses
	if revision == "" {
		revision = model.Revision
		losses = append(losses, inference.Loss{
			Kind:    inference.LossUnsupported,
			Feature: "model_revision",
			Detail:  "provider did not report the serving model; the declared revision was recorded",
		})
	}

	finish := translateFinishReason(s.finish, nil)
	if len(s.order) > 0 && s.finish == "" {
		finish = inference.FinishToolUse
	}
	return inference.Response{
		IRVersion:     req.IRVersion,
		Alias:         req.Alias,
		ModelRevision: revision,
		Parts:         parts,
		FinishReason:  finish,
		Usage:         translateUsage(s.usage),
		Losses:        losses,
	}, nil
}

// CountTokens implements inference.Adapter.
//
// O9. The chat-completions protocol has no token-counting endpoint, so this is an estimate and says
// so. A budget decision made on an estimate must be able to declare that rather than presenting it
// as measured — the gateway rounds cost up for the same reason (MOD-A01 decision 7).
func (a *Adapter) CountTokens(_ context.Context, req inference.Request, _ inference.Capabilities) (inference.TokenCount, error) {
	characters := 0
	count := func(parts []inference.Part) {
		for _, p := range parts {
			characters += len(p.Text) + len(p.Refusal)
			if p.ToolCall != nil {
				characters += len(p.ToolCall.Name) + len(p.ToolCall.Input)
			}
			if p.ToolResult != nil {
				for _, rp := range p.ToolResult.Parts {
					characters += len(rp.Text)
				}
			}
		}
	}
	count(req.System)
	count(req.Developer)
	for _, m := range req.Messages {
		count(m.Parts)
	}
	for _, t := range req.Tools {
		characters += len(t.Name) + len(t.Description) + len(t.InputSchema)
	}
	// Four characters per token is the conventional English approximation. It is deliberately not
	// tuned per model: a more precise wrong number invites treating it as exact.
	return inference.TokenCount{Tokens: (characters + 3) / 4, Exact: false}, nil
}

// Health implements inference.Adapter.
func (a *Adapter) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/models", nil)
	if err != nil {
		return modberr.Wrap(err, modberr.CodeInternal, "health request could not be built")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return transportError(err)
	}
	defer resp.Body.Close()
	// The body is drained so the connection can be reused rather than torn down on every check.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 500 {
		return modberr.Newf(modberr.CodeProviderUnavailable, "provider health check returned %d", resp.StatusCode)
	}
	return nil
}

func (a *Adapter) checkCredential(cred inference.Credential) error {
	if cred.IsZero() {
		// INV-2: the credential is an explicit parameter precisely so this is checkable. An adapter
		// that fell back to an ambient value would make the boundary unobservable.
		return modberr.New(modberr.CodeUnauthenticated, "adapter requires a leased credential")
	}
	if cred.ProviderID != a.provider {
		return modberr.New(modberr.CodeUnauthenticated,
			"credential was leased for a different provider")
	}
	if cred.Expired(time.Now()) {
		return modberr.New(modberr.CodeLeaseExpired, "credential lease has expired")
	}
	return nil
}

func (a *Adapter) post(ctx context.Context, body chatRequest, cred inference.Credential, stream bool) (*http.Response, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInternal, "request could not be encoded")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/chat/completions", bytes.NewReader(encoded))
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInternal, "request could not be built")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// O2. The secret reaches this header and nothing else. It is never a query parameter, because a
	// URL is logged by proxies, servers, and Go's own error strings.
	httpReq.Header.Set("Authorization", "Bearer "+cred.Secret())
	if stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, transportError(err)
	}
	return resp, nil
}

// statusError maps an HTTP status onto a stable Modbit code.
//
// O3. The upstream body is read only to be discarded. A provider error body routinely echoes the
// request — including the prompt, and occasionally the credential that was rejected — so letting it
// into a Modbit error would move a secret from the wire into the audit log (R-ERR-02).
func statusError(resp *http.Response) error {
	if resp.StatusCode < 400 {
		return nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return modberr.New(modberr.CodeUnauthenticated, "provider rejected the credential")
	case resp.StatusCode == http.StatusNotFound:
		return modberr.New(modberr.CodeNoEligibleRoute, "provider does not serve the requested model")
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		return modberr.New(modberr.CodeInvalidArgument, "request exceeded the provider's size limit")
	case resp.StatusCode == http.StatusTooManyRequests:
		return modberr.New(modberr.CodeRateLimited, "provider rate limit reached")
	case resp.StatusCode >= 500:
		return modberr.Newf(modberr.CodeProviderUnavailable, "provider returned %d", resp.StatusCode)
	default:
		return modberr.Newf(modberr.CodeInvalidArgument, "provider rejected the request with %d", resp.StatusCode)
	}
}

// providerError maps a structured error payload. Only the provider's type and code cross over; the
// message does not, for the same reason statusError discards the body.
func providerError(status int, e *chatError) error {
	switch e.Type {
	case "invalid_request_error":
		return modberr.New(modberr.CodeInvalidArgument, "provider rejected the request")
	case "rate_limit_error":
		return modberr.New(modberr.CodeRateLimited, "provider rate limit reached")
	case "authentication_error", "permission_error":
		return modberr.New(modberr.CodeUnauthenticated, "provider rejected the credential")
	default:
		if status >= 500 || status == 0 {
			return modberr.New(modberr.CodeProviderUnavailable, "provider reported an error")
		}
		return modberr.New(modberr.CodeInvalidArgument, "provider reported a request error")
	}
}

// transportError classifies a failure that happened before a response existed.
//
// A context cancellation must stay cancellation rather than becoming a provider fault: the gateway
// fails over on retryable classes, and retrying a call the caller cancelled would spend budget
// reproducing a result nobody wants. An egress refusal is likewise not retryable — the next attempt
// reaches the same blocked destination.
func transportError(err error) error {
	switch {
	case modberr.Is(err, modberr.CodePolicyDenied):
		return err
	case errors.Is(err, context.Canceled):
		return modberr.Wrap(err, modberr.CodeCancelled, "request cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		return modberr.Wrap(err, modberr.CodeTimeout, "request timed out")
	default:
		// The egress guard rejects a disallowed destination inside RoundTrip, and net/http wraps
		// that in a *url.Error. Unwrapping keeps a policy denial from being reported as an outage
		// and retried against the same blocked host.
		if policy, ok := modberr.As(err); ok {
			return policy
		}
		return modberr.Wrap(err, modberr.CodeProviderUnavailable, "provider could not be reached")
	}
}
