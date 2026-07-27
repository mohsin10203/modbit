// Package fake provides a scriptable in-memory inference Adapter.
//
// Boundary: a test double for the model layer. It performs no I/O, holds no credentials, and is
// never linked into a shipped binary path.
//
// It exists for two jobs:
//
//  1. Give the Model Gateway, orchestrator, and agent-runtime tests a deterministic model to run
//     against without a provider.
//  2. Give the shared adapter conformance suite something to prove itself on. A conformance suite
//     that has never been shown to fail a broken adapter is decoration, so this adapter can be
//     configured to violate each contract property on demand through Faults.
package fake

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Faults selectively breaks contract properties so the conformance suite can be shown to detect
// each one. The zero value is a fully conformant adapter.
type Faults struct {
	// OmitRevision returns a response with no model revision, defeating drift detection (MOD-6).
	OmitRevision bool
	// NegativeUsage returns impossible token counts.
	NegativeUsage bool
	// UnclosedStream leaves the stream channel open after the terminal event.
	UnclosedStream bool
	// IgnoreCancellation keeps streaming after the context is cancelled.
	IgnoreCancellation bool
	// SuppressLosses returns no Loss even where the model cannot honour the request (ADP-3).
	SuppressLosses bool
	// LaunderProvenance labels model output as user_trusted.
	LaunderProvenance bool
	// UnstableErrorCode returns an error with no Modbit code (R-ERR-01).
	UnstableErrorCode bool
	// OmitFinalResponse ends a stream without the assembled response.
	OmitFinalResponse bool
	// DivergentStreamText makes the assembled response disagree with the emitted deltas.
	DivergentStreamText bool
	// MisreportToolUse returns FinishToolUse with no tool call part.
	MisreportToolUse bool
	// RejectMedia refuses media parts even where the model record declares support, so the
	// capability record and the adapter disagree.
	RejectMedia bool
	// FailWith, when set, makes Complete and Stream return this error.
	FailWith error
}

// Adapter is an in-memory inference.Adapter.
//
// It is safe for concurrent use: call bookkeeping is mutex guarded, and the configuration fields
// are read-only after construction.
type Adapter struct {
	// ProviderID is the stable provider identifier.
	ProviderID string
	// Models are the capability records this adapter serves.
	Models []inference.Capabilities
	// Reply is the assistant text returned for every completion.
	Reply string
	// ToolCalls are emitted as tool-call parts when the request declares matching tools. Two or
	// more exercises the parallel tool-call path.
	ToolCalls []inference.ToolCall
	// ReportRevision overrides the revision reported on the response, modelling a provider that
	// rolled a model forward under the same identifier.
	ReportRevision string
	// Latency delays each streamed delta, giving cancellation tests something to interrupt.
	Latency time.Duration
	// StreamBuffer sizes the stream channel. A buffered channel models a provider whose response
	// was already fully received, so the adapter emits every delta without ever blocking — and a
	// cancellation arriving afterwards has nothing left to interrupt.
	StreamBuffer int
	// Faults breaks specific contract properties.
	Faults Faults

	requireCredential bool

	mu          sync.Mutex
	calls       int
	lastRequest *inference.Request
}

var _ inference.Adapter = (*Adapter)(nil)

// New returns a conformant adapter serving model.
func New(model inference.Capabilities) *Adapter {
	return &Adapter{
		ProviderID: model.ProviderID,
		Models:     []inference.Capabilities{model},
		Reply:      "acknowledged",
	}
}

// Provider returns the provider identifier.
func (a *Adapter) Provider() string { return a.ProviderID }

// RequireCredential makes the adapter refuse calls with no credential, so a gateway that forgets to
// lease one fails loudly instead of silently working against a fake.
func (a *Adapter) RequireCredential() *Adapter {
	a.requireCredential = true
	return a
}

// checkCredential rejects a credential minted for a different provider. An adapter accepting one
// would let a misrouted call authenticate with another provider's material.
func (a *Adapter) checkCredential(cred inference.Credential) error {
	if cred.IsZero() {
		if a.requireCredential {
			return modberr.New(modberr.CodeUnauthenticated, "no provider credential was supplied").
				WithDetail("scheme", "provider_credential")
		}
		return nil
	}
	if cred.ProviderID != a.ProviderID {
		return modberr.New(modberr.CodeUnauthenticated,
			"credential was minted for a different provider").WithDetail("scheme", "provider_credential")
	}
	return nil
}

// Capabilities returns the configured capability records.
func (a *Adapter) Capabilities(ctx context.Context) ([]inference.Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return nil, modberr.Wrap(err, modberr.CodeCancelled, "capability lookup cancelled")
	}
	out := make([]inference.Capabilities, len(a.Models))
	copy(out, a.Models)
	return out, nil
}

// Calls returns how many completions have been requested.
func (a *Adapter) Calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// LastRequest returns the request the adapter most recently received, or nil.
//
// This is what lets a caller assert on the payload that actually reached the provider boundary
// rather than the one it handed to the gateway — the difference is the entire point of a redaction
// step.
func (a *Adapter) LastRequest() *inference.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastRequest
}

// Health always reports healthy.
func (a *Adapter) Health(ctx context.Context) error { return ctx.Err() }

// CountTokens returns a whitespace-based estimate, flagged as an estimate rather than presented as
// a provider-authoritative count.
func (a *Adapter) CountTokens(ctx context.Context, req inference.Request, _ inference.Capabilities) (inference.TokenCount, error) {
	if err := ctx.Err(); err != nil {
		return inference.TokenCount{}, modberr.Wrap(err, modberr.CodeCancelled, "token count cancelled")
	}
	return inference.TokenCount{Tokens: estimateTokens(req), Exact: false}, nil
}

// Complete returns a non-streaming completion.
func (a *Adapter) Complete(ctx context.Context, req inference.Request, model inference.Capabilities, cred inference.Credential) (inference.Response, error) {
	a.mu.Lock()
	a.calls++
	received := req
	a.lastRequest = &received
	a.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return inference.Response{}, modberr.Wrap(err, modberr.CodeCancelled, "completion cancelled")
	}
	if a.Faults.FailWith != nil {
		return inference.Response{}, a.Faults.FailWith
	}
	if a.Faults.UnstableErrorCode {
		return inference.Response{}, fmt.Errorf("upstream said no")
	}
	if err := a.checkCredential(cred); err != nil {
		return inference.Response{}, err
	}
	if err := req.Validate(); err != nil {
		return inference.Response{}, err
	}
	if a.Faults.RejectMedia && requestHasMedia(req) {
		return inference.Response{}, modberr.New(modberr.CodeNoEligibleRoute,
			"adapter refuses media parts").WithDetail("required_capabilities", "media")
	}

	losses, err := model.Check(req)
	if err != nil {
		return inference.Response{}, err
	}
	if a.Faults.SuppressLosses {
		losses = nil
	}
	return a.buildResponse(req, model, losses, a.Reply), nil
}

func (a *Adapter) buildResponse(req inference.Request, model inference.Capabilities, losses []inference.Loss, text string) inference.Response {
	provenance := taint.Generated
	if a.Faults.LaunderProvenance {
		provenance = taint.UserTrusted
	}

	parts := []inference.Part{{Kind: inference.PartText, Text: text, Provenance: provenance}}
	finish := inference.FinishEndTurn

	if calls := a.applicableToolCalls(req); len(calls) > 0 {
		for i := range calls {
			call := calls[i]
			parts = append(parts, inference.Part{
				Kind: inference.PartToolCall, ToolCall: &call, Provenance: provenance,
			})
		}
		finish = inference.FinishToolUse
	}
	if a.Faults.MisreportToolUse {
		finish = inference.FinishToolUse
		parts = parts[:1]
	}

	usage := inference.Usage{InputTokens: estimateTokens(req), OutputTokens: len(strings.Fields(text))}
	if model.SupportsPromptCache && requestUsesCache(req) {
		// Attribute half the input to the cache so the accounting path is exercised.
		usage.CachedInputTokens = usage.InputTokens / 2
		usage.InputTokens -= usage.CachedInputTokens
	}
	if a.Faults.NegativeUsage {
		usage.OutputTokens = -1
	}

	revision := model.Revision
	if a.ReportRevision != "" {
		revision = a.ReportRevision
	}
	if a.Faults.OmitRevision {
		revision = ""
	}
	return inference.Response{
		IRVersion:     inference.Version,
		Alias:         req.Alias,
		ModelRevision: revision,
		Parts:         parts,
		FinishReason:  finish,
		Usage:         usage,
		Losses:        losses,
	}
}

// applicableToolCalls returns the configured tool calls whose names the request actually declared.
// Emitting a call for an undeclared tool would produce a response the harness must reject, which is
// a different failure from the one a caller configuring ToolCalls is trying to exercise.
func (a *Adapter) applicableToolCalls(req inference.Request) []inference.ToolCall {
	declared := make(map[string]struct{}, len(req.Tools))
	for _, t := range req.Tools {
		declared[t.Name] = struct{}{}
	}
	var out []inference.ToolCall
	for _, c := range a.ToolCalls {
		if _, ok := declared[c.Name]; ok {
			out = append(out, c)
		}
	}
	return out
}

// Stream returns a normalized streaming completion.
func (a *Adapter) Stream(ctx context.Context, req inference.Request, model inference.Capabilities, cred inference.Credential) (<-chan inference.StreamEvent, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, modberr.Wrap(err, modberr.CodeCancelled, "stream cancelled")
	}
	if a.Faults.FailWith != nil {
		return nil, a.Faults.FailWith
	}
	if err := a.checkCredential(cred); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if !model.SupportsStreaming {
		return nil, modberr.New(modberr.CodeNoEligibleRoute, "model does not support streaming").
			WithDetail("required_capabilities", "streaming")
	}

	losses, err := model.Check(req)
	if err != nil {
		return nil, err
	}
	if a.Faults.SuppressLosses {
		losses = nil
	}

	events := make(chan inference.StreamEvent, a.StreamBuffer)
	go a.emit(ctx, req, model, losses, events)
	return events, nil
}

// emit produces the stream. It owns the channel and closes it on every exit path unless the
// UnclosedStream fault is set, which is the condition the conformance suite must detect (R-GO-03).
func (a *Adapter) emit(ctx context.Context, req inference.Request, model inference.Capabilities, losses []inference.Loss, events chan<- inference.StreamEvent) {
	if !a.Faults.UnclosedStream {
		defer close(events)
	}

	send := func(e inference.StreamEvent) bool {
		if !a.Faults.IgnoreCancellation {
			select {
			case <-ctx.Done():
				return false
			default:
			}
		}
		select {
		case events <- e:
			return true
		case <-ctx.Done():
			return a.Faults.IgnoreCancellation
		}
	}

	if !send(inference.StreamEvent{Kind: inference.StreamMessageStart}) {
		return
	}

	emitted := make([]string, 0, 8)
	for _, word := range strings.Fields(a.Reply) {
		if a.Latency > 0 {
			if a.Faults.IgnoreCancellation {
				// Genuinely ignore the context: sleeping through it is what a provider client that
				// forgets to propagate cancellation actually does.
				time.Sleep(a.Latency)
			} else {
				select {
				case <-time.After(a.Latency):
				case <-ctx.Done():
					return
				}
			}
		}
		chunk := word + " "
		if !send(inference.StreamEvent{Kind: inference.StreamTextDelta, Text: chunk}) {
			return
		}
		emitted = append(emitted, chunk)
	}

	for i, call := range a.applicableToolCalls(req) {
		if !send(inference.StreamEvent{
			Kind: inference.StreamToolCallDelta, Index: i + 1,
			ToolCallID: call.ID, ToolName: call.Name, InputDelta: string(call.Input),
		}) {
			return
		}
	}

	text := strings.TrimSpace(strings.Join(emitted, ""))
	if a.Faults.DivergentStreamText {
		text = "something entirely different"
	}
	final := a.buildResponse(req, model, losses, text)

	stop := inference.StreamEvent{Kind: inference.StreamMessageStop, Final: &final}
	if a.Faults.OmitFinalResponse {
		stop.Final = nil
	}
	send(stop)
}

func requestHasMedia(req inference.Request) bool {
	for _, m := range req.Messages {
		for _, p := range m.Parts {
			switch p.Kind {
			case inference.PartImage, inference.PartAudio, inference.PartFile:
				return true
			}
		}
	}
	return false
}

func requestUsesCache(req inference.Request) bool {
	for _, m := range req.Messages {
		for _, p := range m.Parts {
			if p.CacheHint != inference.CacheNone {
				return true
			}
		}
	}
	return false
}

// estimateTokens is a deliberately crude whitespace count. It exists so usage accounting is
// non-zero and proportional, not to be accurate.
func estimateTokens(req inference.Request) int {
	total := 0
	count := func(parts []inference.Part) {
		for _, p := range parts {
			switch p.Kind {
			case inference.PartText:
				total += len(strings.Fields(p.Text))
			case inference.PartToolCall:
				if p.ToolCall != nil {
					total += len(p.ToolCall.Input) / 4
				}
			case inference.PartToolResult:
				if p.ToolResult != nil {
					for _, nested := range p.ToolResult.Parts {
						total += len(strings.Fields(nested.Text))
					}
				}
			default:
				total += 16 // flat cost for a media reference
			}
		}
	}
	count(req.System)
	count(req.Developer)
	for _, m := range req.Messages {
		count(m.Parts)
	}
	for _, t := range req.Tools {
		total += len(t.Name)/4 + len(t.InputSchema)/4
	}
	if total == 0 {
		total = 1
	}
	return total
}

// ToolCall is a helper for building a tool call in tests.
func ToolCall(id, name string, input map[string]any) inference.ToolCall {
	raw, err := json.Marshal(input)
	if err != nil {
		raw = []byte(`{}`)
	}
	return inference.ToolCall{ID: id, Name: name, Input: raw}
}
