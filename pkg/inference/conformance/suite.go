// Package conformance implements the shared adapter conformance suite.
//
// Boundary: it exercises an inference.Adapter against the contract in PRD v5.1 §14.1.1 and returns
// a structured report. It does not decide release readiness policy, does not talk to a registry,
// and knows nothing about any specific provider.
//
// Requirements: ADP-5 (the suite must cover request translation, parallel and serial tool calls,
// schema validation, structured output, streaming, cancellation, retry classification, errors,
// usage accounting, prompt caching, model revision capture, and content-type support) and ADP-6
// (an adapter cannot be marked production ready until the shared suite passes).
//
// # What this suite does and does not assert
//
// It verifies the *adapter's* conformance to the canonical contract, never the model's behaviour.
// An adapter cannot make a provider return two tool calls on demand, so a case that needs a
// specific model behaviour asserts conditionally: "if the response contains tool calls, they are
// well formed and correlate", not "the model returned tool calls". Making it otherwise would
// produce a suite that fails for reasons the adapter author cannot fix, which is how conformance
// gates get disabled.
//
// # Why Inconclusive exists
//
// A case whose path the provider did not exercise is Inconclusive, not Pass. The Modbit agent rules
// require a failed runtime validation to be inconclusive unless evidence proves mitigation, and the
// same honesty applies here: an untested path on a declared capability must not be reported as
// verified. ProductionReady therefore refuses both failures and inconclusive results on declared
// capabilities, while Skipped — the capability is not declared at all — is fine.
package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// SuiteVersion is recorded in every report. A qualification run is only comparable against runs of
// the same suite version.
const SuiteVersion = 1

// Options tune the suite's timing. A live provider needs far longer than an in-memory adapter, so
// the timeouts are explicit rather than hardcoded to either one.
type Options struct {
	// StreamTimeout bounds how long a stream may take to close its channel.
	StreamTimeout time.Duration
	// CancelTimeout bounds how long a stream may keep producing after its context is cancelled.
	CancelTimeout time.Duration
}

// DefaultOptions are sized for a live hosted provider.
func DefaultOptions() Options {
	return Options{StreamTimeout: 30 * time.Second, CancelTimeout: 10 * time.Second}
}

func (o Options) withDefaults() Options {
	d := DefaultOptions()
	if o.StreamTimeout <= 0 {
		o.StreamTimeout = d.StreamTimeout
	}
	if o.CancelTimeout <= 0 {
		o.CancelTimeout = d.CancelTimeout
	}
	return o
}

// Status is the outcome of one conformance case.
type Status string

const (
	// StatusPass means the case ran and the contract held.
	StatusPass Status = "pass"
	// StatusFail means the contract was violated. Any failure blocks production readiness.
	StatusFail Status = "fail"
	// StatusSkipped means the model does not declare the capability, so the case does not apply.
	StatusSkipped Status = "skipped"
	// StatusInconclusive means the capability is declared but the provider did not exercise the
	// path during this run. It is not a pass.
	StatusInconclusive Status = "inconclusive"
)

// Result is one conformance case outcome.
type Result struct {
	// Case is the stable case identifier, used to diff runs.
	Case string `json:"case"`
	// Requirement is the PRD requirement the case covers.
	Requirement string `json:"requirement"`
	Status      Status `json:"status"`
	// Detail explains a non-pass. It never contains prompt or completion content.
	Detail string `json:"detail,omitempty"`
}

// Report is the outcome of a full suite run. It is the evidence artifact behind ADP-6.
type Report struct {
	SuiteVersion int       `json:"suite_version"`
	Provider     string    `json:"provider"`
	ModelID      string    `json:"model_id"`
	Revision     string    `json:"revision"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	Results      []Result  `json:"results"`
}

// Failures returns every failing case.
func (r Report) Failures() []Result { return r.filter(StatusFail) }

// Inconclusive returns every case whose path was not exercised.
func (r Report) Inconclusive() []Result { return r.filter(StatusInconclusive) }

func (r Report) filter(s Status) []Result {
	var out []Result
	for _, res := range r.Results {
		if res.Status == s {
			out = append(out, res)
		}
	}
	return out
}

// ProductionReady implements ADP-6.
//
// It requires zero failures and zero inconclusive results: a declared capability whose path was
// never exercised has not been shown to work, and shipping it as verified is exactly the
// "success based solely on assertion" the platform prohibits.
func (r Report) ProductionReady() bool {
	return len(r.Failures()) == 0 && len(r.Inconclusive()) == 0
}

// Summary renders a one-line count per status, for CI output.
func (r Report) Summary() string {
	counts := map[Status]int{}
	for _, res := range r.Results {
		counts[res.Status]++
	}
	return fmt.Sprintf("%s/%s@%s: %d pass, %d fail, %d inconclusive, %d skipped",
		r.Provider, r.ModelID, r.Revision,
		counts[StatusPass], counts[StatusFail], counts[StatusInconclusive], counts[StatusSkipped])
}

// runner accumulates results for one suite run.
type runner struct {
	adapter inference.Adapter
	model   inference.Capabilities
	opts    Options
	cred    inference.Credential
	results []Result
}

func (r *runner) record(name, requirement string, status Status, detail string) {
	r.results = append(r.results, Result{Case: name, Requirement: requirement, Status: status, Detail: detail})
}

func (r *runner) pass(name, requirement string)      { r.record(name, requirement, StatusPass, "") }
func (r *runner) skip(name, requirement, why string) { r.record(name, requirement, StatusSkipped, why) }
func (r *runner) fail(name, requirement, why string) { r.record(name, requirement, StatusFail, why) }
func (r *runner) unproven(name, requirement, why string) {
	r.record(name, requirement, StatusInconclusive, why)
}

// Run executes the suite against adapter for model.
//
// It never panics on adapter misbehaviour: a conformance suite that crashes on a broken adapter
// cannot report what was broken.
func Run(ctx context.Context, adapter inference.Adapter, model inference.Capabilities) Report {
	return RunWithOptions(ctx, adapter, model, DefaultOptions())
}

// RunWithOptions is Run with explicit timing.
func RunWithOptions(ctx context.Context, adapter inference.Adapter, model inference.Capabilities, opts Options) Report {
	// A conformance credential is minted for the adapter's own provider and expires with the run,
	// so an adapter that validates its credential is exercised rather than silently skipped.
	cred := inference.NewCredential(adapter.Provider(), "lease_conformance",
		"conformance-suite-placeholder", time.Now().Add(time.Hour))
	r := &runner{adapter: adapter, model: model, opts: opts.withDefaults(), cred: cred}
	started := time.Now().UTC()

	r.checkCapabilityRecord()
	r.checkProviderIdentity(ctx)
	r.checkRequestTranslation(ctx)
	r.checkModelRevisionCapture(ctx)
	r.checkUsageAccounting(ctx)
	r.checkSerialToolCalls(ctx)
	r.checkParallelToolCalls(ctx)
	r.checkSchemaValidation(ctx)
	r.checkStructuredOutput(ctx)
	r.checkContentTypes(ctx)
	r.checkPromptCaching(ctx)
	r.checkLossDeclaration(ctx)
	r.checkStreaming(ctx)
	r.checkCancellation(ctx)
	r.checkErrorClassification(ctx)
	r.checkTokenCounting(ctx)
	r.checkCredentialIsolation(ctx)

	return Report{
		SuiteVersion: SuiteVersion,
		Provider:     adapter.Provider(),
		ModelID:      model.ModelID,
		Revision:     model.Revision,
		StartedAt:    started,
		CompletedAt:  time.Now().UTC(),
		Results:      r.results,
	}
}

// request builds a minimal valid request for the model under test.
func (r *runner) request() inference.Request {
	return inference.Request{
		IRVersion: inference.Version,
		Alias:     r.model.Aliases[0],
		Messages: []inference.Message{{
			Role: inference.RoleUser,
			Parts: []inference.Part{{
				Kind: inference.PartText, Text: "conformance probe", Provenance: taint.UserTrusted,
			}},
		}},
		RunID:  id.MustNew(id.Run),
		StepID: id.MustNew(id.RunStep),
	}
}

func (r *runner) checkCapabilityRecord() {
	const name, req = "capability_record", "ADP-4"
	if err := r.model.Validate(); err != nil {
		r.fail(name, req, "capability record is not self-consistent: "+message(err))
		return
	}
	if len(r.model.Aliases) == 0 {
		r.fail(name, req, "model declares no capability alias, so it cannot be routed to")
		return
	}
	r.pass(name, req)
}

func (r *runner) checkProviderIdentity(ctx context.Context) {
	const name, req = "provider_identity", "ADP-1"
	if r.adapter.Provider() == "" {
		r.fail(name, req, "adapter reports an empty provider identifier")
		return
	}
	if r.adapter.Provider() != r.model.ProviderID {
		r.fail(name, req, fmt.Sprintf("adapter provider %q does not match the model record %q",
			r.adapter.Provider(), r.model.ProviderID))
		return
	}
	caps, err := r.adapter.Capabilities(ctx)
	if err != nil {
		r.fail(name, req, "Capabilities returned an error: "+message(err))
		return
	}
	for _, c := range caps {
		if c.ProviderID != r.adapter.Provider() {
			r.fail(name, req, fmt.Sprintf("advertised model %q names provider %q", c.ModelID, c.ProviderID))
			return
		}
	}
	r.pass(name, req)
}

func (r *runner) checkRequestTranslation(ctx context.Context) {
	const name, req = "request_translation", "ADP-5.request_translation"
	resp, err := r.adapter.Complete(ctx, r.request(), r.model, r.cred)
	if err != nil {
		r.fail(name, req, "a minimal valid request was rejected: "+message(err))
		return
	}
	if err := resp.Validate(); err != nil {
		r.fail(name, req, "response is not a valid canonical response: "+message(err))
		return
	}
	if resp.Alias != r.model.Aliases[0] {
		r.fail(name, req, "response does not echo the requested capability alias")
		return
	}
	r.pass(name, req)
}

func (r *runner) checkModelRevisionCapture(ctx context.Context) {
	const name, req = "model_revision_capture", "ADP-5.model_revision"
	resp, err := r.adapter.Complete(ctx, r.request(), r.model, r.cred)
	if err != nil {
		r.fail(name, req, "completion failed: "+message(err))
		return
	}
	switch {
	case resp.ModelRevision == "":
		// Without a captured revision, MOD-6 silent-model-change detection and OEV-1 canary
		// gating have nothing to compare against.
		r.fail(name, req, "response records no provider model revision")
	case resp.ModelRevision != r.model.Revision:
		r.fail(name, req, "response revision does not match the capability record")
	default:
		r.pass(name, req)
	}
}

func (r *runner) checkUsageAccounting(ctx context.Context) {
	const name, req = "usage_accounting", "ADP-5.usage_accounting"
	resp, err := r.adapter.Complete(ctx, r.request(), r.model, r.cred)
	if err != nil {
		r.fail(name, req, "completion failed: "+message(err))
		return
	}
	u := resp.Usage
	switch {
	case u.InputTokens < 0 || u.OutputTokens < 0 || u.CachedInputTokens < 0 || u.ReasoningTokens < 0:
		r.fail(name, req, "usage contains a negative token count")
	case u.Total() == 0:
		// Zero usage makes cost-per-verified-task (OBR-1) and budget enforcement meaningless.
		r.fail(name, req, "usage reports zero tokens for a non-empty request")
	default:
		r.pass(name, req)
	}
}

func (r *runner) checkSerialToolCalls(ctx context.Context) {
	const name, req = "tool_calls_serial", "ADP-5.tool_calls"
	if !r.model.SupportsTools {
		r.skip(name, req, "model does not declare tool support")
		return
	}
	request := r.request()
	request.Tools = []inference.ToolDefinition{{
		Name: "conformance_probe", Description: "returns a fixed value",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
	}}
	resp, err := r.adapter.Complete(ctx, request, r.model, r.cred)
	if err != nil {
		r.fail(name, req, "a request declaring one tool was rejected: "+message(err))
		return
	}
	if err := resp.Validate(); err != nil {
		r.fail(name, req, "response is not valid: "+message(err))
		return
	}
	calls := resp.ToolCalls()
	if len(calls) == 0 {
		// The adapter cannot force the model to call a tool, so this is unproven rather than failed.
		r.unproven(name, req, "the model did not call a tool during this run; the path is untested")
		return
	}
	for _, c := range calls {
		if c.ID == "" {
			r.fail(name, req, "tool call has no correlation id, so its result cannot be matched")
			return
		}
		if c.Name != "conformance_probe" {
			r.fail(name, req, "model called a tool that was not declared in the request")
			return
		}
		if !json.Valid(c.Input) {
			r.fail(name, req, "tool call input is not valid JSON")
			return
		}
	}
	if resp.FinishReason != inference.FinishToolUse {
		r.fail(name, req, "response contains tool calls but the finish reason is not tool_use")
		return
	}
	r.pass(name, req)
}

func (r *runner) checkParallelToolCalls(ctx context.Context) {
	const name, req = "tool_calls_parallel", "ADP-5.parallel_tool_calls"
	if !r.model.SupportsTools || !r.model.SupportsParallelToolCall {
		r.skip(name, req, "model does not declare parallel tool-call support")
		return
	}
	request := r.request()
	request.Tools = []inference.ToolDefinition{
		{Name: "probe_a", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "probe_b", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
	resp, err := r.adapter.Complete(ctx, request, r.model, r.cred)
	if err != nil {
		r.fail(name, req, "a request declaring two tools was rejected: "+message(err))
		return
	}
	calls := resp.ToolCalls()
	if len(calls) < 2 {
		r.unproven(name, req, "the model issued fewer than two tool calls; the parallel path is untested")
		return
	}
	seen := make(map[string]struct{}, len(calls))
	for _, c := range calls {
		if _, dup := seen[c.ID]; dup {
			// Duplicate ids make results unmatchable, which silently pairs a result with the wrong call.
			r.fail(name, req, "parallel tool calls share a correlation id")
			return
		}
		seen[c.ID] = struct{}{}
	}
	r.pass(name, req)
}

func (r *runner) checkSchemaValidation(ctx context.Context) {
	const name, req = "schema_validation", "ADP-5.schema_validation"
	if !r.model.SupportsTools {
		r.skip(name, req, "model does not declare tool support")
		return
	}
	if r.model.ToolSchemaDialect == "" {
		r.fail(name, req, "a tool-capable model must declare its tool-schema dialect")
		return
	}
	// A malformed tool schema must be refused, not forwarded. Forwarding it makes the provider the
	// validator, and providers disagree about what they reject.
	request := r.request()
	request.Tools = []inference.ToolDefinition{{Name: "broken", InputSchema: json.RawMessage(`{"type":`)}}
	if _, err := r.adapter.Complete(ctx, request, r.model, r.cred); err == nil {
		r.fail(name, req, "adapter accepted a tool definition with a malformed input schema")
		return
	}
	r.pass(name, req)
}

func (r *runner) checkStructuredOutput(ctx context.Context) {
	const name, req = "structured_output", "ADP-5.structured_output"
	if !r.model.SupportsStructuredOutput {
		r.skip(name, req, "model does not declare structured-output support")
		return
	}
	request := r.request()
	request.StructuredOutput = &inference.StructuredOutput{
		SchemaID: "modbit.conformance.probe", Version: 1,
		Schema: json.RawMessage(`{"type":"object","properties":{"ok":{"type":"boolean"}}}`),
		Strict: true,
	}
	resp, err := r.adapter.Complete(ctx, request, r.model, r.cred)
	if err != nil {
		r.fail(name, req, "a structured-output request was rejected: "+message(err))
		return
	}
	if !r.model.SupportsStrictSchema && !declaresLoss(resp, "structured_output.strict") {
		// ADP-3: a downgrade the caller cannot see is indistinguishable from a guarantee.
		r.fail(name, req, "strict schema was requested on a best-effort model without a declared loss")
		return
	}
	r.pass(name, req)
}

func (r *runner) checkContentTypes(ctx context.Context) {
	const name, req = "content_types", "ADP-5.content_types"
	probe := func(kind inference.PartKind, mediaType string, supported bool) (ok bool, detail string) {
		request := r.request()
		request.Messages[0].Parts = append(request.Messages[0].Parts, inference.Part{
			Kind: kind,
			Media: &inference.MediaRef{
				ObjectRef: id.MustNew(id.ObjectRef), MediaType: mediaType,
				Digest: "sha256:" + strings.Repeat("0", 64), Bytes: 128,
			},
			Provenance: taint.UserTrusted,
		})
		_, err := r.adapter.Complete(ctx, request, r.model, r.cred)
		if supported {
			if err != nil {
				return false, fmt.Sprintf("declared %s support but rejected a %s part: %s", kind, kind, message(err))
			}
			return true, ""
		}
		if err == nil {
			// Accepting content the model cannot read produces a confident answer to a question the
			// model never saw.
			return false, fmt.Sprintf("accepted a %s part although the model does not declare support", kind)
		}
		return true, ""
	}

	for _, c := range []struct {
		kind      inference.PartKind
		mediaType string
		supported bool
	}{
		{inference.PartImage, "image/png", r.model.SupportsVision},
		{inference.PartAudio, "audio/wav", r.model.SupportsAudio},
		{inference.PartFile, "application/pdf", r.model.SupportsFiles},
	} {
		if ok, detail := probe(c.kind, c.mediaType, c.supported); !ok {
			r.fail(name, req, detail)
			return
		}
	}
	r.pass(name, req)
}

func (r *runner) checkPromptCaching(ctx context.Context) {
	const name, req = "prompt_caching", "ADP-5.prompt_caching"
	if !r.model.SupportsPromptCache {
		r.skip(name, req, "model does not declare prompt-cache support")
		return
	}
	if r.model.PromptCacheTTL <= 0 {
		r.fail(name, req, "cache-capable model declares no cache TTL")
		return
	}
	request := r.request()
	request.Messages[0].Parts[0].CacheHint = inference.CacheEphemeral
	resp, err := r.adapter.Complete(ctx, request, r.model, r.cred)
	if err != nil {
		r.fail(name, req, "a request carrying a cache hint was rejected: "+message(err))
		return
	}
	if resp.Usage.CachedInputTokens == 0 {
		// A cold cache is normal, so this is unproven rather than a failure.
		r.unproven(name, req, "no cached input tokens were reported; the cache path is untested")
		return
	}
	r.pass(name, req)
}

func (r *runner) checkLossDeclaration(ctx context.Context) {
	const name, req = "loss_declaration", "ADP-3"
	// Ask for a reasoning effort the model does not expose. The adapter must either declare the
	// loss or refuse; silently ignoring it is the violation.
	unsupported := inference.ReasoningHigh
	for _, e := range []inference.ReasoningEffort{inference.ReasoningHigh, inference.ReasoningMedium, inference.ReasoningLow} {
		if !r.model.SupportsReasoning(e) {
			unsupported = e
			break
		}
	}
	if r.model.SupportsReasoning(unsupported) {
		r.skip(name, req, "model exposes every reasoning effort, so there is no gap to declare")
		return
	}
	request := r.request()
	request.Reasoning = unsupported
	resp, err := r.adapter.Complete(ctx, request, r.model, r.cred)
	if err != nil {
		r.pass(name, req) // refusing is an acceptable, non-silent response
		return
	}
	if !declaresLoss(resp, "reasoning") {
		r.fail(name, req, "an unsupported reasoning effort was silently ignored with no declared loss")
		return
	}
	r.pass(name, req)
}

func (r *runner) checkStreaming(ctx context.Context) {
	const name, req = "streaming", "ADP-5.streaming"
	if !r.model.SupportsStreaming {
		r.skip(name, req, "model does not declare streaming support")
		return
	}

	streamCtx, cancel := context.WithTimeout(ctx, r.opts.StreamTimeout)
	defer cancel()

	events, err := r.adapter.Stream(streamCtx, r.request(), r.model, r.cred)
	if err != nil {
		r.fail(name, req, "Stream returned an error: "+message(err))
		return
	}

	var (
		sawStart, sawStop, closed bool
		accumulated               strings.Builder
		final                     *inference.Response
	)
	timeout := time.After(r.opts.StreamTimeout)
collect:
	for {
		select {
		case e, open := <-events:
			if !open {
				closed = true
				break collect
			}
			switch e.Kind {
			case inference.StreamMessageStart:
				sawStart = true
			case inference.StreamTextDelta:
				accumulated.WriteString(e.Text)
			case inference.StreamMessageStop:
				sawStop = true
				final = e.Final
			case inference.StreamError:
				r.fail(name, req, "stream reported an error: "+message(e.Err))
				return
			}
		case <-timeout:
			// An unclosed channel leaks the consuming goroutine for the life of the process.
			r.fail(name, req, "stream did not close its channel within the timeout")
			return
		}
	}

	switch {
	case !sawStart:
		r.fail(name, req, "stream emitted no message_start event")
	case !sawStop:
		r.fail(name, req, "stream emitted no message_stop event")
	case !closed:
		r.fail(name, req, "stream channel was not closed after the terminal event")
	case final == nil:
		r.fail(name, req, "message_stop carried no assembled response")
	default:
		if err := final.Validate(); err != nil {
			r.fail(name, req, "assembled response is not valid: "+message(err))
			return
		}
		if strings.TrimSpace(accumulated.String()) != strings.TrimSpace(final.Text()) {
			// A divergence means a client rendering deltas shows something different from what was
			// recorded as evidence.
			r.fail(name, req, "assembled response text does not match the emitted deltas")
			return
		}
		r.pass(name, req)
	}
}

func (r *runner) checkCancellation(ctx context.Context) {
	const name, req = "cancellation", "ADP-5.cancellation"
	if !r.model.SupportsCancellation {
		r.skip(name, req, "model does not declare cancellation support")
		return
	}
	if !r.model.SupportsStreaming {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := r.adapter.Complete(cancelled, r.request(), r.model, r.cred); err == nil {
			r.fail(name, req, "Complete ignored a cancelled context")
			return
		}
		r.pass(name, req)
		return
	}

	streamCtx, cancel := context.WithCancel(ctx)
	events, err := r.adapter.Stream(streamCtx, r.request(), r.model, r.cred)
	if err != nil {
		cancel()
		r.fail(name, req, "Stream returned an error: "+message(err))
		return
	}
	// Cancel after the first event so cancellation lands mid-stream rather than before it starts.
	select {
	case <-events:
	case <-time.After(r.opts.CancelTimeout):
		cancel()
		r.fail(name, req, "stream produced no event within the timeout")
		return
	}
	cancel()

	// completedNormally records whether the stream reached its terminal event anyway. A stream that
	// finished before cancellation could take effect proves nothing about cancellation — reporting
	// it as a pass would let a fast adapter that ignores cancellation ship as verified. It is
	// inconclusive instead, which still blocks production readiness.
	completedNormally := false
	deadline := time.After(r.opts.CancelTimeout)
	for {
		select {
		case e, open := <-events:
			if !open {
				if completedNormally {
					r.unproven(name, req,
						"the stream completed before cancellation could take effect; the path is untested")
					return
				}
				r.pass(name, req)
				return
			}
			if e.Kind == inference.StreamMessageStop {
				completedNormally = true
			}
		case <-deadline:
			r.fail(name, req, "stream kept producing after cancellation and did not stop within the timeout")
			return
		}
	}
}

func (r *runner) checkErrorClassification(ctx context.Context) {
	const name, req = "error_classification", "ADP-5.errors"
	// An invalid request is the one error every adapter can produce without a provider fault.
	invalid := r.request()
	invalid.Messages = nil

	_, err := r.adapter.Complete(ctx, invalid, r.model, r.cred)
	if err == nil {
		r.fail(name, req, "adapter accepted a request with no messages")
		return
	}
	code := modberr.CodeOf(err)
	if code == modberr.CodeInternal {
		// R-ERR-01: an unclassified error crossing a process boundary cannot be retried, surfaced,
		// or budgeted correctly.
		r.fail(name, req, "adapter returned an error with no stable Modbit code")
		return
	}
	var typed *modberr.Error
	if !errors.As(err, &typed) {
		r.fail(name, req, "adapter error is not a Modbit structured error")
		return
	}
	// Retry classification must exist as a property of the code, which Retryable reads from the
	// catalog; this asserts the error carries a catalogued code at all.
	if _, known := modberr.Lookup(code); !known {
		r.fail(name, req, "adapter returned an uncatalogued error code")
		return
	}
	r.pass(name, req)
}

func (r *runner) checkTokenCounting(ctx context.Context) {
	const name, req = "token_counting", "ADP-5.request_translation"
	count, err := r.adapter.CountTokens(ctx, r.request(), r.model)
	if err != nil {
		r.fail(name, req, "CountTokens returned an error: "+message(err))
		return
	}
	if count.Tokens <= 0 {
		r.fail(name, req, "CountTokens reported no tokens for a non-empty request")
		return
	}
	r.pass(name, req)
}

// checkCredentialIsolation asserts an adapter refuses material minted for another provider. An
// adapter that accepts it would let a misrouted call authenticate against the wrong provider
// (INV-2).
func (r *runner) checkCredentialIsolation(ctx context.Context) {
	const name, req = "credential_isolation", "INV-2"
	foreign := inference.NewCredential("some-other-provider", "lease_foreign",
		"placeholder", time.Now().Add(time.Hour))
	if _, err := r.adapter.Complete(ctx, r.request(), r.model, foreign); err == nil {
		r.fail(name, req, "adapter accepted a credential minted for a different provider")
		return
	}
	r.pass(name, req)
}

func declaresLoss(resp inference.Response, feature string) bool {
	for _, l := range resp.Losses {
		if l.Feature == feature {
			return true
		}
	}
	return false
}

// message returns an error's operator-facing message without its cause chain, so a conformance
// report cannot carry provider response bodies (R-ERR-02).
func message(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := modberr.As(err); ok {
		return string(e.Code()) + ": " + e.Message()
	}
	return "unclassified error"
}
