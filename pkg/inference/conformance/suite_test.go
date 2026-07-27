package conformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/inference/conformance"
	"github.com/modbit/modbit/pkg/inference/fake"
)

// fullModel declares every capability, so no case is skipped and every contract property is
// actually exercised.
func fullModel() inference.Capabilities {
	return inference.Capabilities{
		ProviderID:               "acme",
		ModelID:                  "acme-large",
		Revision:                 "2026-07-01",
		ReleaseDate:              time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Aliases:                  []string{"reasoning.balanced"},
		MaxContextTokens:         200000,
		MaxOutputTokens:          16384,
		SupportsTools:            true,
		SupportsParallelToolCall: true,
		ToolSchemaDialect:        inference.DialectJSONSchemaDraft202012,
		SupportsStructuredOutput: true,
		SupportsStrictSchema:     true,
		SupportsVision:           true,
		SupportsAudio:            true,
		SupportsFiles:            true,
		SupportsStreaming:        true,
		SupportsCancellation:     true,
		ReasoningEfforts: []inference.ReasoningEffort{
			inference.ReasoningLow, inference.ReasoningMedium, inference.ReasoningHigh,
		},
		SupportsPromptCache:   true,
		PromptCacheTTL:        5 * time.Minute,
		Regions:               []string{"us-east"},
		ProviderRetentionDays: 0,
		RequestsPerMinute:     1000,
		MaxConcurrency:        50,
		TypicalLatency:        time.Second,
		ReliabilityScore:      0.99,
		Pricing: inference.Pricing{
			InputPerMillion:  inference.Money{Micros: 3_000_000, Currency: "USD"},
			OutputPerMillion: inference.Money{Micros: 15_000_000, Currency: "USD"},
		},
		SafetyFilterBehavior: inference.SafetyRefusalPart,
	}
}

// conformantAdapter returns a fake that exercises every declared path, so the suite reaches Pass
// rather than Inconclusive.
func conformantAdapter(model inference.Capabilities) *fake.Adapter {
	a := fake.New(model)
	// A multi-word reply with a small per-delta latency makes the stream genuinely interruptible.
	// An instantaneous stream finishes before cancellation lands, and the suite then reports
	// cancellation as inconclusive rather than pretending it was verified.
	a.Reply = "acknowledged and understood completely"
	a.Latency = 15 * time.Millisecond
	a.ToolCalls = []inference.ToolCall{
		fake.ToolCall("call-1", "conformance_probe", map[string]any{"q": "x"}),
		fake.ToolCall("call-a", "probe_a", map[string]any{}),
		fake.ToolCall("call-b", "probe_b", map[string]any{}),
	}
	return a
}

// testOptions size the suite for an in-memory adapter. A live provider uses DefaultOptions.
func testOptions() conformance.Options {
	return conformance.Options{StreamTimeout: 5 * time.Second, CancelTimeout: 300 * time.Millisecond}
}

func run(t *testing.T, a inference.Adapter, model inference.Capabilities) conformance.Report {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return conformance.RunWithOptions(ctx, a, model, testOptions())
}

func statusOf(t *testing.T, r conformance.Report, caseName string) conformance.Result {
	t.Helper()
	for _, res := range r.Results {
		if res.Case == caseName {
			return res
		}
	}
	t.Fatalf("suite produced no result for case %q", caseName)
	return conformance.Result{}
}

func TestConformantAdapterIsProductionReady(t *testing.T) {
	t.Parallel()
	model := fullModel()
	report := run(t, conformantAdapter(model), model)

	if !report.ProductionReady() {
		t.Fatalf("a conformant adapter was not production ready: %s\nfailures: %+v\ninconclusive: %+v",
			report.Summary(), report.Failures(), report.Inconclusive())
	}
	if report.SuiteVersion != conformance.SuiteVersion {
		t.Errorf("suite version = %d", report.SuiteVersion)
	}
	if report.Revision != model.Revision {
		t.Errorf("report revision = %q, want %q", report.Revision, model.Revision)
	}
	if report.CompletedAt.Before(report.StartedAt) {
		t.Error("report timestamps are inverted")
	}
}

// ADP-5 enumerates the coverage the suite must provide. A missing case would let an adapter ship
// with an untested contract surface, so the coverage itself is asserted.
func TestSuiteCoversEveryADP5Area(t *testing.T) {
	t.Parallel()
	model := fullModel()
	report := run(t, conformantAdapter(model), model)

	required := []string{
		"request_translation",    // request translation
		"tool_calls_serial",      // serial tool calls
		"tool_calls_parallel",    // parallel tool calls
		"schema_validation",      // schema validation
		"structured_output",      // structured output
		"streaming",              // streaming
		"cancellation",           // cancellation
		"error_classification",   // errors and retry classification
		"usage_accounting",       // usage accounting
		"prompt_caching",         // prompt caching
		"model_revision_capture", // model revision capture
		"content_types",          // content-type support
	}
	present := make(map[string]struct{}, len(report.Results))
	for _, res := range report.Results {
		present[res.Case] = struct{}{}
	}
	for _, c := range required {
		if _, ok := present[c]; !ok {
			t.Errorf("suite is missing the ADP-5 case %q", c)
		}
	}
}

// The point of the suite. Each fault is a real contract violation, and a suite that cannot detect
// one is decoration.
func TestSuiteDetectsEachContractViolation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		fault    fake.Faults
		wantCase string
		// latency slows the fake's stream so a timing-sensitive case is genuinely exercised.
		latency time.Duration
	}{
		{
			name:     "missing model revision defeats drift detection",
			fault:    fake.Faults{OmitRevision: true},
			wantCase: "model_revision_capture",
		},
		{
			name:     "negative usage breaks cost accounting",
			fault:    fake.Faults{NegativeUsage: true},
			wantCase: "usage_accounting",
		},
		{
			name:     "unclosed stream channel leaks the consumer goroutine",
			fault:    fake.Faults{UnclosedStream: true},
			wantCase: "streaming",
		},
		{
			name:     "stream ignoring cancellation cannot be interrupted",
			fault:    fake.Faults{IgnoreCancellation: true},
			wantCase: "cancellation",
			latency:  200 * time.Millisecond, // outlives the 300ms drain deadline
		},
		{
			name:     "adapter refuses a modality its capability record declares",
			fault:    fake.Faults{RejectMedia: true},
			wantCase: "content_types",
		},
		{
			name:     "message_stop with no assembled response",
			fault:    fake.Faults{OmitFinalResponse: true},
			wantCase: "streaming",
		},
		{
			name:     "assembled response disagrees with the emitted deltas",
			fault:    fake.Faults{DivergentStreamText: true},
			wantCase: "streaming",
		},
		{
			name:     "unclassified error has no stable Modbit code",
			fault:    fake.Faults{UnstableErrorCode: true},
			wantCase: "error_classification",
		},
		{
			name:     "model output laundered as user-trusted provenance",
			fault:    fake.Faults{LaunderProvenance: true},
			wantCase: "request_translation",
		},
		{
			name:     "tool_use finish reported with no tool call",
			fault:    fake.Faults{MisreportToolUse: true},
			wantCase: "request_translation",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			model := fullModel()
			a := conformantAdapter(model)
			a.Faults = tc.fault
			if tc.latency > 0 {
				a.Latency = tc.latency
			}

			report := run(t, a, model)
			if report.ProductionReady() {
				t.Fatalf("suite passed a broken adapter: %s", report.Summary())
			}
			res := statusOf(t, report, tc.wantCase)
			if res.Status != conformance.StatusFail {
				t.Fatalf("case %q = %s (%s), want fail", tc.wantCase, res.Status, res.Detail)
			}
			if res.Detail == "" {
				t.Errorf("case %q failed with no explanation", tc.wantCase)
			}
		})
	}
}

// ADP-3: a silently ignored capability is indistinguishable from a guarantee.
func TestSuiteDetectsSuppressedLossDeclaration(t *testing.T) {
	t.Parallel()
	model := fullModel()
	// Remove the highest reasoning effort so there is a genuine gap the adapter must declare.
	model.ReasoningEfforts = []inference.ReasoningEffort{inference.ReasoningLow}

	a := conformantAdapter(model)
	a.Faults = fake.Faults{SuppressLosses: true}

	report := run(t, a, model)
	res := statusOf(t, report, "loss_declaration")
	if res.Status != conformance.StatusFail {
		t.Fatalf("loss_declaration = %s (%s), want fail", res.Status, res.Detail)
	}
	if report.ProductionReady() {
		t.Error("an adapter suppressing declared losses must not be production ready")
	}
}

// A model that does not declare a capability legitimately skips its case, and skips do not block
// readiness.
func TestUndeclaredCapabilitiesAreSkippedNotFailed(t *testing.T) {
	t.Parallel()
	model := fullModel()
	model.SupportsTools = false
	model.SupportsParallelToolCall = false
	model.ToolSchemaDialect = ""
	model.SupportsStructuredOutput = false
	model.SupportsStrictSchema = false
	model.SupportsVision = false
	model.SupportsAudio = false
	model.SupportsFiles = false
	model.SupportsPromptCache = false
	model.PromptCacheTTL = 0

	report := run(t, conformantAdapter(model), model)

	for _, name := range []string{
		"tool_calls_serial", "tool_calls_parallel", "schema_validation",
		"structured_output", "prompt_caching",
	} {
		if got := statusOf(t, report, name).Status; got != conformance.StatusSkipped {
			t.Errorf("case %q = %s, want skipped", name, got)
		}
	}
	if !report.ProductionReady() {
		t.Errorf("skips must not block readiness: %s\nfailures: %+v\ninconclusive: %+v",
			report.Summary(), report.Failures(), report.Inconclusive())
	}
}

// An untested path on a *declared* capability is inconclusive, and inconclusive blocks readiness.
// Reporting it as verified would be exactly the assertion-without-evidence the platform prohibits.
func TestUnexercisedDeclaredPathIsInconclusiveAndBlocksReadiness(t *testing.T) {
	t.Parallel()
	model := fullModel()

	a := fake.New(model)
	a.ToolCalls = nil // declares tool support but never calls one

	report := run(t, a, model)

	serial := statusOf(t, report, "tool_calls_serial")
	if serial.Status != conformance.StatusInconclusive {
		t.Errorf("tool_calls_serial = %s, want inconclusive", serial.Status)
	}
	if len(report.Failures()) != 0 {
		t.Errorf("an unexercised path is not a failure: %+v", report.Failures())
	}
	if report.ProductionReady() {
		t.Error("inconclusive results on a declared capability must block production readiness")
	}
}

// A stream that has already finished cannot demonstrate cancellation. This is the ordinary shape
// for a provider whose response was fully received before the client started reading. Reporting it
// as a pass would let an adapter that ignores cancellation ship as verified, so it is inconclusive
// — which still blocks readiness.
func TestCancellationOnAnAlreadyCompletedStreamIsInconclusive(t *testing.T) {
	t.Parallel()
	model := fullModel()
	a := conformantAdapter(model)
	a.Latency = 0
	// The whole stream, terminal event included, exists before Stream returns. A large StreamBuffer
	// was not enough: emit ran in a goroutine, so whether it reached the terminal event before the
	// suite cancelled was a race, and the test reported pass roughly one run in ten.
	a.CompleteBeforeReturn = true

	report := run(t, a, model)
	res := statusOf(t, report, "cancellation")
	if res.Status != conformance.StatusInconclusive {
		t.Fatalf("cancellation = %s (%s), want inconclusive", res.Status, res.Detail)
	}
	if len(report.Failures()) != 0 {
		t.Errorf("an unexercised path is not a failure: %+v", report.Failures())
	}
	if report.ProductionReady() {
		t.Error("an unverified cancellation path must block production readiness")
	}
}

func TestSuiteSurvivesATotallyBrokenAdapter(t *testing.T) {
	t.Parallel()
	model := fullModel()
	a := fake.New(model)
	a.Faults = fake.Faults{FailWith: errors.New("provider is on fire")}

	// The suite must report, not panic: a crash tells the adapter author nothing.
	report := run(t, a, model)
	if len(report.Failures()) == 0 {
		t.Fatal("expected failures from an adapter that errors on every call")
	}
	if report.ProductionReady() {
		t.Error("a permanently failing adapter must not be production ready")
	}
}

func TestReportIsSerializableEvidence(t *testing.T) {
	t.Parallel()
	model := fullModel()
	report := run(t, conformantAdapter(model), model)

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var restored conformance.Report
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(restored.Results) != len(report.Results) {
		t.Errorf("round trip lost results: %d vs %d", len(restored.Results), len(report.Results))
	}
	if restored.ProductionReady() != report.ProductionReady() {
		t.Error("round trip changed the readiness verdict")
	}
	if !strings.Contains(report.Summary(), model.ModelID) {
		t.Errorf("summary does not name the model: %q", report.Summary())
	}
}

// A conformance report is an evidence artifact: it must never carry provider response bodies or
// prompt content (R-ERR-02).
func TestReportDetailsCarryNoUpstreamContent(t *testing.T) {
	t.Parallel()
	model := fullModel()
	a := fake.New(model)
	a.Faults = fake.Faults{
		FailWith: errors.New("provider said: your api key sk-live-SECRET is invalid for user@example.com"),
	}

	report := run(t, a, model)
	encoded, _ := json.Marshal(report)
	for _, leak := range []string{"sk-live-SECRET", "user@example.com", "provider said"} {
		if strings.Contains(string(encoded), leak) {
			t.Fatalf("conformance report leaked upstream content %q", leak)
		}
	}
	if len(report.Failures()) == 0 {
		t.Error("expected the failure to still be reported")
	}
}

// The gateway can guarantee its streaming protocol only if adapters uphold theirs. Each fault here
// is a way an adapter breaks the terminal contract the pump depends on.
func TestSuiteDetectsStreamTerminalContractViolations(t *testing.T) {
	t.Parallel()
	// The two cases divide the work: stream_terminal_contract owns the event *sequence*, streaming
	// owns *assembly* of the final response. Naming which case must fire keeps that boundary honest.
	tests := []struct {
		name     string
		fault    fake.Faults
		wantCase string
	}{
		{"stream truncated with no terminal event", fake.Faults{TruncateStream: true}, "stream_terminal_contract"},
		{"terminal event carries no assembled response", fake.Faults{OmitFinalResponse: true}, "streaming"},
		{"assembled response disagrees with the deltas", fake.Faults{DivergentStreamText: true}, "streaming"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			model := fullModel()
			a := conformantAdapter(model)
			a.Faults = tc.fault

			report := run(t, a, model)
			if report.ProductionReady() {
				t.Fatalf("suite passed an adapter breaking the terminal contract: %s", report.Summary())
			}
			res := statusOf(t, report, tc.wantCase)
			if res.Status != conformance.StatusFail {
				t.Fatalf("%s = %s (%s), want fail", tc.wantCase, res.Status, res.Detail)
			}
		})
	}
}

// A model with no streaming support legitimately skips the case.
func TestStreamTerminalContractSkippedWithoutStreamingSupport(t *testing.T) {
	t.Parallel()
	model := fullModel()
	model.SupportsStreaming = false
	model.SupportsCancellation = false

	report := run(t, conformantAdapter(model), model)
	if got := statusOf(t, report, "stream_terminal_contract").Status; got != conformance.StatusSkipped {
		t.Errorf("stream_terminal_contract = %s, want skipped", got)
	}
}
