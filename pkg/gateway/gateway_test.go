package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/gateway"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/inference/fake"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/settings"
	"github.com/modbit/modbit/pkg/taint"
)

const testSecret = "sk-live-THIS-MUST-NEVER-APPEAR"

var fixedNow = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return fixedNow }

// broker mints credentials and records what it was asked for.
type broker struct {
	err      error
	expired  bool
	requests []string
}

func (b *broker) Lease(_ context.Context, providerID string) (inference.Credential, error) {
	b.requests = append(b.requests, providerID)
	if b.err != nil {
		return inference.Credential{}, b.err
	}
	expiry := fixedNow.Add(time.Hour)
	if b.expired {
		expiry = fixedNow.Add(-time.Minute)
	}
	return inference.NewCredential(providerID, "lease_test", testSecret, expiry), nil
}

type recorder struct {
	calls []gateway.ModelCall
	err   error
}

func (r *recorder) Record(_ context.Context, call gateway.ModelCall) error {
	r.calls = append(r.calls, call)
	return r.err
}

type spendReporter struct {
	spent inference.Money
	err   error
}

func (s spendReporter) RunSpend(context.Context, id.ID) (inference.Money, error) {
	return s.spent, s.err
}

// failingInspector models a DLP service that is unreachable.
type failingInspector struct{}

func (failingInspector) Inspect(context.Context, inference.Request) (gateway.Verdict, error) {
	return gateway.Verdict{}, errors.New("dlp service unreachable")
}

// marshalCall serializes model-call metadata for leak assertions.
func marshalCall(c gateway.ModelCall) (string, error) {
	encoded, err := json.Marshal(c)
	return string(encoded), err
}

func testModel(provider, model string) inference.Capabilities {
	return inference.Capabilities{
		ProviderID: provider, ModelID: model, Revision: "2026-07-01",
		Aliases:          []string{"reasoning.balanced"},
		MaxContextTokens: 200000, MaxOutputTokens: 16384,
		SupportsStreaming: true, SupportsCancellation: true,
		ReasoningEfforts: []inference.ReasoningEffort{
			inference.ReasoningLow, inference.ReasoningMedium, inference.ReasoningHigh,
		},
		Regions: []string{"us-east"}, ProviderRetentionDays: 0,
		ReliabilityScore: 0.99,
		Pricing: inference.Pricing{
			InputPerMillion:  inference.Money{Micros: 3_000_000, Currency: "USD"},
			OutputPerMillion: inference.Money{Micros: 15_000_000, Currency: "USD"},
		},
		SafetyFilterBehavior: inference.SafetyRefusalPart,
	}
}

func snapshot(t *testing.T, overrides map[settings.Key]any) settings.Snapshot {
	t.Helper()
	resolver, err := settings.NewResolver(settings.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	var layers []settings.Layer
	if len(overrides) > 0 {
		layers = append(layers, settings.Layer{Scope: settings.ScopeOrganization, Values: overrides})
	}
	result, err := resolver.Resolve(layers)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	snap, err := settings.NewSnapshot(result, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap
}

func request(text string) inference.Request {
	return inference.Request{
		IRVersion: inference.Version,
		Alias:     "reasoning.balanced",
		Messages: []inference.Message{{
			Role:  inference.RoleUser,
			Parts: []inference.Part{{Kind: inference.PartText, Text: text, Provenance: taint.UserTrusted}},
		}},
		RunID:  id.MustNew(id.Run),
		StepID: id.MustNew(id.RunStep),
	}
}

type harness struct {
	gw       *gateway.Gateway
	adapters []*fake.Adapter
	broker   *broker
	recorder *recorder
}

func newHarness(t *testing.T, opts gateway.Options, models ...inference.Capabilities) harness {
	t.Helper()
	if len(models) == 0 {
		models = []inference.Capabilities{testModel("acme", "acme-large")}
	}
	var adapters []inference.Adapter
	var fakes []*fake.Adapter
	for _, m := range models {
		a := fake.New(m).RequireCredential()
		fakes = append(fakes, a)
		adapters = append(adapters, a)
	}
	registry, err := inference.NewRegistry(adapters, models)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	b := &broker{}
	rec := &recorder{}

	if opts.Registry == nil {
		opts.Registry = registry
	}
	if opts.Inspector == nil {
		opts.Inspector = gateway.NewDefaultInspector()
	}
	if opts.Broker == nil {
		opts.Broker = b
	}
	if opts.Recorder == nil {
		opts.Recorder = rec
	}
	if opts.Clock == nil {
		opts.Clock = fixedClock{}
	}
	gw, err := gateway.New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return harness{gw: gw, adapters: fakes, broker: b, recorder: rec}
}

func call(t *testing.T, h harness, req inference.Request, snap settings.Snapshot) (gateway.Result, error) {
	t.Helper()
	return h.gw.Complete(context.Background(), gateway.Call{
		Request:          req,
		OrganizationID:   id.MustNew(id.Organization),
		Settings:         snap,
		PolicyDecisionID: id.MustNew(id.PolicyDecision),
		Taint:            taint.UserTrusted,
	})
}

// A gateway assembled without DLP or a credential boundary is not a weaker gateway; it is a
// different product with none of the guarantees. Both are construction errors.
func TestGatewayRefusesToBeConstructedWithoutItsControls(t *testing.T) {
	t.Parallel()
	model := testModel("acme", "acme-large")
	registry, err := inference.NewRegistry([]inference.Adapter{fake.New(model)}, []inference.Capabilities{model})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	if _, err := gateway.New(gateway.Options{Inspector: gateway.NewDefaultInspector(), Broker: &broker{}}); err == nil {
		t.Error("a gateway with no registry must be refused")
	}
	if _, err := gateway.New(gateway.Options{Registry: registry, Broker: &broker{}}); err == nil {
		t.Error("a gateway with no DLP inspector must be refused")
	}
	if _, err := gateway.New(gateway.Options{Registry: registry, Inspector: gateway.NewDefaultInspector()}); err == nil {
		t.Error("a gateway with no credential broker must be refused")
	}
}

func TestSuccessfulCallRecordsImmutableMetadata(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	res, err := call(t, h, request("summarize the changes"), snapshot(t, nil))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.RecordingErr != nil {
		t.Fatalf("Record: %v", res.RecordingErr)
	}
	if len(h.recorder.calls) != 1 {
		t.Fatalf("recorded %d calls, want 1", len(h.recorder.calls))
	}

	rec := h.recorder.calls[0]
	if !rec.ID.HasPrefix(id.ModelCall) {
		t.Errorf("model call id = %q", rec.ID)
	}
	if rec.ProviderID != "acme" || rec.ModelID != "acme-large" {
		t.Errorf("route = %s/%s", rec.ProviderID, rec.ModelID)
	}
	if rec.ObservedRevision != "2026-07-01" || rec.DeclaredRevision != "2026-07-01" {
		t.Errorf("revisions = %q / %q", rec.DeclaredRevision, rec.ObservedRevision)
	}
	if rec.RevisionDrifted() {
		t.Error("no drift expected")
	}
	if rec.Usage.Total() == 0 {
		t.Error("usage was not recorded")
	}
	if rec.Cost.Micros <= 0 || rec.Cost.Currency != "USD" {
		t.Errorf("cost = %+v", rec.Cost)
	}
	if !rec.SettingsSnapshotID.HasPrefix(id.SettingsSnapshot) || !rec.PolicyDecisionID.HasPrefix(id.PolicyDecision) {
		t.Error("metadata must bind the settings snapshot and policy decision")
	}
	if rec.Latency() < 0 {
		t.Error("latency is negative")
	}
}

// INV-4: the metadata type has nowhere to put a body, which is how the promise survives contact
// with a real system.
func TestRecordedMetadataCarriesNoPromptOrCompletionBody(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	const marker = "PROMPT-BODY-MARKER-9f3a"
	if _, err := call(t, h, request("please analyse "+marker), snapshot(t, nil)); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	encoded, err := json.Marshal(h.recorder.calls[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), marker) {
		t.Fatalf("model-call metadata contains the prompt body: %s", encoded)
	}
	if strings.Contains(string(encoded), testSecret) {
		t.Fatalf("model-call metadata contains credential material: %s", encoded)
	}
}

// INV-3 has no degraded mode. An inspection that could not complete is not an inspection that
// passed, and the payload must not reach a provider.
func TestDLPFailureFailsClosedAndNeverCallsAProvider(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{Inspector: failingInspector{}})

	_, err := call(t, h, request("hello"), snapshot(t, nil))
	if !modberr.Is(err, modberr.CodeDLPUnavailable) {
		t.Fatalf("error = %v, want MODBIT_DLP_UNAVAILABLE", err)
	}
	if h.adapters[0].Calls() != 0 {
		t.Error("the provider was called despite DLP failing")
	}
	if len(h.broker.requests) != 0 {
		t.Error("a credential was leased despite DLP failing")
	}
}

func TestDLPBlockRefusesEgress(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})

	// A payload carrying credential-shaped content is blocked outright: a redacted credential still
	// discloses its shape, and its presence signals the caller assembled context it should not have.
	_, err := call(t, h, request("deploy using AKIAIOSFODNN7EXAMPLE now"), snapshot(t, nil))
	if !modberr.Is(err, modberr.CodeDLPBlocked) {
		t.Fatalf("error = %v, want MODBIT_DLP_BLOCKED", err)
	}
	if h.adapters[0].Calls() != 0 {
		t.Error("a blocked payload reached the provider")
	}

	e, _ := modberr.As(err)
	if e.Details()["rule_id"] != "aws_access_key_id" {
		t.Errorf("details = %v, want the firing rule named", e.Details())
	}
	// The error names the rule but must never echo what matched.
	encoded, _ := json.Marshal(e)
	if strings.Contains(string(encoded), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("the DLP error echoed the matched value: %s", encoded)
	}
}

func TestDLPRedactionRewritesThePayloadBeforeEgress(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})

	req := request("connect to postgres://admin:hunter2secret@db.internal/app and report")
	res, err := call(t, h, req, snapshot(t, nil))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Response.Text() == "" {
		t.Fatal("a redacted call should still complete")
	}

	rec := h.recorder.calls[0]
	if len(rec.DLPFindings) == 0 {
		t.Fatal("expected a DLP finding for the connection string")
	}
	for _, f := range rec.DLPFindings {
		if strings.Contains(f.Location, "hunter2secret") {
			t.Error("a finding leaked the matched value")
		}
	}
	if rec.Classification != gateway.ClassificationRestricted {
		t.Errorf("classification = %q, want restricted", rec.Classification)
	}

	// The property that matters: the provider received the redacted payload, not the original.
	sent := h.adapters[0].LastRequest()
	if sent == nil {
		t.Fatal("the adapter recorded no request")
	}
	delivered := sent.Messages[0].Parts[0].Text
	if strings.Contains(delivered, "hunter2secret") {
		t.Fatalf("the original secret reached the provider: %q", delivered)
	}
	if !strings.Contains(delivered, "[redacted]") {
		t.Errorf("the delivered payload was not redacted: %q", delivered)
	}
	// The caller's own request object must be untouched; redaction is not a side effect on input.
	if !strings.Contains(req.Messages[0].Parts[0].Text, "hunter2secret") {
		t.Error("the gateway mutated the caller's request in place")
	}
}

// Nested tool results are the most common carrier of accidentally captured credentials.
func TestDLPInspectsNestedToolResults(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})

	req := request("check the build")
	req.Tools = []inference.ToolDefinition{{Name: "shell", InputSchema: json.RawMessage(`{}`)}}
	req.Messages = append(req.Messages,
		inference.Message{Role: inference.RoleAssistant, Parts: []inference.Part{{
			Kind:       inference.PartToolCall,
			ToolCall:   &inference.ToolCall{ID: "c1", Name: "shell", Input: json.RawMessage(`{"cmd":"env"}`)},
			Provenance: taint.Generated,
		}}},
		inference.Message{Role: inference.RoleTool, Parts: []inference.Part{{
			Kind: inference.PartToolResult,
			ToolResult: &inference.ToolResult{CallID: "c1", Parts: []inference.Part{{
				Kind:       inference.PartText,
				Text:       "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
				Provenance: taint.ToolResult,
			}}},
			Provenance: taint.ToolResult,
		}}},
	)

	if _, err := call(t, h, req, snapshot(t, nil)); !modberr.Is(err, modberr.CodeDLPBlocked) {
		t.Fatalf("error = %v, want the nested tool result to be blocked", err)
	}
	if h.adapters[0].Calls() != 0 {
		t.Error("a payload with a credential in a tool result reached the provider")
	}
}

func TestAliasOutsideThePolicyEnvelopeIsDenied(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	snap := snapshot(t, map[settings.Key]any{
		settings.KeyModelAliasesAllowed: []any{"code.default"},
	})

	_, err := call(t, h, request("hello"), snap)
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("error = %v, want MODBIT_POLICY_DENIED", err)
	}
	if h.adapters[0].Calls() != 0 {
		t.Error("a policy-denied alias reached the provider")
	}
}

// A policy ceiling clamps rather than refuses, but a silent clamp is exactly the invisible
// downgrade ADP-3 exists to prevent, so it is declared.
func TestReasoningCeilingClampsAndDeclaresTheDowngrade(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	snap := snapshot(t, map[settings.Key]any{settings.KeyModelMaxReasoningEffort: "low"})

	req := request("think hard")
	req.Reasoning = inference.ReasoningHigh

	res, err := call(t, h, req, snap)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var found bool
	for _, l := range res.Call.Losses {
		if l.Feature == "reasoning.policy_ceiling" && l.Kind == inference.LossDowngraded {
			found = true
		}
	}
	if !found {
		t.Fatalf("losses = %+v, want a declared reasoning.policy_ceiling downgrade", res.Call.Losses)
	}
	for _, l := range res.Response.Losses {
		if l.Feature == "reasoning.policy_ceiling" {
			return
		}
	}
	t.Error("the declared loss must also reach the caller on the response")
}

func TestResidencyAndRetentionNarrowRouting(t *testing.T) {
	t.Parallel()
	euModel := testModel("euprov", "eu-model")
	euModel.Regions = []string{"eu-west"}
	h := newHarness(t, gateway.Options{}, testModel("acme", "acme-large"), euModel)

	snap := snapshot(t, map[settings.Key]any{
		settings.KeyModelResidencyRequiredRegions: []any{"eu-west"},
	})
	res, err := call(t, h, request("hello"), snap)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Call.ProviderID != "euprov" {
		t.Errorf("routed to %q, want the eu-west provider", res.Call.ProviderID)
	}

	// A retention limit no provider meets leaves no eligible route at all.
	retaining := testModel("acme", "acme-large")
	retaining.ProviderRetentionDays = 30
	h2 := newHarness(t, gateway.Options{}, retaining)
	if _, err := call(t, h2, request("hello"), snapshot(t, nil)); !modberr.Is(err, modberr.CodeNoEligibleRoute) {
		t.Fatalf("error = %v, want MODBIT_NO_ELIGIBLE_ROUTE", err)
	}
}

func TestPerRunCostCapIsEnforcedBeforeTheCall(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{
		Spend: spendReporter{spent: inference.Money{Micros: 4_999_999, Currency: "USD"}},
	})
	snap := snapshot(t, map[settings.Key]any{settings.KeyModelCostCapPerRunMicros: 5_000_000})

	_, err := call(t, h, request(strings.Repeat("token ", 500)), snap)
	if !modberr.Is(err, modberr.CodeBudgetExhausted) {
		t.Fatalf("error = %v, want MODBIT_BUDGET_EXHAUSTED", err)
	}
	if h.adapters[0].Calls() != 0 {
		t.Error("the provider was called despite the budget being exhausted")
	}
}

// An unenforceable cap is not a cap: a spend lookup that fails must refuse the call.
func TestUnreadableSpendRefusesTheCall(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{Spend: spendReporter{err: errors.New("ledger unavailable")}})
	snap := snapshot(t, map[settings.Key]any{settings.KeyModelCostCapPerRunMicros: 5_000_000})

	_, err := call(t, h, request("hello"), snap)
	if !modberr.Is(err, modberr.CodeUnavailable) {
		t.Fatalf("error = %v, want MODBIT_UNAVAILABLE", err)
	}
	if h.adapters[0].Calls() != 0 {
		t.Error("the provider was called although the cost cap could not be enforced")
	}
}

func TestCredentialFailuresNeverReachAProvider(t *testing.T) {
	t.Parallel()

	t.Run("lease failure", func(t *testing.T) {
		t.Parallel()
		b := &broker{err: errors.New("vault sealed")}
		h := newHarness(t, gateway.Options{Broker: b})
		if _, err := call(t, h, request("hello"), snapshot(t, nil)); !modberr.Is(err, modberr.CodeUnauthenticated) {
			t.Fatalf("error = %v, want MODBIT_UNAUTHENTICATED", err)
		}
		if h.adapters[0].Calls() != 0 {
			t.Error("the provider was called with no credential")
		}
	})

	t.Run("expired lease", func(t *testing.T) {
		t.Parallel()
		b := &broker{expired: true}
		h := newHarness(t, gateway.Options{Broker: b})
		if _, err := call(t, h, request("hello"), snapshot(t, nil)); !modberr.Is(err, modberr.CodeUnauthenticated) {
			t.Fatalf("error = %v, want MODBIT_UNAUTHENTICATED", err)
		}
		if h.adapters[0].Calls() != 0 {
			t.Error("the provider was called with an expired credential")
		}
	})
}

// The credential is leased for the provider that will actually serve the call, not eagerly for
// every candidate.
func TestCredentialIsLeasedOnlyForTheChosenProvider(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{}, testModel("acme", "acme-large"), testModel("other", "other-model"))
	if _, err := call(t, h, request("hello"), snapshot(t, nil)); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if len(h.broker.requests) != 1 {
		t.Fatalf("leased %d credentials, want 1: %v", len(h.broker.requests), h.broker.requests)
	}
	if h.broker.requests[0] != "acme" {
		t.Errorf("leased for %q, want the chosen provider", h.broker.requests[0])
	}
}

// §14.4: failover between candidates is safe by construction because every candidate satisfied the
// same envelope. What matters is that it is bounded and recorded.
func TestFailoverIsBoundedAndRecorded(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{MaxRouteAttempts: 3},
		testModel("acme", "acme-large"), testModel("other", "other-model"))

	h.adapters[0].Faults = fake.Faults{
		FailWith: modberr.New(modberr.CodeProviderUnavailable, "upstream is down"),
	}

	res, err := call(t, h, request("hello"), snapshot(t, nil))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.Call.ProviderID != "other" {
		t.Errorf("routed to %q, want the surviving provider", res.Call.ProviderID)
	}
	if !res.Call.FailedOver() || len(res.Call.Failovers) != 1 {
		t.Fatalf("failovers = %+v, want one recorded", res.Call.Failovers)
	}
	if res.Call.Failovers[0].Reason != string(modberr.CodeProviderUnavailable) {
		t.Errorf("failover reason = %q, want the stable error code", res.Call.Failovers[0].Reason)
	}
}

// A deterministic rejection would produce the same refusal from every provider; failing over would
// only spend budget reproducing it.
func TestNonRetryableFailureDoesNotFailOver(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{MaxRouteAttempts: 3},
		testModel("acme", "acme-large"), testModel("other", "other-model"))
	h.adapters[0].Faults = fake.Faults{
		FailWith: modberr.New(modberr.CodeInvalidArgument, "malformed request"),
	}

	if _, err := call(t, h, request("hello"), snapshot(t, nil)); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want the original refusal", err)
	}
	if h.adapters[1].Calls() != 0 {
		t.Error("a deterministic rejection must not fail over to another provider")
	}
}

func TestFailoverRespectsItsAttemptBudget(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{MaxRouteAttempts: 1},
		testModel("acme", "acme-large"), testModel("other", "other-model"))
	h.adapters[0].Faults = fake.Faults{
		FailWith: modberr.New(modberr.CodeProviderUnavailable, "upstream is down"),
	}

	if _, err := call(t, h, request("hello"), snapshot(t, nil)); err == nil {
		t.Fatal("expected the call to fail once the attempt budget was spent")
	}
	if h.adapters[1].Calls() != 0 {
		t.Error("the attempt budget was exceeded")
	}
}

// MOD-6 / OEV-1: keeping both the declared and observed revision is what makes a silent provider
// model change detectable.
func TestRevisionDriftIsDetectable(t *testing.T) {
	t.Parallel()
	model := testModel("acme", "acme-large")
	h := newHarness(t, gateway.Options{}, model)
	// The provider rolled the model forward under the same identifier without announcing it.
	h.adapters[0].ReportRevision = "2026-08-15"

	res, err := call(t, h, request("hello"), snapshot(t, nil))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !res.Call.RevisionDrifted() {
		t.Fatalf("declared %q observed %q should register as drift",
			res.Call.DeclaredRevision, res.Call.ObservedRevision)
	}
	if res.Call.DeclaredRevision != "2026-07-01" || res.Call.ObservedRevision != "2026-08-15" {
		t.Errorf("metadata must keep both revisions, got %q / %q",
			res.Call.DeclaredRevision, res.Call.ObservedRevision)
	}

	// A matching revision is not drift.
	h2 := newHarness(t, gateway.Options{}, model)
	steady, err := call(t, h2, request("hello"), snapshot(t, nil))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if steady.Call.RevisionDrifted() {
		t.Error("a matching revision must not register as drift")
	}
}

// The completion already happened; pretending it did not because the ledger write failed would be
// dishonest. The caller decides whether missing evidence blocks its completion contract.
func TestRecordingFailureIsSurfacedWithoutInvalidatingTheCompletion(t *testing.T) {
	t.Parallel()
	rec := &recorder{err: errors.New("ledger write failed")}
	h := newHarness(t, gateway.Options{Recorder: rec})

	res, err := call(t, h, request("hello"), snapshot(t, nil))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.RecordingErr == nil {
		t.Fatal("a recording failure must be surfaced")
	}
	if res.Response.Text() == "" {
		t.Error("the completion must still be returned")
	}
}

func TestCancelledContextIsRefusedBeforeEgress(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := h.gw.Complete(ctx, gateway.Call{
		Request:        request("hello"),
		OrganizationID: id.MustNew(id.Organization),
		Settings:       snapshot(t, nil),
	})
	if !modberr.Is(err, modberr.CodeCancelled) {
		t.Fatalf("error = %v, want MODBIT_CANCELLED", err)
	}
	if h.adapters[0].Calls() != 0 {
		t.Error("a cancelled call reached the provider")
	}
}

func TestCallRequiresAnOrganization(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	_, err := h.gw.Complete(context.Background(), gateway.Call{
		Request:  request("hello"),
		Settings: snapshot(t, nil),
	})
	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want MODBIT_INVALID_ARGUMENT", err)
	}
}

// INV-2: the protection is not access control, it is making accidental disclosure impossible
// through every path that normally leaks a secret.
func TestCredentialResistsAccidentalDisclosure(t *testing.T) {
	t.Parallel()
	cred := inference.NewCredential("acme", "lease_1", testSecret, fixedNow.Add(time.Hour))

	if cred.Secret() != testSecret {
		t.Fatal("Secret must return the material to its one legitimate caller")
	}

	for name, rendered := range map[string]string{
		"%v":       fmt.Sprintf("%v", cred),
		"%s":       fmt.Sprintf("%s", cred),
		"%+v":      fmt.Sprintf("%+v", cred),
		"%#v":      fmt.Sprintf("%#v", cred),
		"embedded": fmt.Sprintf("%v", struct{ C inference.Credential }{cred}),
	} {
		if strings.Contains(rendered, testSecret) {
			t.Errorf("%s leaked the credential: %s", name, rendered)
		}
	}

	encoded, err := json.Marshal(struct {
		C inference.Credential `json:"credential"`
	}{cred})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), testSecret) {
		t.Errorf("JSON leaked the credential: %s", encoded)
	}

	var buf strings.Builder
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("call", "credential", cred)
	if strings.Contains(buf.String(), testSecret) {
		t.Errorf("structured logging leaked the credential: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "lease_1") {
		t.Errorf("structured logging should still record the lease id: %s", buf.String())
	}
}

func TestCredentialExpiry(t *testing.T) {
	t.Parallel()
	cred := inference.NewCredential("acme", "lease_1", testSecret, fixedNow)
	if !cred.Expired(fixedNow) {
		t.Error("a credential is expired at its expiry instant")
	}
	if cred.Expired(fixedNow.Add(-time.Second)) {
		t.Error("a credential is not expired before its expiry")
	}
	if (inference.Credential{}).IsZero() != true {
		t.Error("the zero credential must report itself as unset")
	}
}
