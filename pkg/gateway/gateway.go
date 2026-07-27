// Package gateway implements the Modbit Model Gateway: the single egress boundary for hosted model
// traffic.
//
// Boundary: it owns the request pipeline from policy validation through to immutable model-call
// metadata. It is the only component that holds provider credential references, and the only
// component permitted to call a provider adapter.
//
// Requirements: SDD v5.1 §10 (pipeline and security), PRD v5.1 §14.3 (routing), §14.4 (safe
// failover), §17.5 (redaction and DLP); rules.md INV-1 (all hosted traffic traverses the gateway),
// INV-2 (credentials never leave this boundary), INV-3 (classification and DLP on every outbound
// payload), INV-4 (bodies are metadata-only by default).
//
// # Pipeline
//
//	request
//	→ settings and policy validation
//	→ context classification
//	→ DLP and redaction
//	→ route selection
//	→ provider adapter
//	→ usage and cost
//	→ immutable metadata
//	→ response
//
// # Fail closed
//
// Every enforcement step in this pipeline refuses on failure rather than proceeding. If DLP cannot
// complete, the call does not happen — a gateway that "tried to classify and moved on" provides no
// guarantee at all, and INV-3 has no degraded mode. The same applies to budget lookups and
// credential leases: a control that cannot be evaluated is treated as not satisfied.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/settings"
	"github.com/modbit/modbit/pkg/taint"
)

// CredentialBroker mints per-call provider credentials.
//
// The gateway never stores what a broker returns beyond the life of one call, and no credential
// crosses back out of this package (INV-2).
type CredentialBroker interface {
	Lease(ctx context.Context, providerID string) (inference.Credential, error)
}

// SpendReporter reports a run's accumulated inference spend, so a per-run cost cap can be enforced
// before a call rather than discovered after it.
type SpendReporter interface {
	RunSpend(ctx context.Context, runID id.ID) (inference.Money, error)
}

// Recorder persists immutable model-call metadata and is where usage, cost, and routing evidence
// become durable. A recording failure does not fail the call — the completion already happened, and
// pretending otherwise would be dishonest — but it is surfaced on the result.
type Recorder interface {
	// Record persists the call metadata and its canonical events as one atomic act (R-EVT-04). A
	// production implementation writes both inside a single transaction alongside the outbox row,
	// so a recorded call can never exist without its event, nor an event without its call.
	Record(ctx context.Context, call ModelCall, events []event.Envelope) error
}

// Clock supplies time. Injected so metadata and cost decisions are reproducible in tests.
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// Options configures a Gateway.
type Options struct {
	Registry  *inference.Registry
	Inspector Inspector
	Broker    CredentialBroker
	Spend     SpendReporter
	Recorder  Recorder
	// Sequencer issues the strictly monotonic per-run event sequence. Required whenever a Recorder
	// is configured, since every gateway event is run scoped.
	Sequencer event.Sequencer
	Clock     Clock
	Generator *id.Generator
	// ConsumerStallTimeout bounds how long a stream waits for a consumer that stopped reading
	// before abandoning it (S9). Zero means the package default.
	ConsumerStallTimeout time.Duration
	// MaxRouteAttempts bounds failover across eligible candidates. Failover is safe by
	// construction here — every candidate already satisfied the same capability, residency,
	// retention, and budget envelope (§14.4) — but it still needs an attempt budget (R-ERR-03).
	MaxRouteAttempts int
}

// Gateway is the model egress boundary. It holds no run or tenant state and is safe for concurrent
// use (R-GO-06).
type Gateway struct {
	registry             *inference.Registry
	inspector            Inspector
	broker               CredentialBroker
	spend                SpendReporter
	recorder             Recorder
	sequencer            event.Sequencer
	clock                Clock
	generator            *id.Generator
	maxAttempts          int
	consumerStallTimeout time.Duration
}

// New validates options and returns a Gateway.
//
// A missing Inspector or CredentialBroker is a construction error, not a runtime degradation: a
// gateway assembled without DLP or without a credential boundary is not a weaker gateway, it is a
// different product with none of the guarantees this one makes.
func New(opts Options) (*Gateway, error) {
	switch {
	case opts.Registry == nil:
		return nil, modberr.New(modberr.CodeInvalidArgument, "gateway requires a model registry")
	case opts.Inspector == nil:
		return nil, modberr.New(modberr.CodeInvalidArgument,
			"gateway requires a DLP inspector; classification and DLP are mandatory on every outbound payload")
	case opts.Broker == nil:
		return nil, modberr.New(modberr.CodeInvalidArgument,
			"gateway requires a credential broker; provider credentials exist only inside this boundary")
	case opts.Recorder != nil && opts.Sequencer == nil:
		// Run-scoped events without a monotonic sequence produce a log that cannot be reassembled
		// (R-EVT-01, R-EVT-07). Refusing at construction beats discovering it on the first call.
		return nil, modberr.New(modberr.CodeInvalidArgument,
			"a gateway with a recorder requires a sequence authority for its run events")
	}
	g := &Gateway{
		registry:             opts.Registry,
		inspector:            opts.Inspector,
		broker:               opts.Broker,
		spend:                opts.Spend,
		recorder:             opts.Recorder,
		sequencer:            opts.Sequencer,
		clock:                opts.Clock,
		generator:            opts.Generator,
		maxAttempts:          opts.MaxRouteAttempts,
		consumerStallTimeout: opts.ConsumerStallTimeout,
	}
	if g.clock == nil {
		g.clock = systemClock{}
	}
	if g.generator == nil {
		g.generator = id.NewGenerator(nil)
	}
	if g.maxAttempts <= 0 {
		g.maxAttempts = 2
	}
	return g, nil
}

// Call is one gateway invocation.
type Call struct {
	// Request is the canonical inference request.
	Request inference.Request
	// OrganizationID owns the call, for tenancy and usage attribution.
	OrganizationID id.ID
	// Settings is the run's frozen settings snapshot (INV-6).
	Settings settings.Snapshot
	// SpaceID scopes run events. Required when the gateway emits canonical events, because a
	// run-scoped envelope without it cannot be authorized or filtered per Space (R-TEN-01).
	SpaceID id.ID
	// CorrelationID ties every event produced while servicing one originating command.
	CorrelationID id.ID
	// PolicyDecisionID links the call to the decision that authorized it.
	PolicyDecisionID id.ID
	// Taint is the highest-risk provenance class in the request context, recorded on the metadata.
	Taint taint.Class
}

// Result is a completed gateway call.
type Result struct {
	Response inference.Response
	// Call is the immutable metadata recorded for this invocation.
	Call ModelCall
	// RecordingErr is non-nil when metadata persistence failed. The completion still happened; the
	// caller decides whether the missing evidence blocks its completion contract.
	RecordingErr error
}

// Complete runs the pipeline and returns the completion.
func (g *Gateway) Complete(ctx context.Context, c Call) (Result, error) {
	started := g.clock.Now()

	prepared, err := g.prepare(ctx, c)
	if err != nil {
		return Result{}, err
	}

	var (
		attempts  int
		lastErr   error
		failovers []Failover
	)
	for _, candidate := range prepared.candidates {
		if attempts >= g.maxAttempts {
			break
		}
		attempts++

		cred, err := g.broker.Lease(ctx, candidate.Model.ProviderID)
		if err != nil {
			// A credential that cannot be leased is a boundary failure, not a routing preference.
			lastErr = modberr.Wrap(err, modberr.CodeUnauthenticated,
				"could not lease a provider credential").WithDetail("scheme", "provider_credential")
			failovers = append(failovers, Failover{
				ProviderID: candidate.Model.ProviderID, ModelID: candidate.Model.ModelID,
				Reason: "credential_lease_failed",
			})
			continue
		}
		if cred.Expired(g.clock.Now()) {
			lastErr = modberr.New(modberr.CodeUnauthenticated, "leased credential is already expired").
				WithDetail("scheme", "provider_credential")
			failovers = append(failovers, Failover{
				ProviderID: candidate.Model.ProviderID, ModelID: candidate.Model.ModelID,
				Reason: "credential_expired",
			})
			continue
		}

		resp, err := candidate.Adapter.Complete(ctx, prepared.request, candidate.Model, cred)
		if err != nil {
			lastErr = err
			// Only a retryable class justifies moving to another provider. Failing over on a
			// deterministic rejection would just spend budget reproducing the same refusal.
			if !modberr.IsRetryable(err) || errors.Is(ctx.Err(), context.Canceled) {
				return Result{}, err
			}
			failovers = append(failovers, Failover{
				ProviderID: candidate.Model.ProviderID, ModelID: candidate.Model.ModelID,
				Reason: string(modberr.CodeOf(err)),
			})
			continue
		}
		if err := resp.Validate(); err != nil {
			return Result{}, modberr.Wrap(err, modberr.CodeInternal,
				"adapter returned a response that is not a valid canonical response")
		}

		return g.finish(ctx, c, prepared, candidate, resp, failovers, started)
	}

	if lastErr == nil {
		lastErr = modberr.New(modberr.CodeNoEligibleRoute, "no route was attempted")
	}
	return Result{}, lastErr
}

// prepared carries the pipeline state between the preparation and execution phases.
type prepared struct {
	// callID identifies this invocation from before any provider is contacted, so a failure at any
	// later point still has something to attribute usage and events to.
	callID         id.ID
	request        inference.Request
	classification Classification
	findings       []Finding
	policyLosses   []inference.Loss
	candidates     []inference.Candidate
	estimatedCost  inference.Money
}

// prepare runs everything up to and including route selection. It performs no provider I/O, so a
// request refused here never reaches a network.
func (g *Gateway) prepare(ctx context.Context, c Call) (prepared, error) {
	if err := ctx.Err(); err != nil {
		return prepared{}, modberr.Wrap(err, modberr.CodeCancelled, "gateway call cancelled")
	}
	if !c.OrganizationID.HasPrefix(id.Organization) {
		return prepared{}, modberr.New(modberr.CodeInvalidArgument,
			"gateway call requires an organization identifier").WithDetail("field", "organization_id")
	}
	if err := c.Request.Validate(); err != nil {
		return prepared{}, err
	}
	callID, err := g.generator.New(id.ModelCall)
	if err != nil {
		return prepared{}, modberr.Wrap(err, modberr.CodeInternal, "allocate model-call identifier")
	}

	req := c.Request
	var policyLosses []inference.Loss

	// 1. Settings and policy validation.
	allowedAliases, aliasErr := c.Settings.StringList(settings.KeyModelAliasesAllowed)
	if err := aliasErr; err != nil {
		return prepared{}, err
	}
	if !aliasPermitted(allowedAliases, req.Alias) {
		return prepared{}, modberr.Newf(modberr.CodePolicyDenied,
			"capability alias %q is not permitted by policy", req.Alias).
			WithDetail("policy_decision_id", c.PolicyDecisionID.String()).
			WithDetail("rule_id", string(settings.KeyModelAliasesAllowed))
	}

	ceiling, err := c.Settings.String(settings.KeyModelMaxReasoningEffort)
	if err != nil {
		return prepared{}, err
	}
	if clamped, lowered := clampReasoning(req.Reasoning, inference.ReasoningEffort(ceiling)); lowered {
		// Clamping rather than refusing keeps the run moving, but a silent clamp would be exactly
		// the invisible downgrade ADP-3 exists to prevent, so it is declared as a Loss.
		policyLosses = append(policyLosses, inference.Loss{
			Kind: inference.LossDowngraded, Feature: "reasoning.policy_ceiling",
			Detail: fmt.Sprintf("policy caps reasoning effort at %q", ceiling),
		})
		req.Reasoning = clamped
	}

	// 2. Classification and DLP. This runs before route selection so a blocked payload never
	// reaches a provider allowlist decision, and before any credential is leased.
	verdict, err := g.inspector.Inspect(ctx, req)
	if err != nil {
		// INV-3: fail closed. An inspection that could not complete is not an inspection that
		// passed.
		return prepared{}, modberr.Wrap(err, modberr.CodeDLPUnavailable,
			"classification and DLP could not complete; the payload was not sent").
			WithDetail("reason_class", "inspector_error")
	}
	switch verdict.Decision {
	case DecisionBlock:
		return prepared{}, modberr.New(modberr.CodeDLPBlocked,
			"payload blocked by data-loss prevention").
			WithDetail("policy_decision_id", c.PolicyDecisionID.String()).
			WithDetail("classification", string(verdict.Classification)).
			WithDetail("rule_id", firstRuleID(verdict.Findings))
	case DecisionRedact:
		if verdict.Redacted == nil {
			return prepared{}, modberr.New(modberr.CodeDLPUnavailable,
				"inspector requested redaction but returned no redacted payload").
				WithDetail("reason_class", "inspector_contract")
		}
		req = *verdict.Redacted
		if err := req.Validate(); err != nil {
			return prepared{}, modberr.Wrap(err, modberr.CodeDLPUnavailable,
				"redaction produced an invalid request; the payload was not sent").
				WithDetail("reason_class", "inspector_contract")
		}
	}

	// 3. Route selection inside the policy envelope.
	constraints, err := g.constraints(c.Settings)
	if err != nil {
		return prepared{}, err
	}
	candidates, err := g.registry.Candidates(req, constraints)
	if err != nil {
		return prepared{}, decorate(err, c.PolicyDecisionID)
	}

	// 4. Budget. Estimated on the best candidate's pricing; the cap is checked before the call so a
	// run cannot discover it is over budget only after spending.
	estimated, err := g.checkBudget(ctx, c, candidates[0])
	if err != nil {
		return prepared{}, err
	}

	return prepared{
		callID:         callID,
		request:        req,
		classification: verdict.Classification,
		findings:       verdict.Findings,
		policyLosses:   policyLosses,
		candidates:     candidates,
		estimatedCost:  estimated,
	}, nil
}

func (g *Gateway) constraints(snapshot settings.Snapshot) (inference.Constraints, error) {
	providers, err := snapshot.StringList(settings.KeyModelProvidersAllowed)
	if err != nil {
		return inference.Constraints{}, err
	}
	regions, err := snapshot.StringList(settings.KeyModelResidencyRequiredRegions)
	if err != nil {
		return inference.Constraints{}, err
	}
	retention, err := snapshot.Int(settings.KeyModelRetentionMaxProviderDays)
	if err != nil {
		return inference.Constraints{}, err
	}
	return inference.Constraints{
		AllowedProviders: providers,
		RequiredRegions:  regions,
		MaxRetentionDays: int(retention),
	}, nil
}

// checkBudget enforces the per-run cost cap. A spend lookup that fails refuses the call: an
// unenforceable cap is not a cap.
func (g *Gateway) checkBudget(ctx context.Context, c Call, candidate inference.Candidate) (inference.Money, error) {
	ceiling, err := c.Settings.Int(settings.KeyModelCostCapPerRunMicros)
	if err != nil {
		return inference.Money{}, err
	}
	// Estimate on the input side only; output length is unknown before the call.
	estimated := candidate.Model.EstimateCost(inference.Usage{InputTokens: estimateInputTokens(c.Request)})
	if ceiling <= 0 {
		return estimated, nil
	}
	if g.spend == nil {
		return estimated, nil
	}
	spent, err := g.spend.RunSpend(ctx, c.Request.RunID)
	if err != nil {
		return inference.Money{}, modberr.Wrap(err, modberr.CodeUnavailable,
			"could not read accumulated run spend; the cost cap could not be enforced").
			WithDetail("dependency", "spend_reporter")
	}
	if spent.Micros+estimated.Micros > ceiling {
		return inference.Money{}, modberr.Newf(modberr.CodeBudgetExhausted,
			"run spend %d plus estimated %d exceeds the per-run cap %d micros",
			spent.Micros, estimated.Micros, ceiling).
			WithDetail("budget_scope", "run")
	}
	return estimated, nil
}

// finish records metadata and assembles the result.
func (g *Gateway) finish(ctx context.Context, c Call, p prepared, candidate inference.Candidate,
	resp inference.Response, failovers []Failover, started time.Time) (Result, error) {

	// Losses from the policy clamp and from the adapter are merged: a caller weighing whether a
	// completion is adequate evidence needs both in one place.
	losses := append(append([]inference.Loss{}, p.policyLosses...), resp.Losses...)
	resp.Losses = losses

	call := g.buildCall(c, p, candidate, resp.FinishReason, resp.Usage, losses, failovers,
		started, resp.ModelRevision)

	result := Result{Response: resp, Call: call}
	if g.recorder != nil {
		// A recording failure does not invalidate a completion that already happened. Reporting it
		// separately lets the caller decide whether missing evidence blocks its completion contract
		// (INV-8) rather than having the gateway silently decide for it.
		result.RecordingErr = g.record(ctx, c, call, nil)
	}
	return result, nil
}

// record persists metadata and its canonical events together.
//
// Event construction failures are folded into the recording error rather than raised separately:
// from the caller's point of view both mean the same thing, that the evidence for this call is
// incomplete.
func (g *Gateway) record(ctx context.Context, c Call, call ModelCall, cause error) error {
	events, err := g.buildEvents(c, call, cause, g.sequenceAllocator(ctx, c.Request.RunID))
	if err != nil {
		return modberr.Wrap(err, modberr.CodeInternal, "build canonical events for the model call")
	}
	return g.recorder.Record(ctx, call, events)
}

// buildCall assembles model-call metadata.
//
// Complete and the streaming pump share it so a stream's evidence is structurally identical to a
// completion's. Divergence here would mean the same call recorded two different ways depending on
// which surface a caller happened to use.
func (g *Gateway) buildCall(c Call, p prepared, candidate inference.Candidate,
	finish inference.FinishReason, usage inference.Usage, losses []inference.Loss,
	failovers []Failover, started time.Time, observedRevision string) ModelCall {

	return ModelCall{
		ID:                 p.callID,
		OrganizationID:     c.OrganizationID,
		RunID:              c.Request.RunID,
		StepID:             c.Request.StepID,
		Alias:              c.Request.Alias,
		ProviderID:         candidate.Model.ProviderID,
		ModelID:            candidate.Model.ModelID,
		DeclaredRevision:   candidate.Model.Revision,
		ObservedRevision:   observedRevision,
		Classification:     p.classification,
		DLPFindings:        p.findings,
		Losses:             losses,
		Usage:              usage,
		Cost:               candidate.Model.EstimateCost(usage),
		EstimatedCost:      p.estimatedCost,
		FinishReason:       finish,
		Taint:              c.Taint,
		Failovers:          failovers,
		PolicyDecisionID:   c.PolicyDecisionID,
		SettingsSnapshotID: c.Settings.ID,
		StartedAt:          started,
		CompletedAt:        g.clock.Now(),
	}
}

func aliasPermitted(allowed []string, alias string) bool {
	for _, a := range allowed {
		if a == settings.Wildcard || a == alias {
			return true
		}
	}
	return false
}

// clampReasoning lowers effort to the ceiling, reporting whether it changed.
func clampReasoning(requested, ceiling inference.ReasoningEffort) (inference.ReasoningEffort, bool) {
	order := map[inference.ReasoningEffort]int{
		inference.ReasoningNone: 0, "": 0,
		inference.ReasoningLow: 1, inference.ReasoningMedium: 2, inference.ReasoningHigh: 3,
	}
	req, okReq := order[requested]
	ceil, okCeil := order[ceiling]
	if !okReq || !okCeil || req <= ceil {
		return requested, false
	}
	return ceiling, true
}

func firstRuleID(findings []Finding) string {
	for _, f := range findings {
		if f.Action == DecisionBlock {
			return f.RuleID
		}
	}
	if len(findings) > 0 {
		return findings[0].RuleID
	}
	return ""
}

// decorate attaches the policy decision to a routing error so an operator can join the refusal to
// the decision that produced the envelope.
func decorate(err error, decisionID id.ID) error {
	e, ok := modberr.As(err)
	if !ok || decisionID.IsZero() {
		return err
	}
	return e.WithDetail("policy_decision_id", decisionID.String())
}

// estimateInputTokens is a whitespace-based pre-call estimate. It is deliberately crude and
// deliberately only used for budget admission, never for billing, which uses provider-reported
// usage.
func estimateInputTokens(req inference.Request) int {
	total := 0
	for _, group := range [][]inference.Part{req.System, req.Developer} {
		for _, p := range group {
			total += len(p.Text) / 4
		}
	}
	for _, m := range req.Messages {
		for _, p := range m.Parts {
			total += len(p.Text) / 4
			if p.ToolResult != nil {
				for _, nested := range p.ToolResult.Parts {
					total += len(nested.Text) / 4
				}
			}
		}
	}
	if total == 0 {
		total = 1
	}
	return total
}
