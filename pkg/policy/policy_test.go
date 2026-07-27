package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/policy"
	"github.com/modbit/modbit/pkg/settings"
	"github.com/modbit/modbit/pkg/taint"
)

var (
	planApproved = time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	taintEntered = time.Date(2026, 7, 26, 11, 0, 0, 0, time.UTC)
	evaluatedAt  = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
)

// snapshot resolves the shipped contracts under the given session overrides and freezes the
// result. Building on the real registry means these tests fail if a contract edit changes a
// default that policy depends on.
func snapshot(t *testing.T, overrides map[settings.Key]any) settings.Snapshot {
	t.Helper()
	resolver, err := settings.NewResolver(settings.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	var layers []settings.Layer
	if len(overrides) > 0 {
		layers = append(layers, settings.Layer{
			Scope: settings.ScopeOrganization, SourceID: "test", Values: overrides,
		})
	}
	result, err := resolver.Resolve(layers)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, d := range result.Diagnostics {
		if d.Severity == settings.SeverityError {
			t.Fatalf("unexpected settings error in fixture: %s", d)
		}
	}
	snap, err := settings.NewSnapshot(result, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap
}

func evaluate(t *testing.T, req policy.Request) policy.Decision {
	t.Helper()
	if req.Now.IsZero() {
		req.Now = evaluatedAt
	}
	d, err := policy.NewEngine(nil).Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return d
}

// SFX-1: an operation that has not declared a side-effect class cannot be evaluated as harmless.
func TestUndeclaredSideEffectClassIsDenied(t *testing.T) {
	t.Parallel()
	d := evaluate(t, policy.Request{
		Operation: policy.Operation{Tool: "shell"},
		Settings:  snapshot(t, nil),
	})
	if d.Effect != policy.EffectDeny {
		t.Fatalf("effect = %q, want deny", d.Effect)
	}
	if !modberr.Is(d.Err(), modberr.CodePolicyDenied) {
		t.Errorf("error code = %q, want MODBIT_POLICY_DENIED", modberr.CodeOf(d.Err()))
	}
}

func TestDeniedToolIsRefusedRegardlessOfMode(t *testing.T) {
	t.Parallel()
	d := evaluate(t, policy.Request{
		Operation: policy.Operation{Tool: "shell", SideEffect: policy.PureReadOnly},
		Settings: snapshot(t, map[settings.Key]any{
			settings.KeyAgentToolsDenied:   []any{"shell"},
			settings.KeyAgentExecutionMode: "unrestricted",
		}),
	})
	if d.Effect != policy.EffectDeny {
		t.Fatalf("effect = %q, want deny", d.Effect)
	}
}

func TestToolOutsideTheAllowlistIsRefused(t *testing.T) {
	t.Parallel()
	base := snapshot(t, map[settings.Key]any{settings.KeyAgentToolsAllowed: []any{"read", "mcp.*"}})

	allowed := evaluate(t, policy.Request{
		Operation: policy.Operation{Tool: "mcp.search", SideEffect: policy.PureReadOnly},
		Settings:  base,
	})
	if allowed.Effect == policy.EffectDeny {
		t.Errorf("namespace wildcard should permit mcp.search, got %+v", allowed.Reasons)
	}

	refused := evaluate(t, policy.Request{
		Operation: policy.Operation{Tool: "shell", SideEffect: policy.PureReadOnly},
		Settings:  base,
	})
	if refused.Effect != policy.EffectDeny {
		t.Fatalf("effect = %q, want deny", refused.Effect)
	}
}

func TestBaseApprovalClassByModeAndSideEffect(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode  string
		class policy.SideEffectClass
		want  policy.ApprovalClass
	}{
		{"manual", policy.PureReadOnly, policy.ApprovalNone},
		{"manual", policy.WorkspaceReversible, policy.ApprovalSingle},
		{"allowlist", policy.WorkspaceReversible, policy.ApprovalNone},
		{"allowlist", policy.LocallyDestructive, policy.ApprovalSingle},
		{"auto-review", policy.WorkspaceReversible, policy.ApprovalNone},
		// PRD §12.2 assigns "approval and backup" to locally destructive work, so it gates.
		{"auto-review", policy.LocallyDestructive, policy.ApprovalSingle},
		{"auto-review", policy.ExternallyCompensatable, policy.ApprovalSingle},
		{"auto-review", policy.ExternallyIrreversible, policy.ApprovalTwoPerson},
		{"unrestricted", policy.LocallyDestructive, policy.ApprovalNone},
		// Auto Mode does not bypass policy: no mode makes an irreversible external action unattended.
		{"unrestricted", policy.ExternallyIrreversible, policy.ApprovalTwoPerson},
	}
	for _, tc := range tests {
		t.Run(tc.mode+"/"+tc.class.String(), func(t *testing.T) {
			t.Parallel()
			d := evaluate(t, policy.Request{
				Operation: policy.Operation{Tool: "shell", SideEffect: tc.class},
				Settings:  snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: tc.mode}),
			})
			if d.ApprovalClass != tc.want {
				t.Errorf("approval = %q, want %q (reasons: %+v)", d.ApprovalClass, tc.want, d.Reasons)
			}
		})
	}
}

func TestTwoPersonThresholdRaisesButNeverLowers(t *testing.T) {
	t.Parallel()
	raised := evaluate(t, policy.Request{
		Operation: policy.Operation{Tool: "shell", SideEffect: policy.LocallyDestructive},
		Settings: snapshot(t, map[settings.Key]any{
			settings.KeyAgentExecutionMode:              "auto-review",
			settings.KeyAgentApprovalTwoPersonThreshold: "locally_destructive",
		}),
	})
	if raised.ApprovalClass != policy.ApprovalTwoPerson {
		t.Errorf("approval = %q, want two_person", raised.ApprovalClass)
	}

	unaffected := evaluate(t, policy.Request{
		Operation: policy.Operation{Tool: "shell", SideEffect: policy.WorkspaceReversible},
		Settings: snapshot(t, map[settings.Key]any{
			settings.KeyAgentExecutionMode:              "auto-review",
			settings.KeyAgentApprovalTwoPersonThreshold: "locally_destructive",
		}),
	})
	if unaffected.ApprovalClass != policy.ApprovalNone {
		t.Errorf("approval = %q, want none", unaffected.ApprovalClass)
	}
}

// TNT-4 default managed policy.
func TestTaintEscalatesExternalOperations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		class     policy.SideEffectClass
		taintSet  taint.Set
		wantEscal bool
	}{
		{"web taint escalates compensatable", policy.ExternallyCompensatable, taint.NewSet(taint.Web), true},
		{"mcp taint escalates compensatable", policy.ExternallyCompensatable, taint.NewSet(taint.MCPResult), true},
		{"repository taint escalates compensatable", policy.ExternallyCompensatable, taint.NewSet(taint.RepositoryUntrusted), true},
		{"tool result alone does not escalate", policy.ExternallyCompensatable, taint.NewSet(taint.ToolResult), false},
		{"trusted context does not escalate", policy.ExternallyCompensatable, taint.NewSet(taint.UserTrusted), false},
		{"workspace edits are not escalated", policy.WorkspaceReversible, taint.NewSet(taint.Web), false},
		{"read-only is not escalated", policy.PureReadOnly, taint.NewSet(taint.MCPResult), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := evaluate(t, policy.Request{
				Operation:      policy.Operation{Tool: "github.comment", SideEffect: tc.class, Hash: "op-1"},
				Settings:       snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"}),
				Taint:          tc.taintSet,
				TaintEnteredAt: map[taint.Class]time.Time{taint.Web: taintEntered, taint.MCPResult: taintEntered, taint.RepositoryUntrusted: taintEntered},
			})
			escalated := d.EscalatedFrom != nil
			if escalated != tc.wantEscal {
				t.Fatalf("escalated = %t, want %t (approval %q, reasons %+v)", escalated, tc.wantEscal, d.ApprovalClass, d.Reasons)
			}
			if tc.wantEscal && !modberr.Is(d.Err(), modberr.CodeTaintEscalationRequired) {
				t.Errorf("error code = %q, want MODBIT_TAINT_ESCALATION_REQUIRED", modberr.CodeOf(d.Err()))
			}
		})
	}
}

// The TNT-4 carve-out: declared before the taint entered exempts; declared after does not.
func TestPlanDeclarationCarveOutDependsOnOrdering(t *testing.T) {
	t.Parallel()
	base := policy.Request{
		Operation:      policy.Operation{Tool: "github.comment", SideEffect: policy.ExternallyCompensatable, Hash: "op-1"},
		Settings:       snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"}),
		Taint:          taint.NewSet(taint.Web),
		TaintEnteredAt: map[taint.Class]time.Time{taint.Web: taintEntered},
	}

	before := base
	before.PlanDeclarations = []policy.PlanDeclaration{{Hash: "op-1", DeclaredAt: planApproved}}
	if d := evaluate(t, before); d.EscalatedFrom != nil {
		t.Errorf("an operation declared before the taint entered must not escalate: %+v", d.Reasons)
	}

	after := base
	after.PlanDeclarations = []policy.PlanDeclaration{{Hash: "op-1", DeclaredAt: taintEntered.Add(time.Minute)}}
	if d := evaluate(t, after); d.EscalatedFrom == nil {
		t.Error("an operation declared after the taint entered must escalate")
	}

	// A declaration for a different operation must not transfer.
	other := base
	other.PlanDeclarations = []policy.PlanDeclaration{{Hash: "some-other-op", DeclaredAt: planApproved}}
	if d := evaluate(t, other); d.EscalatedFrom == nil {
		t.Error("a declaration for a different operation hash must not exempt this one")
	}
}

func TestPlanCarveOutCanBeDisabledButNotWidened(t *testing.T) {
	t.Parallel()
	req := policy.Request{
		Operation: policy.Operation{Tool: "github.comment", SideEffect: policy.ExternallyCompensatable, Hash: "op-1"},
		Settings: snapshot(t, map[settings.Key]any{
			settings.KeyAgentExecutionMode:                    "auto-review",
			settings.KeyTaintPlanDeclarationExemptsEscalation: false,
		}),
		Taint:            taint.NewSet(taint.Web),
		TaintEnteredAt:   map[taint.Class]time.Time{taint.Web: taintEntered},
		PlanDeclarations: []policy.PlanDeclaration{{Hash: "op-1", DeclaredAt: planApproved}},
	}
	if d := evaluate(t, req); d.EscalatedFrom == nil {
		t.Error("with the carve-out disabled, a prior declaration must not exempt the operation")
	}
}

// Adversarial suite (TNT-7). Each case is an attempt to reach a high-risk operation through
// tainted context; each must be escalated or denied.
func TestSecurityTaintBypassAttemptsAreRefused(t *testing.T) {
	t.Parallel()
	base := snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"})

	t.Run("injection in a repository file cannot reach an irreversible operation unattended", func(t *testing.T) {
		t.Parallel()
		d := evaluate(t, policy.Request{
			Operation:      policy.Operation{Tool: "npm.publish", SideEffect: policy.ExternallyIrreversible, Hash: "publish"},
			Settings:       base,
			Taint:          taint.NewSet(taint.RepositoryUntrusted),
			TaintEnteredAt: map[taint.Class]time.Time{taint.RepositoryUntrusted: taintEntered},
		})
		if d.Effect != policy.EffectRequireApproval || d.ApprovalClass != policy.ApprovalTwoPerson {
			t.Fatalf("effect %q approval %q, want require_approval/two_person", d.Effect, d.ApprovalClass)
		}
	})

	t.Run("laundering through a summary keeps the escalation", func(t *testing.T) {
		t.Parallel()
		// The summary carries the propagated class, so the policy input is identical to the raw
		// fetched page. This asserts the policy layer honours what taint.Derive produced.
		laundered := taint.Propagate(taint.Web, taint.Generated)
		d := evaluate(t, policy.Request{
			Operation:      policy.Operation{Tool: "github.comment", SideEffect: policy.ExternallyCompensatable, Hash: "comment"},
			Settings:       base,
			Taint:          taint.NewSet(laundered),
			TaintEnteredAt: map[taint.Class]time.Time{laundered: taintEntered},
		})
		if d.EscalatedFrom == nil {
			t.Fatalf("laundered web content must still escalate, reasons: %+v", d.Reasons)
		}
	})

	t.Run("an operation with no hash cannot claim a plan exemption", func(t *testing.T) {
		t.Parallel()
		d := evaluate(t, policy.Request{
			Operation:        policy.Operation{Tool: "github.comment", SideEffect: policy.ExternallyCompensatable},
			Settings:         base,
			Taint:            taint.NewSet(taint.Web),
			TaintEnteredAt:   map[taint.Class]time.Time{taint.Web: taintEntered},
			PlanDeclarations: []policy.PlanDeclaration{{Hash: "", DeclaredAt: planApproved}},
		})
		if d.EscalatedFrom == nil {
			t.Fatal("an unhashed operation must not match a plan declaration")
		}
	})

	t.Run("an unknown taint entry time denies the exemption", func(t *testing.T) {
		t.Parallel()
		// TaintEnteredAt is empty: the ledger could not prove when the taint arrived, so the
		// carve-out must not apply.
		d := evaluate(t, policy.Request{
			Operation:        policy.Operation{Tool: "github.comment", SideEffect: policy.ExternallyCompensatable, Hash: "comment"},
			Settings:         base,
			Taint:            taint.NewSet(taint.Web),
			PlanDeclarations: []policy.PlanDeclaration{{Hash: "comment", DeclaredAt: planApproved}},
		})
		if d.EscalatedFrom == nil {
			t.Fatal("without a provable taint entry time the exemption must be refused")
		}
	})

	t.Run("unrestricted mode does not dissolve taint escalation for irreversible work", func(t *testing.T) {
		t.Parallel()
		d := evaluate(t, policy.Request{
			Operation:      policy.Operation{Tool: "cloud.delete", SideEffect: policy.ExternallyIrreversible, Hash: "delete"},
			Settings:       snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "unrestricted"}),
			Taint:          taint.NewSet(taint.MCPResult),
			TaintEnteredAt: map[taint.Class]time.Time{taint.MCPResult: taintEntered},
		})
		if d.ApprovalClass != policy.ApprovalTwoPerson || d.Effect != policy.EffectRequireApproval {
			t.Fatalf("effect %q approval %q, want require_approval/two_person", d.Effect, d.ApprovalClass)
		}
	})
}

func TestDisablingTaintEnforcementIsRecordedRatherThanSilent(t *testing.T) {
	t.Parallel()
	d := evaluate(t, policy.Request{
		Operation: policy.Operation{Tool: "github.comment", SideEffect: policy.ExternallyCompensatable, Hash: "op"},
		Settings: snapshot(t, map[settings.Key]any{
			settings.KeyAgentExecutionMode:      "auto-review",
			settings.KeyTaintEnforcementEnabled: false,
		}),
		Taint:          taint.NewSet(taint.Web),
		TaintEnteredAt: map[taint.Class]time.Time{taint.Web: taintEntered},
	})
	if d.EscalatedFrom != nil {
		t.Error("escalation must not apply when enforcement is disabled")
	}
	var found bool
	for _, r := range d.Reasons {
		if r.Code == policy.ReasonTaintDisabled {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a taint_enforcement_disabled reason, got %+v", d.Reasons)
	}
}

func TestDecisionCarriesNoSensitiveDetail(t *testing.T) {
	t.Parallel()
	d := evaluate(t, policy.Request{
		Operation:      policy.Operation{Tool: "github.comment", SideEffect: policy.ExternallyCompensatable, Hash: "op"},
		Settings:       snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"}),
		Taint:          taint.NewSet(taint.Web),
		TaintEnteredAt: map[taint.Class]time.Time{taint.Web: taintEntered},
	})
	err, ok := modberr.As(d.Err())
	if !ok {
		t.Fatal("decision error should be a Modbit error")
	}
	// R-ERR-02: only allowlisted detail keys survive. A rejected key would appear in the reserved
	// diagnostic entry instead.
	if dropped, present := err.Details()["unregistered_detail_keys"]; present {
		t.Errorf("decision attached unregistered detail keys: %s", dropped)
	}
}

func TestEvaluateHonoursContextCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := policy.NewEngine(nil).Evaluate(ctx, policy.Request{
		Operation: policy.Operation{Tool: "read", SideEffect: policy.PureReadOnly},
		Settings:  snapshot(t, nil),
	})
	if !modberr.Is(err, modberr.CodeCancelled) {
		t.Fatalf("error = %v, want MODBIT_CANCELLED", err)
	}
}

// Every rung of the approval ladder must be a materially stronger gate than the one below it.
// A rung that permits the operation would make a TNT-4 escalation decorative in exactly the
// configuration where it matters most: unrestricted mode, where external work starts ungated.
func TestEveryEscalationStepIsARealGate(t *testing.T) {
	t.Parallel()

	// Under unrestricted mode an externally compensatable operation is ungated until taint arrives.
	ungated := evaluate(t, policy.Request{
		Operation: policy.Operation{Tool: "github.comment", SideEffect: policy.ExternallyCompensatable, Hash: "op"},
		Settings:  snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "unrestricted"}),
	})
	if ungated.Effect != policy.EffectAllow || ungated.ApprovalClass != policy.ApprovalNone {
		t.Fatalf("baseline = %q/%q, want allow/none", ungated.Effect, ungated.ApprovalClass)
	}

	escalated := evaluate(t, policy.Request{
		Operation:      policy.Operation{Tool: "github.comment", SideEffect: policy.ExternallyCompensatable, Hash: "op"},
		Settings:       snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "unrestricted"}),
		Taint:          taint.NewSet(taint.Web),
		TaintEnteredAt: map[taint.Class]time.Time{taint.Web: taintEntered},
	})
	if escalated.Effect != policy.EffectRequireApproval {
		t.Fatalf("escalated effect = %q, want require_approval — escalation must gate, not merely notify", escalated.Effect)
	}
	if escalated.ApprovalClass != policy.ApprovalSingle {
		t.Errorf("escalated approval = %q, want single_approver", escalated.ApprovalClass)
	}
}

// Effect and ApprovalClass must never disagree: anything above ApprovalNone gates, and
// ApprovalNone allows.
func TestEffectAndApprovalClassAgree(t *testing.T) {
	t.Parallel()
	modes := []string{"manual", "allowlist", "auto-review", "unrestricted"}
	classes := []policy.SideEffectClass{
		policy.PureReadOnly, policy.WorkspaceReversible, policy.LocallyDestructive,
		policy.ExternallyCompensatable, policy.ExternallyIrreversible,
	}
	for _, mode := range modes {
		for _, class := range classes {
			d := evaluate(t, policy.Request{
				Operation: policy.Operation{Tool: "shell", SideEffect: class, Hash: "op"},
				Settings:  snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: mode}),
			})
			wantAllow := d.ApprovalClass == policy.ApprovalNone
			gotAllow := d.Effect == policy.EffectAllow
			if wantAllow != gotAllow {
				t.Errorf("%s/%s: effect %q disagrees with approval class %q", mode, class, d.Effect, d.ApprovalClass)
			}
		}
	}
}

// An unnameable approval class must render as the strictest rung rather than silently reading as
// a permissive one.
func TestUnknownApprovalClassRendersAsStrictest(t *testing.T) {
	t.Parallel()
	if got := policy.ApprovalClass(200).String(); got != "two_person" {
		t.Errorf("String = %q, want two_person", got)
	}
}

// Sink controls answer a different question from the approval ladder: not "how much sign-off does
// this need" but "should this content reach this destination at all". Adopted under ADR-0100.
func TestSecurityKnownSecretCannotReachAnExternalSink(t *testing.T) {
	t.Parallel()
	base := snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"})

	denied := []policy.Sink{
		policy.SinkModelPrompt, policy.SinkNetworkEgress,
		policy.SinkSourceControl, policy.SinkMemoryWrite, policy.SinkArtifactExport,
	}
	for _, sink := range denied {
		t.Run("denied at "+sink.String(), func(t *testing.T) {
			t.Parallel()
			d := evaluate(t, policy.Request{
				Operation: policy.Operation{
					Tool: "github.comment", SideEffect: policy.ExternallyCompensatable,
					Hash: "op", Sink: sink,
				},
				Settings: base,
				Taint:    taint.NewSet(taint.KnownSecret),
			})
			if d.Effect != policy.EffectDeny {
				t.Fatalf("effect = %q, want deny — no approval class makes a credential at %s acceptable",
					d.Effect, sink)
			}
			var found bool
			for _, r := range d.Reasons {
				if r.Code == policy.ReasonSecretAtSink {
					found = true
				}
			}
			if !found {
				t.Errorf("reasons = %+v, want a secret_at_sink reason", d.Reasons)
			}
		})
	}
}

// A secret reaching a tool argument is often the point — a broker handing a leased credential to
// the operation that needs it. That path is governed by the Task Secret contract, not by taint
// confinement, so it is deliberately not denied here.
func TestKnownSecretIsNotBlockedAtAToolArgument(t *testing.T) {
	t.Parallel()
	d := evaluate(t, policy.Request{
		Operation: policy.Operation{
			Tool: "deploy", SideEffect: policy.ExternallyCompensatable,
			Hash: "op", Sink: policy.SinkToolArgument,
		},
		Settings: snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"}),
		Taint:    taint.NewSet(taint.KnownSecret),
	})
	if d.Effect == policy.EffectDeny {
		t.Fatalf("a tool argument must not be denied by the secret sink rule: %+v", d.Reasons)
	}
}

func TestSinkDenialPrecedesTheApprovalLadder(t *testing.T) {
	t.Parallel()
	// Even with a valid two-person approval in hand, a secret must not reach an external sink.
	op := policy.Operation{
		Tool: "github.comment", SideEffect: policy.ExternallyCompensatable,
		Hash: "op", Sink: policy.SinkSourceControl,
	}
	d := evaluate(t, policy.Request{
		Operation: op,
		Settings:  snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"}),
		Taint:     taint.NewSet(taint.KnownSecret),
		Approval: &policy.ApprovalBinding{
			ID: id.MustNew(id.Approval), OperationHash: "op",
			ApprovalClass: policy.ApprovalTwoPerson,
			Approvers:     []string{"usr_a", "usr_b"},
			ExpiresAt:     evaluatedAt.Add(time.Hour),
		},
	})
	if d.Effect != policy.EffectDeny {
		t.Fatalf("effect = %q, want deny even with an approval present", d.Effect)
	}
}

func TestSinkParsing(t *testing.T) {
	t.Parallel()
	if s, err := policy.ParseSink("network_egress"); err != nil || s != policy.SinkNetworkEgress {
		t.Errorf("ParseSink = %v, %v", s, err)
	}
	if _, err := policy.ParseSink("carrier_pigeon"); err == nil {
		t.Error("an unrecognized sink must be an error, not a default")
	}
}

func validBinding(op policy.Operation) *policy.ApprovalBinding {
	return &policy.ApprovalBinding{
		ID:            id.MustNew(id.Approval),
		OperationHash: op.Hash,
		Scope:         op.Scope,
		ApprovalClass: policy.ApprovalSingle,
		Approvers:     []string{"usr_alice"},
		FenceEpoch:    op.FenceEpoch,
		ExpiresAt:     evaluatedAt.Add(time.Hour),
	}
}

// SFX-3/SFX-4 plus the fence epoch adopted under ADR-0100.
func TestApprovalBindingInvalidation(t *testing.T) {
	t.Parallel()
	op := policy.Operation{
		Tool: "github.comment", SideEffect: policy.ExternallyCompensatable,
		Hash: "op-1", Scope: "repo_a", FenceEpoch: 7,
	}

	if err := validBinding(op).Check(op, evaluatedAt); err != nil {
		t.Fatalf("a matching binding was rejected: %v", err)
	}

	t.Run("a changed operation invalidates", func(t *testing.T) {
		t.Parallel()
		changed := op
		changed.Hash = "op-2"
		if err := validBinding(op).Check(changed, evaluatedAt); !modberr.Is(err, modberr.CodeApprovalInvalidated) {
			t.Fatalf("error = %v, want MODBIT_APPROVAL_INVALIDATED", err)
		}
	})

	t.Run("a changed scope invalidates", func(t *testing.T) {
		t.Parallel()
		changed := op
		changed.Scope = "repo_b"
		if err := validBinding(op).Check(changed, evaluatedAt); !modberr.Is(err, modberr.CodeApprovalInvalidated) {
			t.Fatalf("error = %v, want MODBIT_APPROVAL_INVALIDATED", err)
		}
	})

	// The case the fence epoch exists for: the lease was reassigned, so a second worker computed
	// the same operation hash and would otherwise execute against its predecessor's approval.
	t.Run("a reassigned lease invalidates", func(t *testing.T) {
		t.Parallel()
		reassigned := op
		reassigned.FenceEpoch = 8
		err := validBinding(op).Check(reassigned, evaluatedAt)
		if !modberr.Is(err, modberr.CodeApprovalInvalidated) {
			t.Fatalf("error = %v, want MODBIT_APPROVAL_INVALIDATED", err)
		}
		e, _ := modberr.As(err)
		if e.Details()["fence_epoch"] != "7" {
			t.Errorf("details = %v, want the approved epoch reported", e.Details())
		}
		if dropped, present := e.Details()["unregistered_detail_keys"]; present {
			t.Errorf("approval error attached unallowlisted keys: %s", dropped)
		}
	})

	// An expired approval is not a denial: the operation is still permissible, it needs asking again.
	t.Run("expiry requires a fresh approval rather than denying", func(t *testing.T) {
		t.Parallel()
		b := validBinding(op)
		b.ExpiresAt = evaluatedAt.Add(-time.Minute)
		if err := b.Check(op, evaluatedAt); !modberr.Is(err, modberr.CodeApprovalRequired) {
			t.Fatalf("error = %v, want MODBIT_APPROVAL_REQUIRED", err)
		}
	})

	t.Run("two-person requires two distinct approvers", func(t *testing.T) {
		t.Parallel()
		b := validBinding(op)
		b.ApprovalClass = policy.ApprovalTwoPerson
		b.Approvers = []string{"usr_alice", "usr_alice"}
		if err := b.Check(op, evaluatedAt); !modberr.Is(err, modberr.CodeApprovalInvalidated) {
			t.Fatalf("error = %v, want the duplicate approver rejected", err)
		}
	})

	t.Run("an unhashed operation cannot be bound", func(t *testing.T) {
		t.Parallel()
		unhashed := op
		unhashed.Hash = ""
		if err := validBinding(op).Check(unhashed, evaluatedAt); err == nil {
			t.Error("an operation with no hash must not match any approval")
		}
	})
}

func TestSatisfiedApprovalResolvesToAllow(t *testing.T) {
	t.Parallel()
	op := policy.Operation{
		Tool: "github.comment", SideEffect: policy.ExternallyCompensatable,
		Hash: "op-1", Scope: "repo_a", FenceEpoch: 3, Sink: policy.SinkSourceControl,
	}
	snap := snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"})

	// Without an approval the operation gates.
	if d := evaluate(t, policy.Request{Operation: op, Settings: snap}); d.Effect != policy.EffectRequireApproval {
		t.Fatalf("effect = %q, want require_approval", d.Effect)
	}

	// With a matching single-approver grant it proceeds.
	d := evaluate(t, policy.Request{Operation: op, Settings: snap, Approval: validBinding(op)})
	if d.Effect != policy.EffectAllow {
		t.Fatalf("effect = %q, want allow (reasons %+v)", d.Effect, d.Reasons)
	}
}

// A presented-but-invalid approval is reported rather than ignored: silently falling back to
// "approval required" would hide that a stale grant was attempted.
func TestStaleApprovalIsReportedNotSilentlyIgnored(t *testing.T) {
	t.Parallel()
	op := policy.Operation{
		Tool: "github.comment", SideEffect: policy.ExternallyCompensatable,
		Hash: "op-1", FenceEpoch: 3,
	}
	stale := validBinding(op)
	stale.FenceEpoch = 99

	d := evaluate(t, policy.Request{
		Operation: op,
		Settings:  snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"}),
		Approval:  stale,
	})
	if d.Effect != policy.EffectRequireApproval {
		t.Fatalf("effect = %q, want require_approval", d.Effect)
	}
	var found bool
	for _, r := range d.Reasons {
		if r.Code == policy.ReasonApprovalInvalid {
			found = true
		}
	}
	if !found {
		t.Errorf("reasons = %+v, want an approval_invalid reason", d.Reasons)
	}
}

// An approval below the required class must not satisfy it.
func TestUnderpoweredApprovalDoesNotSatisfy(t *testing.T) {
	t.Parallel()
	op := policy.Operation{
		Tool: "npm.publish", SideEffect: policy.ExternallyIrreversible, Hash: "op-1",
	}
	single := validBinding(op) // ApprovalSingle

	d := evaluate(t, policy.Request{
		Operation: op,
		Settings:  snapshot(t, map[settings.Key]any{settings.KeyAgentExecutionMode: "auto-review"}),
		Approval:  single,
	})
	if d.Effect != policy.EffectRequireApproval || d.ApprovalClass != policy.ApprovalTwoPerson {
		t.Fatalf("effect %q class %q, want require_approval/two_person", d.Effect, d.ApprovalClass)
	}
}
