package capability_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/capability"
	"github.com/modbit/modbit/pkg/modberr"
)

// LCD invariants (C1–C8). One test each; a test without a C-number, or a C-number without a test,
// is a gap.
//
//	C1 The published matrix covers all ten features for every mode.
//	C2 A mode that forbids hosted inference never yields a hosted-backed capability.
//	C3 Degradation is never silent: any outcome short of full carries a reason.
//	C4 An unknown mode is refused rather than defaulted.
//	C5 A negotiated set is complete; a missing feature is refused, not read as unavailable.
//	C6 The zero Support is unavailable, so an unconsidered feature cannot read as usable.
//	C7 A model is placed in the highest tier it satisfies on *every* dimension.
//	C8 A negotiated set survives a snapshot round trip unchanged (LCD-5).

// C1. LCD-1 requires a published matrix over all ten features for every operating mode.
func TestPublishedMatrixCoversEveryFeatureAndMode(t *testing.T) {
	if len(capability.Features()) != 10 {
		t.Fatalf("LCD-1 names ten features, the package declares %d", len(capability.Features()))
	}
	for _, mode := range capability.Modes() {
		set, err := capability.Published(mode)
		if err != nil {
			t.Fatalf("Published(%s): %v", mode, err)
		}
		if err := set.Validate(); err != nil {
			t.Errorf("Published(%s) is not valid: %v", mode, err)
		}
		for _, f := range capability.Features() {
			if _, ok := set.Outcome(f); !ok {
				t.Errorf("Published(%s) omits %s", mode, f)
			}
		}
	}
}

// C2. A mode whose boundary forbids hosted inference must not produce a hosted-backed capability,
// even when a hosted model is reachable.
//
// This is the case where the network and the policy disagree. §8A.1 makes Local Private and Offline
// device-only; if a reachable hosted endpoint could raise their capabilities, topology would
// override a declared boundary and LCL-4's zero-egress qualification would be unprovable.
func TestSecurityADeviceOnlyModeIgnoresAReachableHostedModel(t *testing.T) {
	reachable := capability.Available{Hosted: true} // no local models at all

	for _, mode := range []capability.Mode{capability.ModeLocalPrivate, capability.ModeOffline} {
		set, err := capability.Negotiate(mode, reachable)
		if err != nil {
			t.Fatalf("Negotiate(%s): %v", mode, err)
		}
		for _, o := range set.Outcomes {
			if o.Support.Usable() {
				t.Errorf("%s reported %s as %s with no local model and hosted inference forbidden",
					mode, o.Feature, o.Support)
			}
		}
		// And the reason must name the boundary, not the missing model, or an operator reading it
		// would go install a model and still be refused.
		if got, _ := set.Outcome(capability.FeatureAsk); !strings.Contains(got.Reason, "device") {
			t.Errorf("%s: reason %q does not explain the boundary", mode, got.Reason)
		}
	}
}

// C3. LCD-3 prohibits silent degradation, so an outcome short of full without a reason must be
// unrepresentable rather than merely discouraged.
func TestSecurityDegradationCannotBeSilent(t *testing.T) {
	for _, support := range []capability.Support{capability.SupportDegraded, capability.SupportUnavailable} {
		bad := capability.Outcome{Feature: capability.FeatureCode, Support: support}
		if err := bad.Validate(); err == nil {
			t.Fatalf("a %s outcome with no reason was accepted; LCD-3 forbids silent degradation", support)
		}
		if err := bad.Validate(); !modberr.Is(err, modberr.CodeInvalidArgument) {
			t.Fatalf("err = %v, want CodeInvalidArgument", err)
		}
	}

	// The converse: a full outcome must not carry a stale reason, which would disclose a
	// degradation that is not happening.
	stale := capability.Outcome{
		Feature: capability.FeatureCode, Support: capability.SupportFull, Reason: "left over",
	}
	if err := stale.Validate(); err == nil {
		t.Fatal("a fully supported outcome carrying a degradation reason was accepted")
	}
}

// Every degradation any mode can produce carries a usable explanation.
//
// C3 proves the rule holds for a hand-built outcome. This proves `Negotiate` obeys it across every
// mode and a spread of device configurations — the path that actually populates a run snapshot.
func TestSecurityEveryNegotiatedDegradationExplainsItself(t *testing.T) {
	devices := []capability.Available{
		{},
		{Hosted: true},
		{Local: []capability.LocalModel{weakModel()}},
		{Local: []capability.LocalModel{midModel()}},
		{Local: []capability.LocalModel{strongModel()}},
		{Hosted: true, Local: []capability.LocalModel{weakModel()}},
	}
	for _, mode := range capability.Modes() {
		for i, device := range devices {
			set, err := capability.Negotiate(mode, device)
			if err != nil {
				t.Fatalf("Negotiate(%s, device %d): %v", mode, i, err)
			}
			for _, o := range set.Degradations() {
				if strings.TrimSpace(o.Reason) == "" {
					t.Errorf("%s device %d: %s is %s with no reason", mode, i, o.Feature, o.Support)
				}
				// A reason that merely restates the level explains nothing to the user reading it.
				if o.Reason == string(o.Support) || len(o.Reason) < 20 {
					t.Errorf("%s device %d: %s reason is not an explanation: %q",
						mode, i, o.Feature, o.Reason)
				}
			}
		}
	}
}

// C4. An unknown mode is refused rather than defaulted.
//
// Defaulting would pick an egress posture on the caller's behalf, which is the one decision a
// capability negotiator must never make quietly.
func TestAnUnknownModeIsRefused(t *testing.T) {
	if _, err := capability.Negotiate("not_a_mode", capability.Available{Hosted: true}); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
	if _, err := capability.Published("not_a_mode"); err == nil {
		t.Fatal("an unknown mode produced a published matrix")
	}
}

// C5. An incomplete set is refused, because a caller cannot tell "unavailable" from "not
// considered" once a feature is simply missing.
func TestAnIncompleteSetIsRefused(t *testing.T) {
	partial := capability.Set{
		Mode: capability.ModeOffline,
		Outcomes: []capability.Outcome{
			{Feature: capability.FeatureAsk, Support: capability.SupportFull},
		},
	}
	if err := partial.Validate(); err == nil {
		t.Fatal("a set covering one of ten features validated")
	}

	// A duplicated feature is refused for the same reason: two answers is no answer.
	full, err := capability.Negotiate(capability.ModeLocalHybrid, capability.Available{Hosted: true})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	dup := full
	dup.Outcomes = append(append([]capability.Outcome{}, full.Outcomes...), full.Outcomes[0])
	if err := dup.Validate(); err == nil {
		t.Fatal("a set with a duplicated feature validated")
	}
}

// C6. The zero Support is unavailable, so a feature nobody considered cannot read as usable.
//
// The same reasoning as sandbox.EnforcementUnsupported and taint's unknown class: the only safe
// reading of no answer is the most restrictive one.
func TestTheZeroSupportIsUnavailable(t *testing.T) {
	var unset capability.Support
	if unset != capability.SupportUnavailable {
		t.Fatalf("the zero Support is %q, want unavailable", unset)
	}
	if unset.Usable() {
		t.Fatal("the zero Support reports itself usable")
	}
	// And reading a feature out of an empty set yields it rather than a panic or a false positive.
	if (capability.Set{}).Support(capability.FeatureCode).Usable() {
		t.Fatal("an empty set reported a usable feature")
	}
}

// C7. A model is placed in the highest tier it satisfies on every dimension, not the easiest one.
//
// Context length is the dimension a model advertises and the one least likely to be wrong. Tool-call
// reliability is what actually decides whether the agentic loop terminates, and latency is what
// decides whether tab completion is a completion. A model strong on context and weak on either of
// the others must not be promoted on the strength of the number that is easy to publish.
func TestTierPlacementRequiresEveryDimension(t *testing.T) {
	bigButUnreliable := capability.LocalModel{
		ID: "big-unreliable", ContextTokens: 200000,
		ToolCallReliability: 0.5, FirstTokenLatency: 100 * time.Millisecond,
	}
	tier, ok := bigButUnreliable.Tier()
	if !ok {
		t.Fatal("a model with a large context met no tier at all")
	}
	if tier.Name != capability.TierMinimal.Name {
		t.Fatalf("tier = %s, want minimal: a 200k-context model with 50%% tool reliability "+
			"must not be promoted on context alone", tier.Name)
	}

	bigButSlow := capability.LocalModel{
		ID: "big-slow", ContextTokens: 200000,
		ToolCallReliability: 0.99, FirstTokenLatency: 10 * time.Second,
	}
	if tier, _ := bigButSlow.Tier(); tier.Name == capability.TierFull.Name {
		t.Fatal("a model 12x over the latency budget was placed in the full tier")
	}
}

// C8. A negotiated set survives the round trip a run snapshot performs (LCD-5).
//
// LCD-5 freezes the set for the life of the run, which means it is serialized and read back. A
// reason lost in transit turns a disclosed degradation into a silent one at exactly the moment
// LCD-3 is being satisfied.
func TestANegotiatedSetSurvivesASnapshotRoundTrip(t *testing.T) {
	original, err := capability.Negotiate(capability.ModeOffline,
		capability.Available{Local: []capability.LocalModel{midModel()}})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if len(original.Degradations()) == 0 {
		t.Fatal("the fixture produced no degradations, so the round trip proves nothing")
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var restored capability.Set
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatalf("the restored set is not valid: %v", err)
	}
	if len(restored.Degradations()) != len(original.Degradations()) {
		t.Fatalf("degradations = %d after the round trip, want %d",
			len(restored.Degradations()), len(original.Degradations()))
	}
	for i, o := range restored.Degradations() {
		if o.Reason != original.Degradations()[i].Reason {
			t.Fatalf("%s lost its reason across the round trip", o.Feature)
		}
	}
}

// A stronger device never yields a weaker capability set.
//
// Monotonicity is not stated as a requirement, and it is the property a user assumes: installing a
// better model must not withdraw a feature. A negotiation that violated it would be defensible line
// by line and incomprehensible in use.
func TestABetterModelNeverWithdrawsAFeature(t *testing.T) {
	for _, mode := range capability.Modes() {
		weak, err := capability.Negotiate(mode, capability.Available{
			Local: []capability.LocalModel{weakModel()}})
		if err != nil {
			t.Fatalf("Negotiate(%s, weak): %v", mode, err)
		}
		strong, err := capability.Negotiate(mode, capability.Available{
			Local: []capability.LocalModel{strongModel()}})
		if err != nil {
			t.Fatalf("Negotiate(%s, strong): %v", mode, err)
		}
		for _, f := range capability.Features() {
			if weak.Support(f).Usable() && !strong.Support(f).Usable() {
				t.Errorf("%s: %s is usable on the weak model and not on the strong one", mode, f)
			}
		}
	}
}

func weakModel() capability.LocalModel {
	return capability.LocalModel{
		ID: "weak", ContextTokens: 8192,
		ToolCallReliability: 0.5, FirstTokenLatency: 3 * time.Second,
	}
}

func midModel() capability.LocalModel {
	return capability.LocalModel{
		ID: "mid", ContextTokens: 32768,
		ToolCallReliability: 0.92, FirstTokenLatency: 1500 * time.Millisecond,
	}
}

func strongModel() capability.LocalModel {
	return capability.LocalModel{
		ID: "strong", ContextTokens: 128000,
		ToolCallReliability: 0.99, FirstTokenLatency: 500 * time.Millisecond,
	}
}
