package memory_test

import (
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/memory"
)

// MEM invariants (M1–M9). One test each; a test without an M-number, or an M-number without a test,
// is a gap.
//
//	M1 MEM-2: a single trajectory never promotes automatically.
//	M2 MEM-2: corroboration counts distinct runs, so one run repeating itself is one trajectory.
//	M3 MEM-1: Tier B never promotes automatically, at any corroboration count.
//	M4 The zero Tier is behavioural, so an unclassified memory cannot reach the automatic path.
//	M5 MEM-2: policy may tighten the threshold and may not lower it below two.
//	M6 MEM-6: a disabled scope outranks corroboration.
//	M7 MEM-3: a corroboration with no evidence is not a provenance link.
//	M8 MEM-4: every decision carries a reason, so a withheld memory is inspectable.
//	M9 MEM-5: retirement is recorded, not deleted, and a retired memory does not apply.

func corroborations(n int) []memory.Corroboration {
	out := make([]memory.Corroboration, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, memory.Corroboration{
			RunID: id.MustNew(id.Run), EvidenceRef: "run-log#build-flag", ObservedAt: time.Now(),
		})
	}
	return out
}

func operational(n int) memory.Memory {
	return memory.Memory{
		ID: id.MustNew(id.Memory), Tier: memory.TierOperational, Scope: memory.ScopeRepository,
		OwnerID: id.MustNew(id.Repository), Claim: "tests need -tags=integration",
		State: memory.StateActive, Corroborations: corroborations(n),
	}
}

// M1. MEM-2: "A single trajectory never changes behavior automatically."
func TestSecurityASingleTrajectoryNeverPromotes(t *testing.T) {
	d, err := memory.MayApplyAutomatically(operational(1), memory.Policy{})
	if err != nil {
		t.Fatalf("MayApplyAutomatically: %v", err)
	}
	if d.Apply {
		t.Fatal("one trajectory promoted a memory automatically; MEM-2 forbids it outright")
	}
	if d.Reason == "" {
		t.Fatal("a refusal carries no reason")
	}
}

// M2. Corroboration counts distinct trajectories, not observations.
//
// This is the failure wearing the disguise of the fix: one run that retried three times produces
// three confirmations from a single source. Counting occurrences would promote its own guess.
func TestSecurityOneRunRepeatingItselfIsOneTrajectory(t *testing.T) {
	single := id.MustNew(id.Run)
	m := operational(0)
	for i := 0; i < 5; i++ {
		m.Corroborations = append(m.Corroborations, memory.Corroboration{
			RunID: single, EvidenceRef: "run-log#retry", ObservedAt: time.Now(),
		})
	}

	if got := m.IndependentTrajectories(); got != 1 {
		t.Fatalf("trajectories = %d for five observations of one run, want 1", got)
	}
	d, err := memory.MayApplyAutomatically(m, memory.Policy{})
	if err != nil {
		t.Fatalf("MayApplyAutomatically: %v", err)
	}
	if d.Apply {
		t.Fatal("one run corroborating itself five times promoted a memory")
	}
}

// M3. MEM-1 reserves Tier B promotion for explicit human review; no corroboration count substitutes.
//
// A wrong operational memory fails the next build visibly. A wrong behavioural memory produces
// confident work that is subtly off, which no test catches — so there is no threshold at which
// automatic promotion becomes safe.
func TestSecurityBehaviouralMemoryNeverPromotesAutomatically(t *testing.T) {
	m := operational(50) // fifty independent trajectories
	m.Tier = memory.TierBehavioral

	d, err := memory.MayApplyAutomatically(m, memory.Policy{})
	if err != nil {
		t.Fatalf("MayApplyAutomatically: %v", err)
	}
	if d.Apply {
		t.Fatal("behavioural memory promoted automatically on corroboration alone")
	}
	if !strings.Contains(d.Reason, "human review") {
		t.Fatalf("reason = %q; it must say review is required", d.Reason)
	}

	// Even reviewed, it is applied by that approval rather than automatically — the distinction
	// matters because MEM-4 shows the user which mechanism admitted each memory.
	m.ReviewedBy = "alice@example.com"
	d, err = memory.MayApplyAutomatically(m, memory.Policy{})
	if err != nil {
		t.Fatalf("MayApplyAutomatically: %v", err)
	}
	if d.Apply {
		t.Fatal("reviewed behavioural memory was reported as an automatic application")
	}
}

// M4. The zero Tier is behavioural, so an unclassified memory cannot reach the automatic path.
func TestSecurityTheZeroTierIsBehavioural(t *testing.T) {
	var unset memory.Tier
	if unset != memory.TierBehavioral {
		t.Fatalf("the zero Tier is %q, want behavioural", unset)
	}
	m := operational(10)
	m.Tier = unset
	d, err := memory.MayApplyAutomatically(m, memory.Policy{})
	if err != nil {
		t.Fatalf("MayApplyAutomatically: %v", err)
	}
	if d.Apply {
		t.Fatal("a memory with no tier promoted automatically")
	}
}

// M5. Policy may tighten MEM-2's threshold and may not repeal it.
func TestSecurityPolicyCannotLowerTheCorroborationFloor(t *testing.T) {
	if err := (memory.Policy{MinCorroborations: 1}).Validate(); err == nil {
		t.Fatal("a corroboration minimum of 1 was accepted; that is single-trajectory promotion")
	}
	if err := (memory.Policy{MinCorroborations: memory.MinAllowedCorroborations}).Validate(); err != nil {
		t.Fatalf("the MEM-2 floor of %d was refused: %v", memory.MinAllowedCorroborations, err)
	}

	// Tightening is permitted, and takes effect.
	strict := memory.Policy{MinCorroborations: 5}
	d, err := memory.MayApplyAutomatically(operational(4), strict)
	if err != nil {
		t.Fatalf("MayApplyAutomatically: %v", err)
	}
	if d.Apply {
		t.Fatal("four trajectories satisfied a policy requiring five")
	}
	if d.Required != 5 {
		t.Fatalf("required = %d, want the policy's 5", d.Required)
	}

	// The default is MEM-2's 3.
	d, _ = memory.MayApplyAutomatically(operational(3), memory.Policy{})
	if !d.Apply || d.Required != memory.DefaultMinCorroborations {
		t.Fatalf("default policy: apply=%v required=%d, want true and %d",
			d.Apply, d.Required, memory.DefaultMinCorroborations)
	}
}

// M6. MEM-6: an organization disabling a scope outranks any amount of corroboration.
func TestSecurityADisabledScopeOutranksCorroboration(t *testing.T) {
	p := memory.Policy{DisabledScopes: []memory.Scope{memory.ScopeRepository}}
	d, err := memory.MayApplyAutomatically(operational(20), p)
	if err != nil {
		t.Fatalf("MayApplyAutomatically: %v", err)
	}
	if d.Apply {
		t.Fatal("a memory in a disabled scope applied on corroboration")
	}
	if !strings.Contains(d.Reason, "disabled") {
		t.Fatalf("reason = %q; it must name the policy", d.Reason)
	}
}

// M7. MEM-3 asks for provenance links to source runs *and evidence*.
//
// A run id with no evidence records that a run agreed without recording why, which cannot be
// audited and is not a provenance link.
func TestMEM3RequiresEvidenceNotJustARunID(t *testing.T) {
	m := operational(2)
	m.Corroborations[0].EvidenceRef = "  "
	if _, err := memory.MayApplyAutomatically(m, memory.Policy{}); err == nil {
		t.Fatal("a corroboration with no evidence reference was accepted")
	}

	for name, mutate := range map[string]func(*memory.Memory){
		"no id":    func(m *memory.Memory) { m.ID = "" },
		"no scope": func(m *memory.Memory) { m.Scope = memory.ScopeUnset },
		"no owner": func(m *memory.Memory) { m.OwnerID = "" },
		"no claim": func(m *memory.Memory) { m.Claim = " " },
		"no run":   func(m *memory.Memory) { m.Corroborations[0].RunID = "" },
	} {
		bad := operational(2)
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: an incomplete memory validated", name)
		}
	}
}

// M8. MEM-4 prohibits silent application, and the converse matters as much.
//
// A memory withheld with no explanation cannot be inspected: a user cannot tell one that was
// rejected from one that was never learned. The manifest therefore lists both, with the arithmetic.
func TestSecurityTheManifestShowsWhatWasWithheldAndWhy(t *testing.T) {
	applied := operational(3)
	withheld := operational(1)
	behavioural := operational(9)
	behavioural.Tier = memory.TierBehavioral

	lines, err := memory.Manifest(
		[]memory.Memory{applied, withheld, behavioural}, memory.Policy{})
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("manifest has %d lines, want 3: withheld memories are listed too", len(lines))
	}
	var appliedCount, withheldCount int
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "applied "):
			appliedCount++
		case strings.HasPrefix(l, "withheld "):
			withheldCount++
			if !strings.Contains(l, ":") {
				t.Errorf("a withheld line carries no reason: %q", l)
			}
		}
	}
	if appliedCount != 1 || withheldCount != 2 {
		t.Fatalf("applied=%d withheld=%d, want 1 and 2", appliedCount, withheldCount)
	}
}

// M9. MEM-5: rollback is recorded rather than deleted, and a retired memory stops applying.
func TestRetirementIsRecordedAndStopsApplication(t *testing.T) {
	m := operational(5)
	d, _ := memory.MayApplyAutomatically(m, memory.Policy{})
	if !d.Apply {
		t.Fatal("the fixture does not apply, so retirement proves nothing")
	}

	retired := memory.Retire(m)
	if retired.State != memory.StateRetired {
		t.Fatalf("state = %q after Retire, want retired", retired.State)
	}
	// The corroborations survive, so the rollback event has something to reference and a later
	// re-proposal is recognisable as a return rather than a discovery.
	if len(retired.Corroborations) != len(m.Corroborations) {
		t.Fatal("retirement discarded the provenance the rollback event needs")
	}
	d, err := memory.MayApplyAutomatically(retired, memory.Policy{})
	if err != nil {
		t.Fatalf("MayApplyAutomatically: %v", err)
	}
	if d.Apply {
		t.Fatal("a retired memory still applies")
	}
}
