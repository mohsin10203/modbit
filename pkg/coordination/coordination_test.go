package coordination_test

import (
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/coordination"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// CRC invariants (K1–K8). One test each; a test without a K-number, or a K-number without a test,
// is a gap.
//
//	K1 CRC-1: a claim both runs made is a direct conflict.
//	K2 CRC-1: a shared dependency-closure file is a conflict neither run claimed.
//	K3 CRC-6/INV-10: a cross-tenant comparison is refused, not answered empty.
//	K4 CRC-6: the refusal discloses nothing about the other tenant's run.
//	K5 Runs on different repositories do not overlap, and that is not an error.
//	K6 CRC-2: a held lock is reported and never blocks.
//	K7 CRC-2: a lock with no expiry is treated as expired, not as eternal.
//	K8 A scope with no organization is refused, because it could not be tenant-checked.

func org() id.ID  { return id.MustNew(id.Organization) }
func repo() id.ID { return id.MustNew(id.Repository) }
func run() id.ID  { return id.MustNew(id.Run) }

func scope(o, s, r, runID id.ID, claims ...coordination.Claim) coordination.Scope {
	return coordination.Scope{
		RunID: runID, OrganizationID: o, SpaceID: s, RepositoryID: r, Claims: claims,
	}
}

func symbol(name string) coordination.Claim {
	return coordination.Claim{Kind: coordination.ScopeSymbol, Ref: name}
}

// K1. CRC-1: two runs claiming the same symbol conflict, and the conflict is marked direct.
func TestADirectlySharedClaimIsAConflict(t *testing.T) {
	o, s, r := org(), id.MustNew(id.Space), repo()
	a := scope(o, s, r, run(), symbol("pkg/index.Cite"), symbol("pkg/index.Span"))
	b := scope(o, s, r, run(), symbol("pkg/index.Cite"))

	conflicts, err := coordination.Overlaps(a, b)
	if err != nil {
		t.Fatalf("Overlaps: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1: only Cite is shared", len(conflicts))
	}
	if !conflicts[0].Direct || conflicts[0].Ref != "pkg/index.Cite" {
		t.Fatalf("conflict = %+v, want a direct conflict on Cite", conflicts[0])
	}
}

// K2. CRC-1 asks for dependency-graph overlap, not only claim overlap.
//
// Two runs editing different files that both sit in the other's closure conflict semantically, and
// comparing claims alone would miss it — which is the interesting half of the requirement, because
// it is the conflict neither author wrote down.
func TestADependencyClosureOverlapIsAConflictNeitherRunClaimed(t *testing.T) {
	o, s, r := org(), id.MustNew(id.Space), repo()
	a := scope(o, s, r, run(), symbol("pkg/a.Handler"))
	a.DependencyClosure = []string{"pkg/shared/types.go"}
	b := scope(o, s, r, run(), symbol("pkg/b.Worker"))
	b.DependencyClosure = []string{"pkg/shared/types.go"}

	conflicts, err := coordination.Overlaps(a, b)
	if err != nil {
		t.Fatalf("Overlaps: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1 through the dependency closure", len(conflicts))
	}
	if conflicts[0].Direct {
		t.Fatal("a closure overlap was reported as a direct claim; neither run claimed that file")
	}
	if conflicts[0].Ref != "pkg/shared/types.go" {
		t.Fatalf("ref = %q, want the shared closure file", conflicts[0].Ref)
	}
}

// K3. CRC-6 and INV-10: a cross-tenant comparison is refused rather than answered.
//
// Returning "no overlap" would be worse than refusing, because it is a usable answer: a caller could
// compare against another organization's scope and read the empty result as permission-checked truth.
// "No overlap" and "not permitted to know" must not be the same reply.
func TestSecurityACrossTenantComparisonIsRefused(t *testing.T) {
	s, r := id.MustNew(id.Space), repo()
	a := scope(org(), s, r, run(), symbol("pkg/index.Cite"))
	b := scope(org(), s, r, run(), symbol("pkg/index.Cite"))

	_, err := coordination.Overlaps(a, b)
	if err == nil {
		t.Fatal("two scopes in different organizations were compared")
	}
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("err = %v, want CodePolicyDenied", err)
	}

	// A different Space in the same organization is equally out of scope (INV-10 names both).
	o := org()
	c := scope(o, id.MustNew(id.Space), r, run(), symbol("pkg/index.Cite"))
	d := scope(o, id.MustNew(id.Space), r, run(), symbol("pkg/index.Cite"))
	if _, err := coordination.Overlaps(c, d); err == nil {
		t.Fatal("two scopes in different Spaces were compared")
	}
}

// K4. The refusal discloses nothing about the other tenant.
//
// An overlap detector's error is the natural place to leak: the obvious message names the run and
// the symbol that collided. A caller learning "your run overlaps something you may not see" has
// already learned that a run exists, on this repository, touching this symbol.
func TestSecurityTheCrossTenantRefusalDisclosesNothing(t *testing.T) {
	s, r := id.MustNew(id.Space), repo()
	secretRun := run()
	a := scope(org(), s, r, run(), symbol("pkg/index.Cite"))
	b := scope(org(), s, r, secretRun, symbol("pkg/secret.Key"))

	_, err := coordination.Overlaps(a, b)
	if err == nil {
		t.Fatal("the comparison succeeded")
	}
	for _, secret := range []string{
		secretRun.String(), b.OrganizationID.String(), r.String(), "pkg/secret.Key", "Cite",
	} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the refusal disclosed %q: %v", secret, err)
		}
	}
}

// K5. CRC-1 scopes overlap to runs on the same repository; different repositories simply do not
// overlap, which is an answer rather than an error.
func TestDifferentRepositoriesDoNotOverlap(t *testing.T) {
	o, s := org(), id.MustNew(id.Space)
	a := scope(o, s, repo(), run(), symbol("pkg/index.Cite"))
	b := scope(o, s, repo(), run(), symbol("pkg/index.Cite"))

	conflicts, err := coordination.Overlaps(a, b)
	if err != nil {
		t.Fatalf("Overlaps refused rather than reporting no overlap: %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("conflicts = %d across two repositories, want 0", len(conflicts))
	}
}

// K6. CRC-2: an advisory lock is visible and never blocks.
//
// Take always succeeds — contention is not an error here. Held reports who else intends the code,
// and the caller decides. Enforcing would turn a coordination hint into a deadlock between two
// agents that cannot negotiate, and it would present as a hung run rather than a conflict.
func TestSecurityAnAdvisoryLockNeverBlocks(t *testing.T) {
	o := org()
	reg, err := coordination.NewRegistry(o, id.MustNew(id.Space))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	now := time.Now()
	first, second := run(), run()
	claim := symbol("pkg/index.Cite")

	if err := reg.Take(coordination.Lock{
		RunID: first, Claim: claim, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("Take: %v", err)
	}
	// The contended take must also succeed. CRC-2 makes locks advisory, so refusing here would be
	// this package deciding something it is not allowed to decide.
	if err := reg.Take(coordination.Lock{
		RunID: second, Claim: claim, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("a contended advisory lock was refused: %v", err)
	}

	held := reg.Held(claim, second, now)
	if len(held) != 1 || held[0].RunID != first {
		t.Fatalf("held = %+v, want exactly the first run's lock", held)
	}
	// A run does not see its own lock as contention.
	if own := reg.Held(claim, first, now); len(own) != 1 || own[0].RunID != second {
		t.Fatalf("a run saw its own lock as contention: %+v", own)
	}

	reg.Release(first)
	if held := reg.Held(claim, second, now); len(held) != 0 {
		t.Fatalf("a released lock is still held: %+v", held)
	}
}

// K7. A lock with no expiry is treated as expired, not as eternal.
//
// CRC-2 requires locks to expire with the run. An unbounded lock left by a crashed run would shadow
// a symbol indefinitely, and because nothing blocks, the failure would be invisible — every later
// run would see phantom contention from a run that ended days ago.
func TestSecurityALockWithNoExpiryIsAlreadyExpired(t *testing.T) {
	if !(coordination.Lock{}).Expired(time.Now()) {
		t.Fatal("a lock with no expiry reported itself live")
	}
	reg, err := coordination.NewRegistry(org(), id.MustNew(id.Space))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	// Take refuses to record one at all, which is the earlier of the two defences.
	if err := reg.Take(coordination.Lock{RunID: run(), Claim: symbol("x")}); err == nil {
		t.Fatal("a lock with no expiry was recorded")
	}

	// And an expired lock is not reported as contention.
	past := time.Now().Add(-time.Hour)
	if err := reg.Take(coordination.Lock{
		RunID: run(), Claim: symbol("x"), ExpiresAt: past}); err != nil {
		t.Fatalf("Take: %v", err)
	}
	if held := reg.Held(symbol("x"), run(), time.Now()); len(held) != 0 {
		t.Fatalf("an expired lock was reported as held: %+v", held)
	}
}

// K8. A scope with no organization is refused, because it could not be tenant-checked.
func TestSecurityAScopeWithoutTenancyIsRefused(t *testing.T) {
	s, r := id.MustNew(id.Space), repo()
	valid := scope(org(), s, r, run(), symbol("x"))
	untenanted := coordination.Scope{RunID: run(), SpaceID: s, RepositoryID: r}

	if _, err := coordination.Overlaps(valid, untenanted); err == nil {
		t.Fatal("a scope with no organization participated in a comparison")
	}

	// The case that matters, and the one a weaker test misses. Pairing an untenanted scope with a
	// valid one is refused by the tenant comparison whether or not validation runs, because zero
	// and non-zero differ. Two *both* untenanted scopes compare as the same tenant — zero equals
	// zero — so only the validation refuses them, and without it two runs with no organization at
	// all would coordinate freely. A mutation removing the check survived until this existed.
	other := coordination.Scope{RunID: run(), SpaceID: s, RepositoryID: r,
		Claims: []coordination.Claim{symbol("x")}}
	if _, err := coordination.Overlaps(untenanted, other); err == nil {
		t.Fatal("two scopes with no organization were compared as the same tenant")
	}
	if _, err := coordination.NewRegistry(id.ID(""), s); err == nil {
		t.Fatal("a lock registry was created with no organization")
	}
}

// An uninterpretable claim is refused rather than silently never matching.
//
// A claim with an unknown kind would compare unequal to everything, so a run making one would report
// no conflicts and look coordinated while being invisible to every other run.
func TestSecurityAnUninterpretableClaimIsRefused(t *testing.T) {
	o, s, r := org(), id.MustNew(id.Space), repo()
	bad := scope(o, s, r, run(), coordination.Claim{Kind: "workspace", Ref: "x"})
	good := scope(o, s, r, run(), symbol("x"))

	if _, err := coordination.Overlaps(good, bad); err == nil {
		t.Fatal("a scope with an unknown claim kind was compared")
	}
	empty := scope(o, s, r, run(), coordination.Claim{Kind: coordination.ScopeSymbol, Ref: "  "})
	if _, err := coordination.Overlaps(good, empty); err == nil {
		t.Fatal("a scope with an empty claim reference was compared")
	}
}
