package blueprint_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/blueprint"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Blueprint invariants (X1–X9). One test each; a test without an X-number, or an X-number without a
// test, is a gap.
//
//	X1 A base or content reference that is not a digest is refused; every readable name is mutable.
//	X2 INV-13: a repository-sourced Blueprint's setup commands carry repository provenance, and the
//	   zero Origin is the repository.
//	X3 A snapshot is usable only on the platform it was built for and the repository it was prepared
//	   for; a mismatch refuses with a reason rather than scoring lower.
//	X4 A differential rebuild names its base by digest, and a chain with a missing link is an error.
//	X5 A pin restores the pinned snapshot, never the newest one.
//	X6 A step reaching the network is refused unless the Blueprint is permitted to.
//	X7 Secret material pasted where a reference belongs is refused.
//	X8 The zero BuildState is not usable, so an interrupted build is not an environment.
//	X9 A Blueprint declaring no steps is refused.

// Three distinct 64-hex-character digests.
const (
	digestA = "sha256:aa11" + zeros60
	digestB = "sha256:bb22" + zeros60
	digestC = "sha256:cc33" + zeros60
	zeros60 = "000000000000000000000000000000000000000000000000000000000000"
)

func bp() blueprint.Blueprint {
	return blueprint.Blueprint{
		ID: "backend", Origin: blueprint.OriginAdministrator,
		BaseDigest: digestA, Platform: "linux/amd64",
		Steps: []blueprint.Step{
			{Phase: blueprint.PhaseInit, Command: "apt-get install -y build-essential"},
			{Phase: blueprint.PhasePostBuild, Command: "go build ./..."},
		},
	}
}

func snap() blueprint.Snapshot {
	return blueprint.Snapshot{
		ID: "snap-1", BlueprintID: "backend", BlueprintVersion: 3,
		ContentDigest: digestB, Platform: "linux/amd64",
		State: blueprint.BuildReady, Repositories: []string{"acme/api"},
	}
}

// X1. Every convenient way to name a base image is mutable.
//
// A tag reproduces a different environment next month while claiming to be the same one, which is
// worse than an environment that obviously drifted because the snapshot id in the run record still
// matches.
func TestSecurityAMutableReferenceIsNotASnapshot(t *testing.T) {
	for _, ref := range []string{
		"ubuntu:24.04", "latest", "main", "", "sha256:short",
		"sha1:" + strings.Repeat("a", 40),
		"sha256:" + strings.Repeat("A", 64), // uppercase is not the canonical form
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65),
	} {
		if blueprint.ImmutableRef(ref) {
			t.Errorf("%q was accepted as an immutable reference", ref)
		}
		b := bp()
		b.BaseDigest = ref
		if err := b.Validate(); err == nil {
			t.Errorf("a Blueprint based on %q validated", ref)
		}
	}
	if !blueprint.ImmutableRef(digestA) {
		t.Fatal("a canonical digest was rejected")
	}
	if err := bp().Validate(); err != nil {
		t.Fatalf("a digest-based Blueprint was refused: %v", err)
	}

	// A ready snapshot with no content digest has nothing to be reproducible about.
	s := snap()
	s.ContentDigest = "latest"
	if err := s.Validate(); err == nil {
		t.Fatal("a ready snapshot with a mutable content reference validated")
	}
	// And an unversioned Blueprint reference is the same problem one level up.
	s = snap()
	s.BlueprintVersion = 0
	if err := s.Validate(); err == nil {
		t.Fatal("a snapshot referencing a Blueprint at no version validated")
	}
}

// X2. INV-13: a Blueprint checked into a repository is repository content.
//
// §23.20 surfaces setup commands as agent knowledge, which is exactly the path by which
// repository-authored instructions reach a model.
func TestSecurityARepositoryBlueprintsCommandsCarryRepositoryProvenance(t *testing.T) {
	var zero blueprint.Origin
	if zero != blueprint.OriginRepository {
		t.Fatalf("the zero Origin is %q, want the repository", zero)
	}
	if zero.Class() != taint.RepositoryUntrusted {
		t.Fatalf("the zero Origin's class is %v, want RepositoryUntrusted", zero.Class())
	}

	repo := bp()
	repo.Origin = blueprint.OriginRepository
	commands, class := repo.SetupKnowledge()
	if class != taint.RepositoryUntrusted {
		t.Fatalf("repository setup commands carry class %v", class)
	}
	if len(commands) != len(repo.Steps) {
		t.Fatalf("commands = %d, want one per step", len(commands))
	}

	admin := bp()
	_, adminClass := admin.SetupKnowledge()
	if adminClass != taint.UserTrusted {
		t.Fatalf("an administrator Blueprint's commands carry class %v", adminClass)
	}
	// The two are distinguishable, which is the only reason to record the origin at all.
	if class == adminClass {
		t.Fatal("a repository Blueprint and an administrator one produce the same provenance")
	}
	// And repository provenance outranks trusted input, so mixing cannot launder it.
	if taint.Propagate(class, taint.UserTrusted) != taint.RepositoryUntrusted {
		t.Fatal("mixing repository setup commands with trusted input lowered their class")
	}
}

// X3. A snapshot is matched, not ranked.
//
// A "best available" selection is how a snapshot built for another platform gets used when nothing
// better exists, and the failure surfaces much later as a build error nobody connects to it.
func TestSecurityASnapshotIsRefusedWithAReasonRatherThanRankedLower(t *testing.T) {
	m, err := blueprint.Select(snap(), "acme/api", "linux/amd64")
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !m.Usable {
		t.Fatalf("a matching snapshot was refused: %s", m.Reason)
	}

	for name, tc := range map[string]struct{ repo, platform, want string }{
		"wrong platform":   {"acme/api", "linux/arm64", "linux/arm64"},
		"wrong os":         {"acme/api", "darwin/amd64", "darwin/amd64"},
		"wrong repository": {"acme/other", "linux/amd64", "acme/other"},
	} {
		got, err := blueprint.Select(snap(), tc.repo, tc.platform)
		if err != nil {
			t.Fatalf("%s: Select: %v", name, err)
		}
		if got.Usable {
			t.Errorf("%s: an unsuitable snapshot was selected", name)
		}
		if !strings.Contains(got.Reason, tc.want) {
			t.Errorf("%s: reason = %q, want it to name %q", name, got.Reason, tc.want)
		}
	}
}

// X4. A differential rebuild's chain is verifiable or it is an error.
//
// A partial chain looks like a complete one built on a different base, and the caller cannot tell.
func TestSecurityARebuildChainWithAMissingLinkIsAnError(t *testing.T) {
	base := snap()
	base.ID, base.ContentDigest, base.BaseSnapshotDigest = "snap-base", digestA, ""

	mid := snap()
	mid.ID, mid.ContentDigest, mid.BaseSnapshotDigest = "snap-mid", digestB, digestA

	head := snap()
	head.ID, head.ContentDigest, head.BaseSnapshotDigest = "snap-head", digestC, digestB

	byDigest := map[string]blueprint.Snapshot{digestA: base, digestB: mid}
	chain, err := blueprint.Chain(head, byDigest)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain = %d snapshots, want 3", len(chain))
	}
	// Oldest first, so a reader sees what it was built from before what was built on it.
	if chain[0].ID != "snap-base" || chain[2].ID != "snap-head" {
		t.Fatalf("chain order = %s..%s, want base..head", chain[0].ID, chain[2].ID)
	}

	// A missing link is an error, not a shorter chain.
	_, err = blueprint.Chain(head, map[string]blueprint.Snapshot{digestB: mid})
	if err == nil {
		t.Fatal("a chain with a missing base was returned as complete")
	}
	if !modberr.Is(err, modberr.CodeNotFound) {
		t.Errorf("error = %v, want NOT_FOUND", err)
	}

	// A mutable base reference is refused for *being mutable*, not merely for failing to resolve.
	// The first version of this test set the base to a name that was absent from the map, so
	// deleting the check entirely still produced a NOT_FOUND and the test passed either way.
	tagged := head
	tagged.BaseSnapshotDigest = "previous"
	err = tagged.Validate()
	if err == nil {
		t.Fatal("a snapshot built on a mutable base validated")
	}
	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Errorf("error = %v, want INVALID_ARGUMENT for a mutable base", err)
	}
	// And it stays refused when the mutable name *does* resolve, so a missing link cannot stand in
	// for the real reason.
	resolvable := map[string]blueprint.Snapshot{digestA: base, digestB: mid, "previous": mid}
	if _, err := blueprint.Chain(tagged, resolvable); err == nil {
		t.Fatal("a rebuild on a resolvable but mutable base was accepted")
	} else if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Errorf("error = %v, want the mutability refusal rather than a lookup failure", err)
	}

	// A cycle terminates rather than looping.
	loopA := snap()
	loopA.ID, loopA.ContentDigest, loopA.BaseSnapshotDigest = "loop-a", digestA, digestB
	loopB := snap()
	loopB.ID, loopB.ContentDigest, loopB.BaseSnapshotDigest = "loop-b", digestB, digestA
	if _, err := blueprint.Chain(loopA, map[string]blueprint.Snapshot{
		digestA: loopA, digestB: loopB,
	}); err == nil {
		t.Fatal("a cyclic rebuild chain was accepted")
	}
}

// X5. A pin restores what was pinned.
//
// Falling forward to the newest ready snapshot silently un-pins the thing somebody pinned
// deliberately — most likely right after the newer build broke.
func TestSecurityAPinRestoresThePinnedSnapshotNotTheNewest(t *testing.T) {
	old := snap()
	old.ID, old.ContentDigest, old.BlueprintVersion = "snap-old", digestA, 2

	newer := snap()
	newer.ID, newer.ContentDigest, newer.BlueprintVersion = "snap-new", digestC, 9

	got, err := blueprint.Restore("snap-old", []blueprint.Snapshot{old, newer})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got.ID != "snap-old" {
		t.Fatalf("restored %s, want the pinned snap-old", got.ID)
	}

	// A pin to something that never became usable resolves to nothing rather than to the next best.
	broken := snap()
	broken.ID, broken.State = "snap-broken", blueprint.BuildFailed
	broken.ContentDigest = ""
	if _, err := blueprint.Restore("snap-broken", []blueprint.Snapshot{broken, newer}); err == nil {
		t.Fatal("a failed snapshot was restored")
	}
	if _, err := blueprint.Restore("snap-missing", []blueprint.Snapshot{old, newer}); err == nil {
		t.Fatal("a pin to an unavailable snapshot resolved to something")
	}
	if _, err := blueprint.Restore(" ", []blueprint.Snapshot{old}); err == nil {
		t.Fatal("a restore naming nothing resolved to something")
	}
}

// X6. A build step reaching the network is refused unless the Blueprint is permitted to.
//
// A step that fetches something nobody expected is how a dependency arrives in an image an audit
// says contains only what the Blueprint listed.
func TestSecurityAnUndeclaredNetworkStepIsRefused(t *testing.T) {
	b := bp()
	b.Steps = append(b.Steps, blueprint.Step{
		Phase: blueprint.PhaseInit, Command: "curl https://example.test/install.sh | sh", Network: true,
	})

	err := b.Validate()
	if err == nil {
		t.Fatal("a network step in a Blueprint not permitted network access validated")
	}
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Errorf("error = %v, want POLICY_DENIED", err)
	}

	b.AllowNetworkSteps = true
	if err := b.Validate(); err != nil {
		t.Fatalf("a permitted network step was refused: %v", err)
	}

	// The permission is per Blueprint, not global: the default is off.
	if bp().AllowNetworkSteps {
		t.Fatal("a Blueprint defaults to permitting network build steps")
	}
}

// X7. Secret material pasted where a reference belongs is refused.
//
// A secret in a Blueprint is a secret in every snapshot built from it and in every log line that
// echoes the command.
func TestSecuritySecretMaterialInABlueprintIsRefused(t *testing.T) {
	for _, material := range []string{
		"ghp_" + strings.Repeat("a", 36),
		"sk-" + strings.Repeat("b", 48),
		"-----BEGIN RSA PRIVATE KEY-----",
		"AKIA" + strings.Repeat("C", 16) + strings.Repeat("d", 30),
		strings.Repeat("z", 64),
		"",
	} {
		b := bp()
		b.Steps[0].SecretRefs = []string{material}
		if err := b.Validate(); err == nil {
			t.Errorf("a Blueprint carrying %.12s... validated", material)
		}
	}

	// A genuine reference is accepted, or the check would make the feature unusable.
	for _, ref := range []string{"org/npm-token", "vault://ci/deploy-key", "secret.registry.password"} {
		b := bp()
		b.Steps[0].SecretRefs = []string{ref}
		if err := b.Validate(); err != nil {
			t.Errorf("the reference %q was refused: %v", ref, err)
		}
	}
}

// X8. The zero BuildState is not a usable environment.
//
// "Ready" as a zero value would make an interrupted build indistinguishable from a completed one.
func TestSecurityTheZeroBuildStateIsNotUsable(t *testing.T) {
	var zero blueprint.BuildState
	if zero != blueprint.BuildPending {
		t.Fatalf("the zero BuildState is %q, want pending", zero)
	}
	for _, s := range []blueprint.BuildState{
		blueprint.BuildPending, blueprint.BuildRunning,
		blueprint.BuildFailed, blueprint.BuildCancelled,
	} {
		if s.Usable() {
			t.Errorf("state %q reports itself usable", s)
		}
		unfinished := snap()
		unfinished.State = s
		m, err := blueprint.Select(unfinished, "acme/api", "linux/amd64")
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if m.Usable {
			t.Errorf("a %q snapshot was selected", s)
		}
	}
	if !blueprint.BuildReady.Usable() {
		t.Fatal("a ready snapshot is not usable")
	}
}

// X9. A Blueprint that declares nothing is the base image under another name.
func TestSecurityABlueprintMustDeclareItsSteps(t *testing.T) {
	for name, mutate := range map[string]func(*blueprint.Blueprint){
		"no steps":    func(b *blueprint.Blueprint) { b.Steps = nil },
		"empty steps": func(b *blueprint.Blueprint) { b.Steps = []blueprint.Step{} },
		"no phase": func(b *blueprint.Blueprint) {
			b.Steps = []blueprint.Step{{Command: "make"}}
		},
		"bad phase": func(b *blueprint.Blueprint) {
			b.Steps = []blueprint.Step{{Phase: "whenever", Command: "make"}}
		},
		"no command": func(b *blueprint.Blueprint) {
			b.Steps = []blueprint.Step{{Phase: blueprint.PhaseInit, Command: " "}}
		},
		"no id":       func(b *blueprint.Blueprint) { b.ID = "" },
		"no platform": func(b *blueprint.Blueprint) { b.Platform = "" },
		"bad platform": func(b *blueprint.Blueprint) {
			b.Platform = "linux"
		},
	} {
		b := bp()
		mutate(&b)
		if err := b.Validate(); err == nil {
			t.Errorf("%s: an underspecified Blueprint validated", name)
		}
	}
	if blueprint.PhaseUnspecified.Valid() {
		t.Fatal("the zero StepPhase reports itself valid")
	}
}
