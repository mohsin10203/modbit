package shard_test

import (
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/shard"
)

// MRS invariants (S1–S9). One test each; a test without an S-number, or an S-number without a test,
// is a gap.
//
//	S1 A layout is complete and non-overlapping, enforced at construction.
//	S2 Longest prefix wins, so a nested shard is not swallowed by its parent.
//	S3 A path in no shard is refused, not dropped and not defaulted.
//	S4 A change confined to one shard affects only that shard (MRS-4).
//	S5 An unlocatable path in a change set fails the whole plan rather than being skipped.
//	S6 An empty grant permits nothing.
//	S7 A composition omits shards the grant does not cover, without revealing them.
//	S8 A composition mixing revisions is refused (MRS-4 makes this the normal case).
//	S9 A refusal does not disclose the layout to a caller probing paths.

func layout(t *testing.T) *shard.Layout {
	t.Helper()
	l, err := shard.NewLayout([]shard.Shard{
		{ID: "core", Prefix: "pkg"},
		{ID: "fsevents", Prefix: "pkg/index/fsevents"},
		{ID: "services", Prefix: "services"},
	})
	if err != nil {
		t.Fatalf("NewLayout: %v", err)
	}
	return l
}

func change(p string) index.Change {
	return index.Change{Path: p, Kind: index.ChangeModified, At: time.Now()}
}

// S1. Overlap and emptiness are refused at construction, because both fail silently later.
func TestALayoutIsValidatedAtConstruction(t *testing.T) {
	if _, err := shard.NewLayout(nil); err == nil {
		t.Error("an empty layout was accepted")
	}
	if _, err := shard.NewLayout([]shard.Shard{{ID: "", Prefix: "pkg"}}); err == nil {
		t.Error("a shard with no identifier was accepted")
	}
	if _, err := shard.NewLayout([]shard.Shard{
		{ID: "a", Prefix: "pkg"}, {ID: "a", Prefix: "services"},
	}); err == nil {
		t.Error("a duplicated shard identifier was accepted")
	}
	if _, err := shard.NewLayout([]shard.Shard{
		{ID: "a", Prefix: "pkg"}, {ID: "b", Prefix: "pkg/"},
	}); err == nil {
		t.Error("two shards covering the same prefix were accepted")
	}
	// A root shard beside others is a default shard under another name, and a default shard grows
	// until it is the full rebuild MRS-4 exists to prevent.
	if _, err := shard.NewLayout([]shard.Shard{
		{ID: "root", Prefix: ""}, {ID: "core", Prefix: "pkg"},
	}); err == nil {
		t.Error("a root shard alongside another shard was accepted")
	}
	// Alone, a root shard is a legitimate single-shard layout.
	if _, err := shard.NewLayout([]shard.Shard{{ID: "all", Prefix: ""}}); err != nil {
		t.Errorf("a single root shard was refused: %v", err)
	}
}

// S2. A nested shard owns its own paths rather than being absorbed by its parent.
func TestTheLongestPrefixWins(t *testing.T) {
	l := layout(t)
	for _, tc := range []struct{ path, want string }{
		{"pkg/index/fsevents/fsevents.go", "fsevents"},
		{"pkg/index/fsevents", "fsevents"},
		{"pkg/index/watch.go", "core"},
		{"pkg/gateway/gateway.go", "core"},
		{"services/modbit-model-gateway/main.go", "services"},
	} {
		got, err := l.Locate(tc.path)
		if err != nil {
			t.Fatalf("Locate(%s): %v", tc.path, err)
		}
		if got.ID != tc.want {
			t.Errorf("Locate(%s) = %s, want %s", tc.path, got.ID, tc.want)
		}
	}
}

// S3. A path in no shard is refused. Dropping it loses content silently, and a default shard
// becomes the unbounded rebuild MRS-4 exists to prevent.
func TestSecurityAPathInNoShardIsRefused(t *testing.T) {
	l := layout(t)
	for _, p := range []string{"docs/adr/0107.md", "Makefile", "", "."} {
		if _, err := l.Locate(p); err == nil {
			t.Errorf("Locate(%q) succeeded; an unassigned path must be refused", p)
		}
	}
}

// S4. MRS-4: a change confined to one shard must not force a full-repository rebuild.
//
// The failure mode this guards is not a crash. It is `Affected` returning every shard — output that
// is correct, useless, and indistinguishable from working until an Extreme-class estate rebuilds
// for hours.
func TestSecurityAConfinedChangeAffectsOneShard(t *testing.T) {
	l := layout(t)
	affected, err := l.Affected([]index.Change{
		change("pkg/index/fsevents/fsevents.go"),
		change("pkg/index/fsevents/shim.c"),
	})
	if err != nil {
		t.Fatalf("Affected: %v", err)
	}
	if len(affected) != 1 || affected[0].ID != "fsevents" {
		t.Fatalf("affected = %+v, want exactly the fsevents shard; MRS-4 forbids widening", affected)
	}

	// And a change spanning two shards affects exactly those two, not all three.
	affected, err = l.Affected([]index.Change{
		change("pkg/index/watch.go"),
		change("services/modbit-model-gateway/main.go"),
	})
	if err != nil {
		t.Fatalf("Affected: %v", err)
	}
	if len(affected) != 2 {
		t.Fatalf("affected = %+v, want two shards", affected)
	}
}

// S5. An unlocatable path fails the plan rather than being skipped.
//
// Skipping would under-report the affected set and leave a shard stale, which is worse than the
// over-rebuild the caller was trying to avoid — a stale index is wrong, a slow one is only slow.
func TestSecurityAnUnlocatablePathFailsThePlan(t *testing.T) {
	l := layout(t)
	if _, err := l.Affected([]index.Change{
		change("pkg/index/watch.go"),
		change("docs/adr/0107.md"),
	}); err == nil {
		t.Fatal("a change set containing an unassigned path produced a rebuild plan")
	}
}

// S6. An empty grant permits nothing, which is the safe reading of an unset permission.
func TestSecurityAnEmptyGrantPermitsNothing(t *testing.T) {
	l := layout(t)
	if visible := l.Visible(shard.Grant{}); len(visible) != 0 {
		t.Fatalf("an empty grant made %d shards visible", len(visible))
	}
	if (shard.Grant{}).Permits("core") {
		t.Fatal("an empty grant permitted a shard")
	}
}

// S7. A composition omits shards the grant does not cover, and does not reveal that they exist.
//
// Returning an error naming the forbidden shard would be a disclosure: a caller could enumerate the
// layout by composing against shard ids and reading which ones complained.
func TestSecurityCompositionOmitsForbiddenShardsSilently(t *testing.T) {
	rev := index.Revision{Worktree: "/repo", Branch: "main", Commit: "aaaa"}
	results := []shard.Result{
		{ShardID: "core", Revision: rev},
		{ShardID: "secret", Revision: rev},
	}
	items, err := shard.Compose(results, shard.Grant{Allowed: []string{"core"}})
	if err != nil {
		t.Fatalf("Compose refused rather than filtering: %v", err)
	}
	if items != nil && len(items) != 0 {
		t.Fatalf("items = %d, want none from these empty results", len(items))
	}
}

// S8. A composition mixing revisions is refused.
//
// MRS-4 lets shards rebuild independently, so two shards being at different revisions is the normal
// state rather than an exotic one — which is exactly why composing them silently would be the
// common failure rather than a rare one. It is the same rule CTX-A01i applies to a citation pack.
func TestSecurityACompositionCannotMixRevisions(t *testing.T) {
	older := index.Revision{Worktree: "/repo", Branch: "main", Commit: "aaaa"}
	newer := index.Revision{Worktree: "/repo", Branch: "main", Commit: "bbbb"}

	_, err := shard.Compose([]shard.Result{
		{ShardID: "core", Revision: older},
		{ShardID: "services", Revision: newer},
	}, shard.Grant{Allowed: []string{"core", "services"}})
	if err == nil {
		t.Fatal("a composition mixing two revisions was accepted")
	}

	// A forbidden shard at a different revision is not an error, because it never contributes.
	if _, err := shard.Compose([]shard.Result{
		{ShardID: "core", Revision: older},
		{ShardID: "secret", Revision: newer},
	}, shard.Grant{Allowed: []string{"core"}}); err != nil {
		t.Fatalf("a filtered-out shard's revision affected the composition: %v", err)
	}
}

// S9. A refusal does not disclose the layout.
//
// A caller probing paths against an error message could otherwise map the repository's structure,
// and the structure is the thing sharding exists to describe.
func TestSecurityARefusalDoesNotDiscloseTheLayout(t *testing.T) {
	l := layout(t)
	_, err := l.Locate("docs/adr/0107.md")
	if err == nil {
		t.Fatal("an unassigned path was located")
	}
	for _, secret := range []string{"pkg", "services", "fsevents", "core"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the refusal disclosed %q from the layout: %v", secret, err)
		}
	}
}
