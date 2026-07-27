package index

import (
	"testing"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/taint"
)

// C9. Every item Cite produces today is RepositoryUntrusted, because that is what repository content
// is. A pack of them is homogeneous, and Propagate over a homogeneous set is indistinguishable from
// "take the first item's class" — so the public API cannot demonstrate that the pack actually
// propagates. This test builds a heterogeneous pack directly, which only in-package code can do.
//
// The case is not hypothetical. A file a DLP inspector flags as containing credential material is
// KnownSecret rather than RepositoryUntrusted, and a pack assembled from an editor selection carries
// UserTrusted alongside repository content. Both make packs heterogeneous, and both are the moment a
// "take the first" implementation would silently under-report what a prompt is carrying.
func TestPackTaintIsPropagatedNotInherited(t *testing.T) {
	t.Parallel()
	rev := Revision{Worktree: "/repo", Branch: "main", Commit: "abc123def456789"}

	item := func(class taint.Class) ContextItem {
		return ContextItem{
			id:         id.MustNew(id.ContextItem),
			repository: id.MustNew(id.Repository),
			path:       "a.go",
			revision:   rev,
			snapshotID: id.MustNew(id.IndexSnapshot),
			source:     SourceLexical,
			reason:     ReasonQueryMatch,
			wholeFile:  WholeFileBelowThreshold,
			provenance: class,
		}
	}

	cases := []struct {
		name   string
		items  []ContextItem
		expect taint.Class
	}{
		{
			// The ordering trap: the most trusted item is first. An implementation that inherited
			// the first item's class would report a prompt built from repository content as
			// user-trusted, which is exactly how repository-authored instructions get executed as
			// though the user had typed them.
			name:   "trusted first, untrusted second",
			items:  []ContextItem{item(taint.UserTrusted), item(taint.RepositoryUntrusted)},
			expect: taint.RepositoryUntrusted,
		},
		{
			name:   "untrusted first, trusted second",
			items:  []ContextItem{item(taint.RepositoryUntrusted), item(taint.UserTrusted)},
			expect: taint.RepositoryUntrusted,
		},
		{
			// A single detected credential dominates the pack no matter how much clean content
			// surrounds it, and it must not be diluted by a majority.
			name: "one secret among many",
			items: []ContextItem{
				item(taint.UserTrusted), item(taint.UserTrusted),
				item(taint.KnownSecret), item(taint.RepositoryUntrusted),
			},
			expect: taint.KnownSecret,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pack, err := NewPack(tc.items...)
			if err != nil {
				t.Fatalf("NewPack: %v", err)
			}
			if got := pack.Taint(); got != tc.expect {
				t.Fatalf("pack taint = %v, want %v", got, tc.expect)
			}
			// The set is the other half: a surface showing "what went into this" needs every class
			// present, not only the worst of them.
			for _, i := range tc.items {
				if !pack.TaintSet().Contains(i.provenance) {
					t.Fatalf("taint set %v is missing %v", pack.TaintSet(), i.provenance)
				}
			}
		})
	}
}
