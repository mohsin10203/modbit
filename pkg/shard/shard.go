// Package shard makes an index addressable in bounded slices (MRS-3, MRS-4).
//
// Boundary: it decides which slice of a repository a path belongs to, which slices a change set
// touches, and which slices a caller is permitted to see. It stores nothing, indexes nothing, and
// reads no files — the index owns content and this owns the partitioning of it.
//
// Requirements: PRD §8B MRS-3, MRS-4.
//
// # Why a change set has to name shards rather than paths
//
// MRS-4 is the requirement with teeth: "a change confined to one shard MUST NOT force a
// full-repository rebuild". On an Extreme-class estate a full rebuild is measured in hours, so the
// difference between rebuilding one shard and rebuilding all of them is the difference between a
// usable index and a nightly job. That makes `Affected` the load-bearing function here, and its
// failure mode is not a crash — it is quietly returning every shard, which is correct output and
// useless behaviour.
//
// # Why an unassigned path is an error
//
// A path matching no shard could reasonably be dropped, assigned to a default, or refused. It is
// refused. Dropping loses content silently, which is the failure CTX-2 spends its whole design
// avoiding; a default shard grows without bound and becomes the full rebuild MRS-4 exists to
// prevent. Refusing forces the layout to be complete, which is the only state in which sharding
// means anything.
package shard

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// Shard is an addressable slice of a repository (MRS-3).
type Shard struct {
	// ID addresses the shard. Retrieval names it, rebuild scopes to it, and permission is granted
	// against it.
	ID string `json:"id"`
	// Prefix is the repository-relative directory the shard covers, without a trailing slash. The
	// empty prefix covers the repository root and is only valid on a single-shard layout.
	Prefix string `json:"prefix"`
}

// Layout is a complete, non-overlapping partition of a repository.
//
// Complete and non-overlapping are both enforced at construction rather than assumed, because both
// failures are silent: an overlap double-indexes and double-rebuilds, and a gap loses content that
// nothing will ever report as missing.
type Layout struct {
	shards []Shard
	// byPrefix is ordered longest-prefix-first, so `pkg/index/fsevents` resolves to its own shard
	// rather than to `pkg`.
	byPrefix []Shard
}

// NewLayout validates and orders a set of shards.
func NewLayout(shards []Shard) (*Layout, error) {
	if len(shards) == 0 {
		return nil, modberr.New(modberr.CodeInvalidArgument, "a layout needs at least one shard").
			WithDetail("field", "shards")
	}

	seenID := make(map[string]bool, len(shards))
	seenPrefix := make(map[string]bool, len(shards))
	normalized := make([]Shard, 0, len(shards))

	for _, s := range shards {
		if strings.TrimSpace(s.ID) == "" {
			return nil, modberr.New(modberr.CodeInvalidArgument, "a shard has no identifier").
				WithDetail("field", "id")
		}
		if seenID[s.ID] {
			return nil, modberr.Newf(modberr.CodeInvalidArgument, "shard %q is declared twice", s.ID).
				WithDetail("field", "id")
		}
		seenID[s.ID] = true

		prefix := normalizePrefix(s.Prefix)
		if seenPrefix[prefix] {
			return nil, modberr.Newf(modberr.CodeInvalidArgument,
				"shards %q and another cover the same prefix %q", s.ID, prefix).
				WithDetail("field", "prefix")
		}
		seenPrefix[prefix] = true
		normalized = append(normalized, Shard{ID: s.ID, Prefix: prefix})
	}

	if len(normalized) > 1 {
		for _, s := range normalized {
			if s.Prefix == "" {
				// A root shard alongside others would claim every path the longest-prefix search did
				// not, which is a default shard wearing a different name.
				return nil, modberr.Newf(modberr.CodeInvalidArgument,
					"shard %q covers the repository root alongside %d other shards",
					s.ID, len(normalized)-1).WithDetail("field", "prefix")
			}
		}
	}

	ordered := make([]Shard, len(normalized))
	copy(ordered, normalized)
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i].Prefix) != len(ordered[j].Prefix) {
			return len(ordered[i].Prefix) > len(ordered[j].Prefix)
		}
		return ordered[i].Prefix < ordered[j].Prefix
	})

	return &Layout{shards: normalized, byPrefix: ordered}, nil
}

// Shards returns the layout's shards in declaration order.
func (l *Layout) Shards() []Shard {
	out := make([]Shard, len(l.shards))
	copy(out, l.shards)
	return out
}

// Locate returns the shard owning a repository-relative path.
//
// Longest prefix wins, so a nested shard is not swallowed by its parent. An unmatched path is an
// error — see the package comment for why it is not silently absorbed.
func (l *Layout) Locate(repoPath string) (Shard, error) {
	clean := normalizePrefix(repoPath)
	if clean == "" {
		return Shard{}, modberr.New(modberr.CodeInvalidArgument, "an empty path belongs to no shard").
			WithDetail("field", "path")
	}
	for _, s := range l.byPrefix {
		if s.Prefix == "" || clean == s.Prefix || strings.HasPrefix(clean, s.Prefix+"/") {
			return s, nil
		}
	}
	// The message names no other shard's prefix. A caller probing paths would otherwise map the
	// layout, and a layout is a description of the repository's structure.
	return Shard{}, modberr.New(modberr.CodeInvalidArgument, "path belongs to no shard in this layout").
		WithDetail("field", "path")
}

// Affected returns the shards a change set touches, in declaration order (MRS-4).
//
// This is the function MRS-4 rests on, and the reason it returns an error rather than skipping an
// unlocatable path: silently ignoring one would under-report the affected set and leave a shard
// stale, which is worse than the over-rebuild it was trying to avoid.
func (l *Layout) Affected(changes []index.Change) ([]Shard, error) {
	touched := make(map[string]bool, len(changes))
	for _, c := range changes {
		s, err := l.Locate(c.Path)
		if err != nil {
			return nil, err
		}
		touched[s.ID] = true
	}

	var out []Shard
	for _, s := range l.shards {
		if touched[s.ID] {
			out = append(out, s)
		}
	}
	return out, nil
}

// Grant is a caller's permission over a layout (MRS-3).
//
// Permission is per shard because that is the granularity MRS-3 asks for, and because a repository
// large enough to need sharding is large enough for a team to be entitled to part of it.
type Grant struct {
	// Allowed lists the shard ids the caller may read. An empty grant permits nothing, which is the
	// safe reading of an unset permission rather than an inconvenient one.
	Allowed []string `json:"allowed"`
}

// Permits reports whether the grant covers a shard.
func (g Grant) Permits(shardID string) bool {
	for _, allowed := range g.Allowed {
		if allowed == shardID {
			return true
		}
	}
	return false
}

// Visible filters shards to those a grant permits, in declaration order.
func (l *Layout) Visible(g Grant) []Shard {
	var out []Shard
	for _, s := range l.shards {
		if g.Permits(s.ID) {
			out = append(out, s)
		}
	}
	return out
}

// Result is one shard's contribution to a composed retrieval (MRS-3).
type Result struct {
	ShardID string `json:"shard_id"`
	// Revision is the revision this shard's index was built at. Shards rebuild independently under
	// MRS-4, so two of them can legitimately be at different revisions at the same instant.
	Revision index.Revision `json:"revision"`
	Items    []index.ContextItem
}

// Compose merges per-shard results into one permission-filtered set (MRS-3).
//
// Two rules, and the second is the one that makes independent rebuild safe. A shard the grant does
// not cover contributes nothing *and is not mentioned* — a caller must not learn that a shard exists
// by seeing it excluded. And every contributing shard must be at the same revision, because MRS-4
// lets shards rebuild independently, so a composed result silently mixing revisions is the normal
// case rather than an exotic one.
func Compose(results []Result, g Grant) ([]index.ContextItem, error) {
	var (
		items    []index.ContextItem
		expected index.Revision
		haveRev  bool
	)
	for _, r := range results {
		if !g.Permits(r.ShardID) {
			continue
		}
		if !haveRev {
			expected, haveRev = r.Revision, true
		} else if r.Revision != expected {
			// Named by shard id, which the caller is permitted to see, and not by path or content.
			return nil, modberr.Newf(modberr.CodeInvalidArgument,
				"shard %q is at a different revision from the rest of the composition; "+
					"a retrieval must not mix revisions", r.ShardID).
				WithDetail("constraint", "revision_consistency")
		}
		items = append(items, r.Items...)
	}
	return items, nil
}

// normalizePrefix cleans a repository-relative prefix to a comparable form.
func normalizePrefix(p string) string {
	clean := path.Clean(strings.TrimSpace(strings.ReplaceAll(p, "\\", "/")))
	clean = strings.Trim(clean, "/")
	if clean == "." {
		return ""
	}
	return clean
}

// String renders a layout for a diagnostic line.
func (l *Layout) String() string {
	names := make([]string, 0, len(l.shards))
	for _, s := range l.shards {
		names = append(names, fmt.Sprintf("%s=%s", s.ID, s.Prefix))
	}
	return strings.Join(names, " ")
}
