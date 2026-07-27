// Package index implements the Context Engine's ignore and classification filter.
//
// Boundary: it decides what may be indexed and how each file is classified. It does not read
// repository contents beyond the bytes needed to detect binary and generated files, does not build
// indexes, and never executes repository code (CTX-12).
//
// Requirements: PRD v5.1 §9.3 — CTX-4 (ignored and restricted content is excluded *before*
// indexing), CTX-12 (indexing does not execute repository code); §20A.10 "Context and indexing"
// (hierarchical ignore discovery, `.modbitignore`, `.modbitindexingignore`, binary and
// generated-file handling); SDD §8 (the classification filter also assigns provenance classes,
// TNT-1); rules.md INV-11 (secrets never reach indexes or artifacts).
package index

import (
	"path"
	"strings"
)

// IgnoreSource names which file a pattern came from, so a decision can explain itself.
type IgnoreSource string

const (
	// SourceGitignore is a `.gitignore` file. Honoured only when context.indexing.respect_gitignore
	// is set, because a repository's build exclusions are not always its indexing exclusions.
	SourceGitignore IgnoreSource = "gitignore"
	// SourceModbitignore is a `.modbitignore` file: content Modbit must not read at all.
	SourceModbitignore IgnoreSource = "modbitignore"
	// SourceIndexingIgnore is a `.modbitindexingignore` file: content readable on request but never
	// indexed. The distinction matters — a large fixture may be legitimately openable while being
	// worthless and expensive to embed.
	SourceIndexingIgnore IgnoreSource = "modbitindexingignore"
	// SourceSettings is a pattern from context.indexing.excluded_globs.
	SourceSettings IgnoreSource = "settings"
)

// IgnoreFileNames maps each ignore file to its source, in discovery order.
var IgnoreFileNames = map[string]IgnoreSource{
	".gitignore":            SourceGitignore,
	".modbitignore":         SourceModbitignore,
	".modbitindexingignore": SourceIndexingIgnore,
}

// Pattern is one parsed ignore rule.
type Pattern struct {
	// Base is the repository-relative directory the pattern is anchored to, "" for the root.
	Base string
	// Source records which file the rule came from.
	Source IgnoreSource
	// Raw is the original text, for diagnostics.
	Raw string

	negate   bool
	dirOnly  bool
	anchored bool
	segments []string
}

// ParsePattern parses one gitignore-syntax line relative to base.
//
// It returns ok=false for blanks and comments rather than an error: an ignore file is
// user-authored and a comment is not a failure.
func ParsePattern(line, base string, source IgnoreSource) (Pattern, bool) {
	raw := line
	line = strings.TrimRight(line, " ")
	// A trailing backslash escapes the space it precedes, so unescape after trimming.
	line = strings.ReplaceAll(line, `\ `, " ")
	if line == "" || strings.HasPrefix(line, "#") {
		return Pattern{}, false
	}

	p := Pattern{Base: base, Source: source, Raw: raw}
	if strings.HasPrefix(line, "!") {
		p.negate = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		p.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	if line == "" {
		return Pattern{}, false
	}

	// gitignore: a pattern containing a slash anywhere but the end is relative to the ignore file's
	// directory. Otherwise it matches a basename at any depth beneath it.
	if strings.Contains(line, "/") {
		p.anchored = true
		line = strings.TrimPrefix(line, "/")
	}
	p.segments = strings.Split(line, "/")
	return p, true
}

// Negates reports whether the pattern re-includes rather than excludes.
func (p Pattern) Negates() bool { return p.negate }

// Match reports whether the pattern applies to a repository-relative path.
func (p Pattern) Match(relPath string, isDir bool) bool {
	if p.dirOnly && !isDir {
		return false
	}
	// A pattern only governs paths beneath the directory that declared it.
	if p.Base != "" {
		prefix := p.Base + "/"
		if !strings.HasPrefix(relPath, prefix) {
			return false
		}
		relPath = strings.TrimPrefix(relPath, prefix)
	}

	segments := strings.Split(relPath, "/")
	if p.anchored {
		return matchSegments(p.segments, segments)
	}
	// Unanchored: try every suffix, so "build" matches "a/b/build/x".
	for i := range segments {
		if matchSegments(p.segments, segments[i:]) {
			return true
		}
	}
	return false
}

// matchSegments matches a segmented pattern against segmented path components, handling "**".
//
// A trailing non-"**" pattern still matches a longer path, because excluding a directory excludes
// everything beneath it: "build" must match "build/out/x.o", not only "build" itself.
func matchSegments(pattern, target []string) bool {
	if len(pattern) == 0 {
		return true
	}
	if pattern[0] == "**" {
		// "**" absorbs zero or more segments.
		for i := 0; i <= len(target); i++ {
			if matchSegments(pattern[1:], target[i:]) {
				return true
			}
		}
		return false
	}
	if len(target) == 0 {
		return false
	}
	ok, err := path.Match(pattern[0], target[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pattern[1:], target[1:])
}

// RuleSet is an ordered collection of patterns.
//
// Order is significant and deliberately preserved: gitignore semantics are last-match-wins, so a
// negation only re-includes what an earlier pattern excluded.
type RuleSet struct {
	patterns []Pattern
}

// NewRuleSet returns a RuleSet over patterns, in precedence order.
func NewRuleSet(patterns []Pattern) *RuleSet {
	out := &RuleSet{patterns: make([]Pattern, len(patterns))}
	copy(out.patterns, patterns)
	return out
}

// ParseFile parses an ignore file's contents into patterns anchored at base.
func ParseFile(contents, base string, source IgnoreSource) []Pattern {
	var out []Pattern
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if p, ok := ParsePattern(line, base, source); ok {
			out = append(out, p)
		}
	}
	return out
}

// Add appends patterns, preserving order.
func (r *RuleSet) Add(patterns ...Pattern) { r.patterns = append(r.patterns, patterns...) }

// Len returns the number of patterns.
func (r *RuleSet) Len() int { return len(r.patterns) }

// Verdict is the outcome of matching a path against a rule set.
type Verdict struct {
	// Ignored reports the final decision after last-match-wins resolution.
	Ignored bool
	// Pattern is the rule that decided it, valid only when Ignored is true or a negation applied.
	Pattern Pattern
	// Matched reports whether any pattern applied at all.
	Matched bool
}

// Match resolves a path against the rule set.
//
// Directory exclusion is checked first and is not negatable, matching git: "it is not possible to
// re-include a file if a parent directory of that file is excluded". Allowing a negation to reach
// inside an excluded directory would let a single `!` line in a nested ignore file pull an entire
// excluded tree back into the index.
func (r *RuleSet) Match(relPath string, isDir bool) Verdict {
	if parent, excluded := r.excludedAncestor(relPath); excluded {
		return Verdict{Ignored: true, Pattern: parent, Matched: true}
	}

	var v Verdict
	for _, p := range r.patterns {
		if !p.Match(relPath, isDir) {
			continue
		}
		v = Verdict{Ignored: !p.negate, Pattern: p, Matched: true}
	}
	return v
}

// excludedAncestor reports whether any parent directory of relPath is excluded.
func (r *RuleSet) excludedAncestor(relPath string) (Pattern, bool) {
	segments := strings.Split(relPath, "/")
	for i := 1; i < len(segments); i++ {
		ancestor := strings.Join(segments[:i], "/")
		var decided Pattern
		var ignored bool
		for _, p := range r.patterns {
			if p.Match(ancestor, true) {
				decided, ignored = p, !p.negate
			}
		}
		if ignored {
			return decided, true
		}
	}
	return Pattern{}, false
}
