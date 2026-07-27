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

// IgnoreFile names one ignore file and the source it contributes.
type IgnoreFile struct {
	Name   string
	Source IgnoreSource
}

// IgnoreFiles lists the ignore files read in each directory, in the order their patterns are
// applied.
//
// The order is part of the contract, not an implementation detail: resolution is last-match-wins,
// so a later file can override an earlier one. Modbit's own files come after `.gitignore` because a
// repository's build exclusions must not be able to overrule an instruction addressed to Modbit,
// and `.modbitindexingignore` comes last because it is the narrowest statement of the three.
var IgnoreFiles = []IgnoreFile{
	{".gitignore", SourceGitignore},
	{".modbitignore", SourceModbitignore},
	{".modbitindexingignore", SourceIndexingIgnore},
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
	segments []segment
	// baseSegments is Base pre-split, so matching a path against a nested rule does not re-split
	// the base on every call.
	baseSegments []string
}

// segment is one "/"-delimited component of a pattern, classified once at parse time.
//
// The classification exists because `path.Match` dominated the classifier's cost: it was more than
// half of the time spent deciding a single file. Almost every segment a real ignore file contains
// is a plain name — `node_modules`, `.ssh`, `dist` — for which a string comparison is exact and
// hundreds of times cheaper. Only segments that actually carry a metacharacter reach the matcher.
type segment struct {
	text string
	// star marks the "**" segment, which absorbs zero or more path components.
	star bool
	// literal marks a segment with no glob metacharacters.
	literal bool
	// suffix is set for the `*rest` form — `*.pem`, `*.log` — which is what most globs in a real
	// ignore file look like. It matches with strings.HasSuffix rather than path.Match.
	suffix    string
	hasSuffix bool
}

// globMeta are the characters that make a segment require path.Match.
const globMeta = `*?[\`

func newSegment(text string) segment {
	s := segment{
		text:    text,
		star:    text == "**",
		literal: !strings.ContainsAny(text, globMeta),
	}
	if !s.star && !s.literal && strings.HasPrefix(text, "*") {
		if rest := text[1:]; !strings.ContainsAny(rest, globMeta) {
			s.suffix, s.hasSuffix = rest, true
		}
	}
	return s
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
	for _, s := range strings.Split(line, "/") {
		p.segments = append(p.segments, newSegment(s))
	}
	if base != "" {
		p.baseSegments = strings.Split(base, "/")
	}
	return p, true
}

// Negates reports whether the pattern re-includes rather than excludes.
func (p Pattern) Negates() bool { return p.negate }

// Match reports whether the pattern applies to a repository-relative path.
func (p Pattern) Match(relPath string, isDir bool) bool {
	return p.match(strings.Split(relPath, "/"), isDir)
}

// match is Match over a path the caller has already split.
//
// Resolving one file consults every pattern against the path and against each of its ancestor
// directories, so splitting inside this function meant one allocation per pattern per ancestor. The
// caller splits once instead and slices it.
func (p Pattern) match(segments []string, isDir bool) bool {
	if p.dirOnly && !isDir {
		return false
	}
	// A pattern only governs paths beneath the directory that declared it.
	if n := len(p.baseSegments); n > 0 {
		if len(segments) <= n {
			return false
		}
		for i, base := range p.baseSegments {
			if segments[i] != base {
				return false
			}
		}
		segments = segments[n:]
	}

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
func matchSegments(pattern []segment, target []string) bool {
	if len(pattern) == 0 {
		return true
	}
	if pattern[0].star {
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
	switch {
	case pattern[0].literal:
		if pattern[0].text != target[0] {
			return false
		}
	case pattern[0].hasSuffix:
		if !strings.HasSuffix(target[0], pattern[0].suffix) {
			return false
		}
	default:
		if ok, err := path.Match(pattern[0].text, target[0]); err != nil || !ok {
			return false
		}
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
	segments := strings.Split(relPath, "/")

	if parent, excluded := r.excludedAncestor(segments); excluded {
		return Verdict{Ignored: true, Pattern: parent, Matched: true}
	}

	var v Verdict
	for _, p := range r.patterns {
		if !p.match(segments, isDir) {
			continue
		}
		v = Verdict{Ignored: !p.negate, Pattern: p, Matched: true}
	}
	return v
}

// excludedAncestor reports whether any parent directory of a split path is excluded.
func (r *RuleSet) excludedAncestor(segments []string) (Pattern, bool) {
	for i := 1; i < len(segments); i++ {
		ancestor := segments[:i]
		var decided Pattern
		var ignored bool
		for _, p := range r.patterns {
			if p.match(ancestor, true) {
				decided, ignored = p, !p.negate
			}
		}
		if ignored {
			return decided, true
		}
	}
	return Pattern{}, false
}
