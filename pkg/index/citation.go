package index

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Citation invariants (C1–C10).
//
// This file is the boundary between what was indexed and what a model is allowed to see. Everything
// upstream of it — the classifier, the walk, the reindexer, the snapshot — decides what may be
// indexed; a ContextItem is the only shape in which any of it reaches a prompt. That makes the
// constructor the last place a protected path can be stopped, and the only place RET-6's six fields
// can be made non-optional.
//
// Each invariant has one test named for it in citation_test.go. A test without a C-number, or a
// C-number without a test, is a gap.
//
//	C1  An excluded path can never become a context item.
//	C2  A reference item cites a whole file and carries no span and no content digest.
//	C3  All six RET-6 fields are present; a missing one is refused at construction.
//	C4  Provenance is derived from the index, never supplied by the caller.
//	C5  Whole-file inclusion carries a reason; a span-limited item must not carry one.
//	C6  A cited span lies inside the file the manifest recorded.
//	C7  The content digest covers exactly the bytes cited.
//	C8  A pack never mixes revisions.
//	C9  A pack's taint is the propagation of its items' classes.
//	C10 Every item names the snapshot it was retrieved from.

// Source names which retrieval index produced an item.
//
// It is one of CTX-5's five, plus the two ways an item arrives without being retrieved at all. RET-6
// requires it on every model-visible item because "why is this in my context" has a different answer
// — and a different remedy — depending on which index proposed it.
type Source string

const (
	// SourceLexical is the full-text index.
	SourceLexical Source = "lexical"
	// SourceSemantic is the vector index.
	SourceSemantic Source = "semantic"
	// SourceSymbol is the symbol table.
	SourceSymbol Source = "symbol"
	// SourceGraph is the dependency graph.
	SourceGraph Source = "graph"
	// SourceMetadata is a path, size, or revision query that consulted no content index.
	SourceMetadata Source = "metadata"
	// SourceExplicit is a path named directly by the user, not retrieved.
	SourceExplicit Source = "explicit"
	// SourceExpansion is an item fetched through a context handle a previous result exposed (RET-7).
	SourceExpansion Source = "expansion"
)

// Valid reports whether s is a known retrieval source.
func (s Source) Valid() bool {
	switch s {
	case SourceLexical, SourceSemantic, SourceSymbol, SourceGraph,
		SourceMetadata, SourceExplicit, SourceExpansion:
		return true
	}
	return false
}

// Retrieval reasons explain why an item was selected. They are stable strings: a citation is
// evidence, and evidence whose reason codes are renamed between versions cannot be compared against
// an older run's.
const (
	// ReasonQueryMatch means the item matched the query directly.
	ReasonQueryMatch = "query_match"
	// ReasonSymbolDefinition means the item defines a symbol the query named.
	ReasonSymbolDefinition = "symbol_definition"
	// ReasonSymbolReference means the item references a symbol the query named.
	ReasonSymbolReference = "symbol_reference"
	// ReasonDependencyExpansion means the item was pulled in by dependency-aware expansion (RET-3).
	ReasonDependencyExpansion = "dependency_expansion"
	// ReasonUserAttached means the user attached the item.
	ReasonUserAttached = "user_attached"
	// ReasonAgentRequested means the agent asked for the item through a context handle (RET-7).
	ReasonAgentRequested = "agent_requested"
	// ReasonRuleScope means a rule or skill declared the item in scope (RET-5).
	ReasonRuleScope = "rule_scope"
)

var retrievalReasons = map[string]bool{
	ReasonQueryMatch:          true,
	ReasonSymbolDefinition:    true,
	ReasonSymbolReference:     true,
	ReasonDependencyExpansion: true,
	ReasonUserAttached:        true,
	ReasonAgentRequested:      true,
	ReasonRuleScope:           true,
}

// WholeFileReason records why a whole file was included rather than a span of it (RET-9).
//
// The requirement exists because whole-file inclusion is the single largest consumer of a context
// budget, and it is invisible in the result: a whole file and a well-chosen span look identical to
// the model. Recording the reason is what lets RET-10 benchmark packing decisions afterwards, and
// what lets an operator see that a budget was spent on files nobody chose to include.
type WholeFileReason string

const (
	// WholeFileNone means the item cites a span, not a whole file.
	WholeFileNone WholeFileReason = ""
	// WholeFileBelowThreshold means the file was small enough that a span would not have saved
	// enough budget to be worth the loss of surrounding context.
	WholeFileBelowThreshold WholeFileReason = "below_span_threshold"
	// WholeFileNoSpanAvailable means no index could propose a span — there were no symbol
	// boundaries to cut on, so any span would have been an arbitrary line window.
	WholeFileNoSpanAvailable WholeFileReason = "no_span_available"
	// WholeFileUserAttached means the user attached the file and did not select part of it.
	WholeFileUserAttached WholeFileReason = "user_attached"
	// WholeFileStructuralUnit means the file is only meaningful whole — a manifest, a lockfile, a
	// configuration document whose keys are interpreted relative to the rest.
	WholeFileStructuralUnit WholeFileReason = "structural_unit"
	// WholeFileNotIndexed means the file was classified reference, so Modbit never read it and has
	// no span to offer. See C2.
	WholeFileNotIndexed WholeFileReason = "not_indexed"
)

var wholeFileReasons = map[WholeFileReason]bool{
	WholeFileBelowThreshold:  true,
	WholeFileNoSpanAvailable: true,
	WholeFileUserAttached:    true,
	WholeFileStructuralUnit:  true,
	WholeFileNotIndexed:      true,
}

// Span is the cited region of a file.
//
// It carries lines and bytes because they answer different questions. Lines are the citation a
// person checks and a UI renders. Bytes are what makes the region exact: a line range says nothing
// about line endings or encoding, so two readers can disagree about what it covers, and a digest
// over "lines 40–60" is not reproducible. The byte range is what the content digest is taken over.
type Span struct {
	// StartLine is 1-based and inclusive.
	StartLine int `json:"start_line"`
	// EndLine is 1-based and inclusive.
	EndLine int `json:"end_line"`
	// StartByte is 0-based and inclusive.
	StartByte int64 `json:"start_byte"`
	// EndByte is exclusive.
	EndByte int64 `json:"end_byte"`
}

// Empty reports whether the span cites nothing, which is how a whole-file item is expressed.
func (s Span) Empty() bool { return s == Span{} }

// String renders the span the way a citation is read: "40-60".
func (s Span) String() string {
	if s.Empty() {
		return "whole-file"
	}
	return strconv.Itoa(s.StartLine) + "-" + strconv.Itoa(s.EndLine)
}

// validate checks the span against the size the manifest recorded for the file.
//
// The size check is C6 and it is cheap only because the manifest already holds it: a span past the
// end of a file is either a stale index or a caller inventing a citation, and both must be caught
// before the item is quotable as evidence.
func (s Span) validate(size int64) error {
	fail := func(msg string) error {
		return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", "span")
	}
	switch {
	case s.StartLine < 1 || s.EndLine < 1:
		return fail("a cited span must have 1-based line numbers")
	case s.EndLine < s.StartLine:
		return fail("a cited span cannot end before it starts")
	case s.StartByte < 0 || s.EndByte < 0:
		return fail("a cited span cannot have negative byte offsets")
	case s.EndByte <= s.StartByte:
		return fail("a cited span cannot be empty in bytes")
	case s.EndByte > size:
		return fail("a cited span extends past the end of the indexed file")
	}
	return nil
}

// ContextItem is one model-visible piece of context and everything RET-6 requires be attributable
// about it.
//
// The type is deliberately not constructible field by field from outside the package: Cite is the
// only way to make one, because three of the fields are guarantees rather than data. Disposition
// decides whether the path may be cited at all (C1), Provenance must not be able to default to
// user_trusted (C4), and Revision and SnapshotID must come from the index that actually produced the
// item rather than from whatever the caller believed was current (C10).
type ContextItem struct {
	id         id.ID
	repository id.ID
	path       string
	revision   Revision
	snapshotID id.ID
	span       Span
	source     Source
	reason     string
	wholeFile  WholeFileReason
	provenance taint.Class
	digest     string
}

// ID is the item's opaque identifier, the stable handle an agent expands through (RET-7).
func (i ContextItem) ID() id.ID { return i.id }

// Repository names the repository the item came from (RET-6). Cross-repository links are attributable
// because this is required rather than inferred from the path (CTX-7).
func (i ContextItem) Repository() id.ID { return i.repository }

// Path is the repository-relative path (RET-6).
func (i ContextItem) Path() string { return i.path }

// Revision is the tree state cited: worktree, branch, and commit (RET-6, RET-8).
func (i ContextItem) Revision() Revision { return i.revision }

// SnapshotID names the immutable index snapshot the item was retrieved from (C10).
func (i ContextItem) SnapshotID() id.ID { return i.snapshotID }

// Span is the cited region, or the empty span for a whole-file item (RET-6).
func (i ContextItem) Span() Span { return i.span }

// Source is the retrieval index that produced the item (RET-6).
func (i ContextItem) Source() Source { return i.source }

// RetrievalReason explains why the item was selected (RET-6).
func (i ContextItem) RetrievalReason() string { return i.reason }

// WholeFileReason explains why a whole file was included, empty for a span-limited item (RET-9).
func (i ContextItem) WholeFileReason() WholeFileReason { return i.wholeFile }

// Provenance is the taint class of the content (TNT-1). Repository content is untrusted, including
// any instructions it contains.
func (i ContextItem) Provenance() taint.Class { return i.provenance }

// ContentDigest covers exactly the bytes cited, empty for an item whose content was never read.
//
// It is what makes a citation checkable rather than merely recorded: a validator re-reading the file
// at this revision and span must arrive at this digest, and a mismatch means the index and the tree
// have diverged.
func (i ContextItem) ContentDigest() string { return i.digest }

// WholeFile reports whether the item cites an entire file.
func (i ContextItem) WholeFile() bool { return i.span.Empty() }

// Citation renders the item the way it is shown to a user and recorded in evidence.
func (i ContextItem) Citation() string {
	return i.path + ":" + i.span.String() + "@" + i.revision.Short()
}

// Request is what a retriever must supply to cite a path.
//
// Everything the index already knows — revision, snapshot, disposition, size, provenance — is read
// from the snapshot rather than accepted here, so a retriever cannot assert any of it.
type Request struct {
	// Repository is the registered repository the index belongs to (RET-6).
	Repository id.ID
	// Path is the repository-relative path, as it appears in the snapshot manifest.
	Path string
	// Span is the cited region. The zero Span cites the whole file and requires WholeFileReason.
	Span Span
	// Source is the retrieval index that produced the item (RET-6).
	Source Source
	// RetrievalReason explains the selection (RET-6). It must be one of the declared reasons.
	RetrievalReason string
	// WholeFileReason is required when Span is empty and refused otherwise (RET-9).
	WholeFileReason WholeFileReason
	// Content is the exact bytes cited, digested and discarded. It is optional for a reference item,
	// whose content was never read, and required otherwise: a citation nothing can revalidate is a
	// claim rather than evidence.
	Content []byte
}

// Cite turns a retrieval result into a model-visible context item.
//
// The snapshot is the authority for everything about the file, which is what makes C1 structural:
// an excluded path is absent from a manifest by construction, so citing one fails as a lookup rather
// than as a permission check that a later caller might be tempted to bypass.
func Cite(snap Snapshot, req Request) (ContextItem, error) {
	fail := func(msg, field string) (ContextItem, error) {
		return ContextItem{}, modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", field)
	}

	// C3: every RET-6 field is checked here, and the check is a refusal rather than a default.
	// A defaulted repository or reason produces an item that satisfies the requirement's letter and
	// tells a reviewer nothing.
	if !req.Repository.HasPrefix(id.Repository) {
		return fail("a context item must name the repository it came from", "repository")
	}
	if snap.ID.IsZero() {
		return fail("a context item must name the index snapshot it was retrieved from", "snapshot")
	}
	if !req.Source.Valid() {
		return fail("a context item must record which index retrieved it", "source")
	}
	if !retrievalReasons[req.RetrievalReason] {
		return fail("a context item must record why it was retrieved", "retrieval_reason")
	}

	entry, ok := snap.Lookup(req.Path)
	if !ok {
		// C1. The message deliberately does not distinguish "excluded" from "absent": a caller
		// probing paths would otherwise learn which protected files exist, which is the disclosure
		// the exclusion was written to prevent.
		return fail("path is not present in the index snapshot", "path")
	}

	// C4. Provenance is read from the index, not from the request. The zero taint.Class is
	// user_trusted, so a field the caller could leave unset would silently promote repository
	// content — including any instructions it contains — to the most trusted class in the lattice.
	provenance := provenanceOf(entry)

	item := ContextItem{
		repository: req.Repository,
		path:       entry.Path,
		revision:   snap.Revision,
		snapshotID: snap.ID,
		source:     req.Source,
		reason:     req.RetrievalReason,
		provenance: provenance,
	}

	switch entry.Disposition {
	case DispositionReference:
		// C2. Modbit never read this file, so it cannot claim a span of it or digest bytes it does
		// not have. The item is a pointer: the path exists, it is citable, and its content is not
		// available through the index.
		if !req.Span.Empty() {
			return fail("a file that was not indexed cannot be cited by span", "span")
		}
		if len(req.Content) > 0 {
			return fail("a file that was not indexed has no content to cite", "content")
		}
		if req.WholeFileReason != WholeFileNotIndexed {
			return fail("a reference item must record whole-file reason not_indexed", "whole_file_reason")
		}
		item.wholeFile = WholeFileNotIndexed
		return finish(item)

	case DispositionIndex:
		if req.WholeFileReason == WholeFileNotIndexed {
			return fail("not_indexed is not a reason for an indexed file", "whole_file_reason")
		}
		if req.Span.Empty() {
			// C5. Whole-file inclusion is the expensive branch, so it is the one that must justify
			// itself. A reason is required here and refused below.
			if !wholeFileReasons[req.WholeFileReason] {
				return fail("whole-file inclusion must record why a span was not used", "whole_file_reason")
			}
			item.wholeFile = req.WholeFileReason
		} else {
			if req.WholeFileReason != WholeFileNone {
				return fail("a span-limited item cannot carry a whole-file reason", "whole_file_reason")
			}
			// C6.
			if err := req.Span.validate(entry.Size); err != nil {
				return ContextItem{}, err
			}
			item.span = req.Span
		}
		if len(req.Content) == 0 {
			return fail("an indexed item must cite content that can be revalidated", "content")
		}
		// C7. The digest is taken here, over the bytes the caller says it cited, so the recorded
		// digest and the cited content cannot disagree. The content itself is not retained: INV-4
		// keeps bodies out of metadata, and a citation is metadata.
		if !req.Span.Empty() && int64(len(req.Content)) != req.Span.EndByte-req.Span.StartByte {
			return fail("cited content length does not match the cited span", "content")
		}
		sum := sha256.Sum256(req.Content)
		item.digest = "sha256:" + hex.EncodeToString(sum[:])
		return finish(item)

	default:
		// DispositionExclude cannot reach here — NewSnapshot rejects excluded entries — but a
		// manifest is a decoded file, and an unrecognized disposition must fail closed rather than
		// fall through to the indexed branch.
		return fail("path is not present in the index snapshot", "path")
	}
}

func finish(item ContextItem) (ContextItem, error) {
	itemID, err := id.New(id.ContextItem)
	if err != nil {
		return ContextItem{}, modberr.Wrap(err, modberr.CodeInternal, "allocate context item id")
	}
	item.id = itemID
	return item, nil
}

// provenanceOf assigns the taint class of indexed repository content.
//
// It is a function rather than a constant because provenance belongs to the *source*, not to the
// file: a context item assembled from an MCP result or a fetched page carries a different class
// through its own constructor. Repository content is uniformly untrusted, generated or not — a
// generated file is still content a contributor can choose.
func provenanceOf(ManifestEntry) taint.Class { return taint.RepositoryUntrusted }

// Lookup returns the manifest entry for a path.
//
// The manifest is sorted by path, so this is a binary search rather than a scan: a pack assembled
// for a large monorepo cites many paths against one snapshot.
func (s Snapshot) Lookup(path string) (ManifestEntry, bool) {
	normalized := normalizePath(path)
	i := sort.Search(len(s.Manifest), func(i int) bool { return s.Manifest[i].Path >= normalized })
	if i < len(s.Manifest) && s.Manifest[i].Path == normalized {
		return s.Manifest[i], true
	}
	return ManifestEntry{}, false
}

// Pack is an assembled set of context items bound to one revision.
//
// It exists to make RET-8 checkable at the only place it can be enforced: a single item cannot mix
// revisions, and by the time items are serialized into a prompt it is too late to notice that two of
// them describe different branches. A caller that never assembles a Pack has no protection.
type Pack struct {
	id         id.ID
	revision   Revision
	items      []ContextItem
	taintClass taint.Class
	taintSet   taint.Set
}

// NewPack assembles items into a pack, refusing any mixture of revisions (RET-8).
func NewPack(items ...ContextItem) (Pack, error) {
	if len(items) == 0 {
		return Pack{}, modberr.New(modberr.CodeInvalidArgument, "a context pack must contain at least one item").
			WithDetail("field", "items")
	}

	revision := items[0].revision
	classes := make([]taint.Class, 0, len(items))
	set := taint.NewSet()
	for _, item := range items {
		if item.id.IsZero() {
			return Pack{}, modberr.New(modberr.CodeInvalidArgument, "a context pack cannot contain an unconstructed item").
				WithDetail("field", "items")
		}
		// C8. Two revisions in one pack is the silent mixing RET-8 forbids, and it is silent
		// precisely because the assembled prompt shows no revision at all. Refusing here is the last
		// moment the difference is still visible.
		if !item.revision.Equal(revision) {
			// The two revisions are named rather than merely reported: "these do not match" gives an
			// operator nothing to act on, and both values are safe to show — a ref name is validated
			// against check-ref-format at the boundary it enters through, so it cannot be read here
			// as anything but a name.
			return Pack{}, modberr.New(modberr.CodeSnapshotDiverged,
				"a context pack cannot mix items from different revisions").
				WithDetail("expected_revision", revision.Short()).
				WithDetail("actual_revision", item.revision.Short())
		}
		classes = append(classes, item.provenance)
		set = set.With(item.provenance)
	}

	packID, err := id.New(id.ContextPack)
	if err != nil {
		return Pack{}, modberr.Wrap(err, modberr.CodeInternal, "allocate context pack id")
	}

	return Pack{
		id:       packID,
		revision: revision,
		items:    append([]ContextItem(nil), items...),
		// C9. Propagated once, at assembly, so the value cannot drift from the items it describes.
		taintClass: taint.Propagate(classes...),
		taintSet:   set,
	}, nil
}

// ID is the pack's opaque identifier.
func (p Pack) ID() id.ID { return p.id }

// Revision is the single tree state every item in the pack was retrieved from (RET-8).
func (p Pack) Revision() Revision { return p.revision }

// Items returns the pack's items.
func (p Pack) Items() []ContextItem { return append([]ContextItem(nil), p.items...) }

// Taint is the class the assembled context carries into a prompt (C9).
//
// It is the propagation of every item's class, so a pack is never less tainted than the most
// tainted thing in it. A prompt assembled from one trusted file and one untrusted one is an
// untrusted prompt; averaging or ignoring the minority is how repository-authored instructions get
// treated as user intent.
func (p Pack) Taint() taint.Class { return p.taintClass }

// TaintSet is every class present in the pack, for a surface that shows what went in rather than
// only the worst of it.
func (p Pack) TaintSet() taint.Set { return p.taintSet }

// WholeFileInclusions returns the items included whole, with their reasons (RET-9).
//
// Assembly records the reason on each item; this is the view a budget review reads, because "which
// files consumed the budget without anyone choosing them" is the question RET-9 exists to answer.
func (p Pack) WholeFileInclusions() []ContextItem {
	var whole []ContextItem
	for _, item := range p.items {
		if item.WholeFile() {
			whole = append(whole, item)
		}
	}
	return whole
}

// Citations renders every item as a citation string, in pack order.
func (p Pack) Citations() []string {
	citations := make([]string, 0, len(p.items))
	for _, item := range p.items {
		citations = append(citations, item.Citation())
	}
	return citations
}
