package codewiki_test

import (
	"testing"

	"github.com/modbit/modbit/pkg/codewiki"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/index"
)

// WIKI invariants (W1–W8). One test each; a test without a W-number, or a W-number without a test,
// is a gap.
//
//	W1 A technical statement with no citation and no inference label is refused.
//	W2 An inference is permitted, and only when it is labelled and explained.
//	W3 The zero Kind is technical, so an unclassified claim is held to the strictest rule.
//	W4 A citation from another revision is refused even though it is a real citation.
//	W5 A citation from another context snapshot is refused (WIKI-2).
//	W6 A diagram node with no evidence is refused, and has no inference escape hatch (WIKI-4).
//	W7 A page with no snapshot cannot be validated and must not pass by default.
//	W8 Every finding names what failed, so a generator knows what to regenerate.

func revisionA() index.Revision {
	return index.Revision{Worktree: "/repo", Branch: "main", Commit: "aaaa1111"}
}

func revisionB() index.Revision {
	return index.Revision{Worktree: "/repo", Branch: "main", Commit: "bbbb2222"}
}

// cite builds a real ContextItem through the package's own constructor.
//
// Going through index.Cite rather than assembling a struct is deliberate: ContextItem's fields are
// unexported precisely so a citation cannot be fabricated, and a fixture that bypassed that would be
// testing a shape this validator will never actually receive. It also means provenance is derived
// from the manifest rather than supplied, which is the C4 rule the citation package enforces.
func cite(t *testing.T, snapshotID id.ID, rev index.Revision, path string) index.ContextItem {
	t.Helper()
	content := []byte("package a\n\nfunc A() {}\n")
	snap := index.Snapshot{
		ID:       snapshotID,
		Revision: rev,
		Manifest: []index.ManifestEntry{{
			Path: path, Disposition: index.DispositionIndex, Size: int64(len(content)),
		}},
	}
	item, err := index.Cite(snap, index.Request{
		Repository:      id.MustNew(id.Repository),
		Path:            path,
		Span:            index.Span{StartLine: 1, EndLine: 1, StartByte: 0, EndByte: int64(len(content))},
		Source:          index.SourceLexical,
		RetrievalReason: index.ReasonQueryMatch,
		Content:         content,
	})
	if err != nil {
		t.Fatalf("index.Cite(%s): %v", path, err)
	}
	return item
}

func basePage(t *testing.T, snapshotID id.ID) codewiki.Page {
	t.Helper()
	return codewiki.Page{
		Path: "docs/overview.md", Revision: revisionA(), SnapshotID: snapshotID,
	}
}

// W1. WIKI-3: a technical statement must link to evidence or declare itself an inference.
func TestSecurityAnUncitedTechnicalStatementIsRefused(t *testing.T) {
	snapshotID := id.MustNew(id.IndexSnapshot)
	page := basePage(t, snapshotID)
	page.Statements = []codewiki.Statement{{ID: "s1", Kind: codewiki.KindTechnical}}

	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if report.Publishable() {
		t.Fatal("a technical statement with no citation was publishable")
	}
	if len(report.Findings) != 1 || report.Findings[0].Statement != "s1" {
		t.Fatalf("findings = %+v, want one naming s1", report.Findings)
	}
}

// W2. An inference is allowed, and only when labelled and explained.
//
// The escape hatch is what keeps the rule honest: without it a generator either omits every
// synthesis or invents a citation for it, and the second failure is the one nobody catches.
func TestAnInferenceIsPermittedOnlyWhenExplained(t *testing.T) {
	snapshotID := id.MustNew(id.IndexSnapshot)

	page := basePage(t, snapshotID)
	page.Statements = []codewiki.Statement{{
		ID: "s1", Kind: codewiki.KindInference,
		Basis: "the three handlers share a retry shape; no single span states the policy",
	}}
	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !report.Publishable() {
		t.Fatalf("a labelled and explained inference was refused: %+v", report.Findings)
	}
	if report.Inferred != 1 {
		t.Fatalf("inferred = %d, want 1", report.Inferred)
	}

	// Unexplained, it is a label with nothing behind it.
	page.Statements = []codewiki.Statement{{ID: "s1", Kind: codewiki.KindInference}}
	report, err = codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if report.Publishable() {
		t.Fatal("an inference with no basis was publishable")
	}
}

// W3. The zero Kind is technical, so a statement nobody classified faces the strictest rule.
//
// The same reasoning as the zero Support, the zero Enforcement and the unknown taint class: the only
// safe reading of no answer is the most restrictive one.
func TestTheZeroKindIsTechnical(t *testing.T) {
	snapshotID := id.MustNew(id.IndexSnapshot)
	page := basePage(t, snapshotID)
	// Kind deliberately unset.
	page.Statements = []codewiki.Statement{{ID: "unclassified"}}

	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if report.Publishable() {
		t.Fatal("an unclassified statement passed; the zero Kind must be held to WIKI-3")
	}
}

// W4. A citation from another revision looks like evidence and describes different code.
//
// This is the failure mode that matters, because nothing about it reads as wrong: the span is real,
// the file exists, the digest verifies. It simply documents code the page is not about.
func TestSecurityACitationFromAnotherRevisionIsRefused(t *testing.T) {
	snapshotID := id.MustNew(id.IndexSnapshot)
	page := basePage(t, snapshotID)
	page.Statements = []codewiki.Statement{{
		ID:        "s1",
		Citations: []index.ContextItem{cite(t, snapshotID, revisionB(), "pkg/a/a.go")},
	}}

	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if report.Publishable() {
		t.Fatal("a citation from another revision was accepted as evidence")
	}
}

// W5. WIKI-2 binds a page to one Context Snapshot; a citation from another is not from this page.
func TestSecurityACitationFromAnotherSnapshotIsRefused(t *testing.T) {
	page := basePage(t, id.MustNew(id.IndexSnapshot))
	page.Statements = []codewiki.Statement{{
		ID:        "s1",
		Citations: []index.ContextItem{cite(t, id.MustNew(id.IndexSnapshot), revisionA(), "pkg/a/a.go")},
	}}

	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if report.Publishable() {
		t.Fatal("a citation from another context snapshot was accepted")
	}
}

// W6. WIKI-4 gives diagrams no inference escape hatch: a node drawn from nothing is a guess.
func TestSecurityADiagramNodeNeedsEvidence(t *testing.T) {
	snapshotID := id.MustNew(id.IndexSnapshot)
	page := basePage(t, snapshotID)
	page.Diagram = []codewiki.Node{{ID: "svc"}}

	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if report.Publishable() {
		t.Fatal("a diagram node with no evidence was publishable")
	}
	if len(report.Findings) != 1 || report.Findings[0].Node != "svc" {
		t.Fatalf("findings = %+v, want one naming the node", report.Findings)
	}

	// With evidence from the page's own revision it passes.
	page.Diagram = []codewiki.Node{{
		ID: "svc", Citations: []index.ContextItem{cite(t, snapshotID, revisionA(), "pkg/svc/svc.go")},
	}}
	report, err = codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !report.Publishable() {
		t.Fatalf("a cited diagram node was refused: %+v", report.Findings)
	}
}

// W7. A page with no snapshot cannot be checked, and must not pass for want of a way to fail.
func TestSecurityAPageWithNoSnapshotCannotBeValidated(t *testing.T) {
	page := codewiki.Page{Path: "docs/x.md", Revision: revisionA()}
	if _, err := codewiki.Validate(page); err == nil {
		t.Fatal("a page with no context snapshot validated")
	}
}

// W8. Every finding names what failed, so a generator can regenerate the statement rather than the
// page.
func TestEveryFindingNamesWhatFailed(t *testing.T) {
	snapshotID := id.MustNew(id.IndexSnapshot)
	page := basePage(t, snapshotID)
	page.Statements = []codewiki.Statement{
		{ID: "good", Citations: []index.ContextItem{cite(t, snapshotID, revisionA(), "pkg/a/a.go")}},
		{ID: "uncited"},
		{ID: "bare-inference", Kind: codewiki.KindInference},
	}
	page.Diagram = []codewiki.Node{{ID: "orphan"}}

	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("findings = %d, want 3 (uncited, bare-inference, orphan): %+v",
			len(report.Findings), report.Findings)
	}
	for _, f := range report.Findings {
		if f.Statement == "" && f.Node == "" {
			t.Errorf("a finding names neither a statement nor a node: %+v", f)
		}
		if f.Reason == "" {
			t.Errorf("a finding carries no reason: %+v", f)
		}
	}
	// The one good statement is still counted, so a caller can see the page is not wholly broken.
	if report.Cited != 1 {
		t.Fatalf("cited = %d, want 1", report.Cited)
	}
}

// A page that passes entirely on inference labels is valid and worth noticing.
//
// WIKI-3 permits it, so refusing would exceed the requirement. But a wiki whose every claim is
// "the model concluded this" is not documentation of the code, and a bare "publishable" would hide
// that — which is why the report splits cited from inferred rather than summing them.
func TestTheReportDistinguishesCitedFromInferred(t *testing.T) {
	snapshotID := id.MustNew(id.IndexSnapshot)
	page := basePage(t, snapshotID)
	page.Statements = []codewiki.Statement{
		{ID: "i1", Kind: codewiki.KindInference, Basis: "synthesised across three packages"},
		{ID: "i2", Kind: codewiki.KindInference, Basis: "synthesised across three packages"},
	}

	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !report.Publishable() {
		t.Fatalf("an all-inference page was refused; WIKI-3 permits labelled inference: %+v", report.Findings)
	}
	if report.EvidenceRatio() != 0 {
		t.Fatalf("evidence ratio = %v for an all-inference page, want 0", report.EvidenceRatio())
	}

	// And a page with no checkable claims at all reports 0 rather than dividing by zero.
	narrative := basePage(t, snapshotID)
	narrative.Statements = []codewiki.Statement{{ID: "n1", Kind: codewiki.KindNarrative}}
	report, err = codewiki.Validate(narrative)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if report.EvidenceRatio() != 0 || !report.Publishable() {
		t.Fatalf("a narrative-only page: ratio=%v publishable=%v", report.EvidenceRatio(), report.Publishable())
	}
}

// A duplicated statement identifier is refused, because a finding could name either one.
func TestADuplicateStatementIdentifierIsRefused(t *testing.T) {
	snapshotID := id.MustNew(id.IndexSnapshot)
	page := basePage(t, snapshotID)
	page.Statements = []codewiki.Statement{
		{ID: "s1", Kind: codewiki.KindNarrative},
		{ID: "s1", Kind: codewiki.KindNarrative},
	}
	if _, err := codewiki.Validate(page); err == nil {
		t.Fatal("a page with a duplicated statement identifier validated")
	}
}

// An unrecognised kind is held to the technical rule, not waved through.
//
// This is the property the zero-value test does not reach. A statement whose kind came from a newer
// generator, or from a typo, must not be treated as prose — the classifier's `default` branch is
// what enforces WIKI-3, and a mutation making KindTechnical a non-zero string leaves that intact
// while breaking nothing, which is how the gap was found.
func TestSecurityAnUnrecognisedKindIsHeldToTheTechnicalRule(t *testing.T) {
	snapshotID := id.MustNew(id.IndexSnapshot)
	page := basePage(t, snapshotID)
	page.Statements = []codewiki.Statement{
		{ID: "typo", Kind: codewiki.Kind("narrativ")},
		{ID: "future", Kind: codewiki.Kind("kind-from-a-newer-generator")},
	}

	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if report.Publishable() {
		t.Fatal("statements with unrecognised kinds were published without evidence")
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: every unrecognised kind faces WIKI-3", len(report.Findings))
	}
}
