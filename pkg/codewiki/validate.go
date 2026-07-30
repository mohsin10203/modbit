// Package codewiki validates that generated documentation is backed by evidence (WIKI-3, WIKI-4).
//
// Boundary: it checks a page's statements against the citations attached to them. It generates
// nothing, reads no repository, and calls no model — a generator produces pages and this decides
// whether they may be published.
//
// Requirements: PRD §9A WIKI-2, WIKI-3, WIKI-4.
//
// # The rule, and the escape hatch that makes it honest
//
// WIKI-3 requires every technical statement to link to source spans, artifacts, **or explicitly
// labeled inferences**. The third option is the interesting one: a generator is allowed to say
// something it cannot cite, provided it says that is what it is doing. Removing the escape hatch
// would produce documentation that either omits every synthesis or fabricates a citation for it, and
// the second failure is the one nobody catches.
//
// So the validator does not ask "is everything cited". It asks whether every statement is either
// cited or *labelled*, which is the same shape as the degradation reason in `pkg/capability` and the
// inconclusive verdict in `pkg/adequacy`: the unsupported case is permitted and must be declared.
//
// # Why citations are ContextItems
//
// `index.ContextItem` is the repository's citation primitive (CTX-A01i), carrying the repository,
// revision, snapshot, span and provenance a citation needs to be checkable. Defining a parallel
// citation type here would produce two notions of "cited" that drift, and the one used by
// documentation would be the weaker.
package codewiki

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// Kind is what a statement claims.
type Kind string

const (
	// KindTechnical is a claim about the code. It requires evidence or an inference label (WIKI-3).
	//
	// It is the zero value, and — more importantly — it is the `default` branch of the switch that
	// classifies a statement. Both matter, and the second is what actually enforces the rule: a
	// statement carrying a kind from a newer generator, a typo, or no value at all is held to the
	// strictest requirement rather than treated as prose. Relying on the zero value alone would
	// leave `Kind("technicaI")` unvalidated.
	KindTechnical Kind = ""
	// KindNarrative is connective text making no checkable claim — a heading, a transition.
	KindNarrative Kind = "narrative"
	// KindInference is a synthesis the generator could not cite and is declaring as such.
	KindInference Kind = "inference"
)

// Statement is one unit of generated documentation.
type Statement struct {
	// ID identifies the statement within its page, so a refusal can name it.
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Citations are the context items backing a technical statement.
	Citations []index.ContextItem `json:"-"`
	// Basis explains an inference. Required for KindInference, for the reason WIKI-3 asks for the
	// label at all: "the model concluded this" is not a useful disclosure, and an inference nobody
	// can evaluate is indistinguishable from a fabrication.
	Basis string `json:"basis,omitempty"`
}

// Node is a diagram node or edge that must link back to evidence (WIKI-4).
type Node struct {
	ID        string              `json:"id"`
	Citations []index.ContextItem `json:"-"`
}

// Page is a generated CodeWiki page bound to one immutable revision (WIKI-2).
type Page struct {
	Path string `json:"path"`
	// Revision and SnapshotID are what WIKI-2 binds generation to. Every citation must agree with
	// them, or the page mixes revisions and its evidence describes code that is not on the page.
	Revision   index.Revision `json:"revision"`
	SnapshotID id.ID          `json:"snapshot_id"`
	Statements []Statement    `json:"statements"`
	Diagram    []Node         `json:"diagram,omitempty"`
	// Symbols and Edges are the indexed symbols and dependency edges the page was generated from.
	// WIKI-6 recalculates freshness when these change, so a page has to say which ones it used;
	// see Recalculate for why a page naming none is stale rather than fresh.
	Symbols []string `json:"symbols,omitempty"`
	Edges   []string `json:"edges,omitempty"`
	// Explicit marks a page from WIKI-12's explicit configuration rather than cluster planning.
	Explicit bool `json:"explicit,omitempty"`
}

// Finding is one reason a page cannot be published.
type Finding struct {
	// Statement or Node names what failed. Exactly one is set.
	Statement string `json:"statement,omitempty"`
	Node      string `json:"node,omitempty"`
	Reason    string `json:"reason"`
}

// Report is the validation outcome.
type Report struct {
	Findings []Finding `json:"findings"`
	// Cited, Inferred and Narrative count the statements by how they were satisfied. The split is
	// the useful number: a page that passes with every statement labelled an inference is valid and
	// worthless, and a single "ok" would hide that.
	Cited     int `json:"cited"`
	Inferred  int `json:"inferred"`
	Narrative int `json:"narrative"`
}

// Publishable reports whether the page may be published.
func (r Report) Publishable() bool { return len(r.Findings) == 0 }

// EvidenceRatio is the share of checkable statements backed by a citation rather than a label.
//
// Returns 0 when a page makes no checkable claims, which is not a failure — a page can be entirely
// narrative — but is also not evidence of anything, and a caller reading a ratio should not have to
// distinguish "nothing claimed" from "nothing cited" by dividing by zero.
func (r Report) EvidenceRatio() float64 {
	checkable := r.Cited + r.Inferred
	if checkable == 0 {
		return 0
	}
	return float64(r.Cited) / float64(checkable)
}

// Validate checks a page against WIKI-2, WIKI-3 and WIKI-4.
//
// It returns a report rather than the first error: a generator fixing one uncited statement at a
// time would need as many runs as it has defects, and the whole point of the check is to tell it
// what to regenerate.
func Validate(page Page) (Report, error) {
	if page.Path == "" {
		return Report{}, modberr.New(modberr.CodeInvalidArgument, "a page has no path").
			WithDetail("field", "path")
	}
	if page.SnapshotID.IsZero() {
		// WIKI-2 binds generation to an immutable revision and Context Snapshot. Without the
		// snapshot there is nothing to check citations against, and a page that cannot be checked
		// must not pass by default.
		return Report{}, modberr.New(modberr.CodeInvalidArgument,
			"a page names no context snapshot; WIKI-2 binds generation to one").
			WithDetail("field", "snapshot_id")
	}

	report := Report{}
	seen := map[string]bool{}

	for _, s := range page.Statements {
		if s.ID == "" {
			return Report{}, modberr.New(modberr.CodeInvalidArgument,
				"a statement has no identifier, so a finding could not name it").
				WithDetail("field", "id")
		}
		if seen[s.ID] {
			return Report{}, modberr.Newf(modberr.CodeInvalidArgument,
				"statement %q appears twice", s.ID).WithDetail("field", "id")
		}
		seen[s.ID] = true

		switch s.Kind {
		case KindNarrative:
			report.Narrative++
			// A narrative statement carrying citations is not an error, but a *technical* statement
			// mislabelled narrative is how the rule gets bypassed. Nothing here can tell those apart
			// — that is a generator concern — so the count is reported and the caller can see a page
			// that is suspiciously narrative.
		case KindInference:
			report.Inferred++
			if strings.TrimSpace(s.Basis) == "" {
				report.Findings = append(report.Findings, Finding{Statement: s.ID,
					Reason: "an inference carries no basis; WIKI-3 requires the label to be explicit, " +
						"and an inference nobody can evaluate is indistinguishable from a fabrication"})
			}
		default: // KindTechnical
			if len(s.Citations) == 0 {
				report.Findings = append(report.Findings, Finding{Statement: s.ID,
					Reason: "a technical statement links to no source span, artifact or labelled inference"})
				continue
			}
			report.Cited++
			report.Findings = append(report.Findings,
				checkCitations(page, s.ID, "", s.Citations)...)
		}
	}

	for _, n := range page.Diagram {
		if n.ID == "" {
			return Report{}, modberr.New(modberr.CodeInvalidArgument, "a diagram node has no identifier").
				WithDetail("field", "id")
		}
		if len(n.Citations) == 0 {
			// WIKI-4 is WIKI-3 for diagrams, and it has no inference escape hatch: a node drawn from
			// nothing is a picture of a guess.
			report.Findings = append(report.Findings, Finding{Node: n.ID,
				Reason: "a diagram node links back to no source evidence"})
			continue
		}
		report.Findings = append(report.Findings, checkCitations(page, "", n.ID, n.Citations)...)
	}

	sortFindings(report.Findings)
	return report, nil
}

// checkCitations verifies every citation belongs to the page's own revision and snapshot.
//
// A citation from another revision is the failure mode that matters: it looks like evidence, renders
// like evidence, and describes code the page is not about. CTX-A01i already refuses to build a pack
// that mixes revisions; this is the same rule at the documentation boundary, where the items arrive
// individually rather than as a pack.
func checkCitations(page Page, statement, node string, citations []index.ContextItem) []Finding {
	var findings []Finding
	for _, c := range citations {
		switch {
		case c.SnapshotID() != page.SnapshotID:
			findings = append(findings, Finding{Statement: statement, Node: node,
				Reason: fmt.Sprintf("a citation to %s comes from another context snapshot; "+
					"WIKI-2 binds the page to one", c.Path())})
		case c.Revision() != page.Revision:
			findings = append(findings, Finding{Statement: statement, Node: node,
				Reason: fmt.Sprintf("a citation to %s comes from another revision", c.Path())})
		}
	}
	return findings
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].Statement != f[j].Statement {
			return f[i].Statement < f[j].Statement
		}
		if f[i].Node != f[j].Node {
			return f[i].Node < f[j].Node
		}
		return f[i].Reason < f[j].Reason
	})
}

// String renders a report for a generation log.
func (r Report) String() string {
	if r.Publishable() {
		return fmt.Sprintf("publishable: %d cited, %d inferred, %d narrative (%.0f%% cited)",
			r.Cited, r.Inferred, r.Narrative, r.EvidenceRatio()*100)
	}
	return fmt.Sprintf("not publishable: %s", plural(len(r.Findings), "finding"))
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
