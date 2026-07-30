// Package review validates review findings and verifier independence (REV-3, REV-5, VAD-6).
//
// Boundary: it checks that a finding carries what a reader needs to act on it, suppresses findings
// already seen or dismissed, and decides whether a verifier was independent of the implementer. It
// runs no review, calls no model, and forms no opinion about code.
//
// Requirements: PRD §11 REV-3, REV-5; §11B VAD-6.
//
// # Why "model family" is supplied rather than inferred
//
// VAD-6 requires the verifier to run on "a different model family" than the implementer. The phrase
// appears exactly once in the PRD and is never defined — there is no family taxonomy in the pack,
// and inferring one from model-id strings would mean deciding that `claude-3-opus` and
// `claude-3-haiku` are related while `gpt-4o` is not, on the strength of a prefix.
//
// That guess would be wrong in the direction that matters. Two models from one vendor sharing
// training lineage are exactly the case VAD-6 exists to prevent, and a naming convention is not
// evidence of lineage — a vendor can rename, and a reseller can front another vendor's model
// entirely. So `Families` is declared configuration, and a route whose family nobody declared is
// treated as unknown rather than assumed distinct. See `Independent`.
package review

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Severity is how serious a finding is (REV-3).
type Severity string

const (
	// SeverityUnset is the zero value and is never valid on a finding. Severity drives REV-4's
	// independent-verification requirement, so a finding that defaulted to low would quietly opt out
	// of the check its severity was supposed to trigger.
	SeverityUnset  Severity = ""
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Valid reports whether s is a declared severity.
func (s Severity) Valid() bool {
	return s == SeverityLow || s == SeverityMedium || s == SeverityHigh
}

// Location identifies where a finding applies.
type Location struct {
	Path string `json:"path"`
	// Line is 1-based. Zero means the finding is about the file rather than a line.
	Line int `json:"line,omitempty"`
}

// Finding is one review result (REV-3).
type Finding struct {
	// ID is stable across runs for the same underlying issue. It is what REV-5 suppresses on, so a
	// generator producing a fresh identifier per run defeats the suppression entirely.
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	// Confidence is 0..1. REV-3 requires it because a high-severity guess and a high-severity
	// certainty need different handling, and a finding that reports only severity conflates them.
	Confidence float64  `json:"confidence"`
	Location   Location `json:"location"`
	// Rationale explains the reasoning. Evidence points at what supports it. REV-3 requires both,
	// and they are different things: rationale without evidence is an assertion, and evidence
	// without rationale makes a reader reconstruct the argument.
	Rationale string   `json:"rationale"`
	Evidence  []string `json:"evidence"`
}

// Validate enforces REV-3's five required parts.
func (f Finding) Validate() error {
	switch {
	case strings.TrimSpace(f.ID) == "":
		return field("a finding has no identifier, so it cannot be suppressed or tracked", "id")
	case !f.Severity.Valid():
		return field(fmt.Sprintf("finding %q has no valid severity", f.ID), "severity")
	case f.Confidence < 0 || f.Confidence > 1 || f.Confidence != f.Confidence:
		// The self-comparison catches NaN, which would otherwise pass every range check and compare
		// false against any threshold a policy later applies.
		return field(fmt.Sprintf("finding %q has a confidence outside 0..1", f.ID), "confidence")
	case strings.TrimSpace(f.Location.Path) == "":
		return field(fmt.Sprintf("finding %q names no location", f.ID), "location")
	case f.Location.Line < 0:
		return field(fmt.Sprintf("finding %q has a negative line", f.ID), "location")
	case strings.TrimSpace(f.Rationale) == "":
		return field(fmt.Sprintf("finding %q carries no rationale", f.ID), "rationale")
	case len(f.Evidence) == 0:
		return field(fmt.Sprintf("finding %q cites no evidence", f.ID), "evidence")
	}
	for _, e := range f.Evidence {
		if strings.TrimSpace(e) == "" {
			return field(fmt.Sprintf("finding %q cites an empty evidence reference", f.ID), "evidence")
		}
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// Disposition is a user's judgement on a finding (REV-6), used here only to suppress.
type Disposition string

const (
	// DispositionNone is the zero value: nobody has judged this finding. Distinct from every other
	// value, because an unreviewed finding and a dismissed one are opposite states and collapsing
	// them clears a queue by forgetting it.
	DispositionNone         Disposition = ""
	DispositionValid        Disposition = "valid"
	DispositionInvalid      Disposition = "invalid"
	DispositionAcceptedRisk Disposition = "accepted_risk"
	DispositionFixed        Disposition = "fixed"
)

// Valid reports whether d is one of REV-6's four judgements. The zero value is not one: it means
// nobody has looked.
func (d Disposition) Valid() bool {
	switch d {
	case DispositionValid, DispositionInvalid, DispositionAcceptedRisk, DispositionFixed:
		return true
	}
	return false
}

// Judged reports whether anybody has actually looked at this finding.
func (d Disposition) Judged() bool { return d.Valid() }

// Dismissed reports whether a disposition means the user does not want to see the finding again.
//
// `fixed` is deliberately not dismissive. A finding marked fixed and then reappearing is a
// regression, and suppressing it would hide exactly the case worth surfacing.
func (d Disposition) Dismissed() bool {
	return d == DispositionInvalid || d == DispositionAcceptedRisk
}

// Suppress applies REV-5: duplicates within the batch and previously dismissed findings are removed.
//
// It returns what survives and what it withheld, because a review that silently drops findings is
// indistinguishable from one that found fewer — and the suppressed set is what a user inspects when
// they suspect the reviewer has gone quiet.
func Suppress(findings []Finding, dismissed map[string]Disposition) (kept, suppressed []Finding, err error) {
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		if err := f.Validate(); err != nil {
			return nil, nil, err
		}
		switch {
		case seen[f.ID]:
			suppressed = append(suppressed, f)
		case dismissed[f.ID].Dismissed():
			suppressed = append(suppressed, f)
		default:
			seen[f.ID] = true
			kept = append(kept, f)
		}
	}
	return kept, suppressed, nil
}

// Route is the model that served one role in a run.
type Route struct {
	ProviderID string `json:"provider_id"`
	ModelID    string `json:"model_id"`
}

// Families maps a route to its declared family (VAD-6).
//
// Declared, not inferred — see the package comment. A route absent from the map has an unknown
// family, and unknown is not the same as distinct.
type Families map[Route]string

// FamilyOf returns a route's declared family and whether one was declared.
func (f Families) FamilyOf(r Route) (string, bool) {
	name, ok := f[r]
	return name, ok && strings.TrimSpace(name) != ""
}

// Diversity is the outcome of an independence check (VAD-6).
type Diversity struct {
	// Independent is true only when both families are known and differ.
	Independent bool `json:"independent"`
	// Reason explains anything other than a clean independent verdict, so a policy refusing a
	// completion can say which of the two failures happened.
	Reason string `json:"reason,omitempty"`
	// ImplementerFamily and VerifierFamily are recorded in evidence metadata, which VAD-6 requires
	// of the route difference itself rather than only of the verdict.
	ImplementerFamily string `json:"implementer_family,omitempty"`
	VerifierFamily    string `json:"verifier_family,omitempty"`
}

// Independent reports whether a verifier ran on a different model family than the implementer.
//
// An undeclared family fails closed. VAD-6 exists because two models sharing lineage can share a
// blind spot, and treating "we do not know whether these are related" as "they are unrelated" is
// precisely the assumption that produces a verifier agreeing with the implementer for the same
// wrong reason.
func Independent(families Families, implementer, verifier Route) Diversity {
	implFamily, implKnown := families.FamilyOf(implementer)
	verFamily, verKnown := families.FamilyOf(verifier)

	switch {
	case !implKnown && !verKnown:
		return Diversity{Reason: "neither route declares a model family, so independence cannot be established"}
	case !implKnown:
		return Diversity{VerifierFamily: verFamily,
			Reason: "the implementing route declares no model family"}
	case !verKnown:
		return Diversity{ImplementerFamily: implFamily,
			Reason: "the verifying route declares no model family"}
	case implFamily == verFamily:
		return Diversity{ImplementerFamily: implFamily, VerifierFamily: verFamily,
			Reason: fmt.Sprintf("the verifier ran on the same model family (%s) as the implementer",
				implFamily)}
	default:
		return Diversity{Independent: true,
			ImplementerFamily: implFamily, VerifierFamily: verFamily}
	}
}

// RequiresIndependentVerification reports whether REV-4 applies to a finding.
func (f Finding) RequiresIndependentVerification() bool { return f.Severity == SeverityHigh }

// Sort orders findings by severity descending, then location, for a stable report.
func Sort(findings []Finding) {
	rank := map[Severity]int{SeverityHigh: 0, SeverityMedium: 1, SeverityLow: 2}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].Severity] != rank[findings[j].Severity] {
			return rank[findings[i].Severity] < rank[findings[j].Severity]
		}
		if findings[i].Location.Path != findings[j].Location.Path {
			return findings[i].Location.Path < findings[j].Location.Path
		}
		return findings[i].Location.Line < findings[j].Location.Line
	})
}
