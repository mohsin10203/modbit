package review_test

import (
	"math"
	"testing"

	"github.com/modbit/modbit/pkg/review"
)

// REV/VAD invariants (R1–R8). One test each; a test without an R-number, or an R-number without a
// test, is a gap.
//
//	R1 REV-3: a finding without all five parts is refused.
//	R2 The zero Severity is invalid, so a finding cannot default out of REV-4.
//	R3 REV-5: a duplicate within a batch is suppressed.
//	R4 REV-5: a previously dismissed finding is suppressed.
//	R5 A finding marked fixed is NOT suppressed, because its return is a regression.
//	R6 Suppression reports what it withheld rather than dropping it silently.
//	R7 VAD-6: same-family verification is not independent.
//	R8 VAD-6: an undeclared family fails closed, because unknown is not distinct.

func good() review.Finding {
	return review.Finding{
		ID: "f1", Severity: review.SeverityHigh, Confidence: 0.9,
		Location:  review.Location{Path: "pkg/a/a.go", Line: 12},
		Rationale: "the error is discarded, so a failed write reports success",
		Evidence:  []string{"pkg/a/a.go:12"},
	}
}

// R1. REV-3 names five required parts; a finding missing any of them cannot be acted on.
func TestREV3RequiresEveryPart(t *testing.T) {
	for name, mutate := range map[string]func(*review.Finding){
		"no id":         func(f *review.Finding) { f.ID = "" },
		"no severity":   func(f *review.Finding) { f.Severity = "" },
		"bad severity":  func(f *review.Finding) { f.Severity = "catastrophic" },
		"low conf":      func(f *review.Finding) { f.Confidence = -0.1 },
		"high conf":     func(f *review.Finding) { f.Confidence = 1.1 },
		"nan conf":      func(f *review.Finding) { f.Confidence = math.NaN() },
		"no location":   func(f *review.Finding) { f.Location = review.Location{} },
		"negative line": func(f *review.Finding) { f.Location.Line = -1 },
		"no rationale":  func(f *review.Finding) { f.Rationale = "  " },
		"no evidence":   func(f *review.Finding) { f.Evidence = nil },
		"empty evidence": func(f *review.Finding) {
			f.Evidence = []string{" "}
		},
	} {
		f := good()
		mutate(&f)
		if err := f.Validate(); err == nil {
			t.Errorf("%s: a finding was accepted", name)
		}
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("a complete finding was refused: %v", err)
	}
}

// R2. The zero Severity is invalid, so a finding cannot default its way out of REV-4.
//
// REV-4 requires independent verification of high-severity findings. A severity that defaulted to
// low would silently opt out of the check its own value was supposed to trigger.
func TestSecurityTheZeroSeverityIsInvalid(t *testing.T) {
	var unset review.Severity
	if unset.Valid() {
		t.Fatal("the zero Severity reports itself valid")
	}
	f := good()
	f.Severity = unset
	if err := f.Validate(); err == nil {
		t.Fatal("a finding with no severity was accepted")
	}
	// And only high severity triggers REV-4, so the mapping must not be accidentally inclusive.
	if !(review.Finding{Severity: review.SeverityHigh}).RequiresIndependentVerification() {
		t.Error("a high-severity finding does not require independent verification")
	}
	for _, s := range []review.Severity{review.SeverityLow, review.SeverityMedium} {
		if (review.Finding{Severity: s}).RequiresIndependentVerification() {
			t.Errorf("%s severity required independent verification", s)
		}
	}
}

// R3, R6. A duplicate within one batch is suppressed and reported.
func TestREV5SuppressesDuplicatesAndReportsThem(t *testing.T) {
	a, b := good(), good()
	b.Location.Line = 99 // same ID, so it is the same underlying issue

	kept, suppressed, err := review.Suppress([]review.Finding{a, b}, nil)
	if err != nil {
		t.Fatalf("Suppress: %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("kept = %d, want 1", len(kept))
	}
	if len(suppressed) != 1 {
		t.Fatalf("suppressed = %d, want 1; a dropped finding must be reported", len(suppressed))
	}
}

// R4. A previously dismissed finding does not come back.
func TestREV5SuppressesPreviouslyDismissedFindings(t *testing.T) {
	for _, d := range []review.Disposition{review.DispositionInvalid, review.DispositionAcceptedRisk} {
		kept, suppressed, err := review.Suppress(
			[]review.Finding{good()}, map[string]review.Disposition{"f1": d})
		if err != nil {
			t.Fatalf("Suppress: %v", err)
		}
		if len(kept) != 0 || len(suppressed) != 1 {
			t.Fatalf("%s: kept=%d suppressed=%d, want 0 and 1", d, len(kept), len(suppressed))
		}
	}
}

// R5. A finding marked fixed is not suppressed, because its reappearance is a regression.
//
// This is the case where the obvious reading of REV-5 is wrong. "Previously dismissed" covers
// invalid and accepted-risk — judgements that the finding does not matter. `fixed` is a claim that
// it no longer exists, so seeing it again is news.
func TestSecurityAFixedFindingIsNotSuppressed(t *testing.T) {
	kept, suppressed, err := review.Suppress(
		[]review.Finding{good()}, map[string]review.Disposition{"f1": review.DispositionFixed})
	if err != nil {
		t.Fatalf("Suppress: %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("a finding marked fixed was suppressed on its return; that is a regression, not noise")
	}
	if len(suppressed) != 0 {
		t.Fatalf("suppressed = %d, want 0", len(suppressed))
	}
	// `valid` is likewise not dismissive: the user agreed with it.
	kept, _, err = review.Suppress(
		[]review.Finding{good()}, map[string]review.Disposition{"f1": review.DispositionValid})
	if err != nil {
		t.Fatalf("Suppress: %v", err)
	}
	if len(kept) != 1 {
		t.Fatal("a finding the user marked valid was suppressed")
	}
}

// An invalid finding fails the whole batch rather than being quietly skipped.
func TestSuppressRefusesAnInvalidFinding(t *testing.T) {
	bad := good()
	bad.Evidence = nil
	if _, _, err := review.Suppress([]review.Finding{good(), bad}, nil); err == nil {
		t.Fatal("a batch containing an invalid finding was suppressed without complaint")
	}
}

// R7. VAD-6: a verifier on the same family as the implementer is not independent.
func TestSecuritySameFamilyVerificationIsNotIndependent(t *testing.T) {
	impl := review.Route{ProviderID: "vendor-a", ModelID: "big"}
	ver := review.Route{ProviderID: "vendor-a", ModelID: "small"}
	families := review.Families{impl: "alpha", ver: "alpha"}

	d := review.Independent(families, impl, ver)
	if d.Independent {
		t.Fatal("two routes in the same declared family were reported independent")
	}
	if d.Reason == "" {
		t.Fatal("a non-independent verdict carries no reason")
	}
	// VAD-6 requires the route difference in evidence metadata, so both families are recorded even
	// when the verdict is negative.
	if d.ImplementerFamily != "alpha" || d.VerifierFamily != "alpha" {
		t.Fatalf("the verdict did not record both families: %+v", d)
	}
}

// R8. An undeclared family fails closed.
//
// This is the whole reason `Families` is configuration rather than a string heuristic. VAD-6 exists
// because two models sharing lineage can share a blind spot, so treating "nobody declared whether
// these are related" as "they are unrelated" produces exactly the verifier that agrees with the
// implementer for the same wrong reason.
func TestSecurityAnUndeclaredFamilyFailsClosed(t *testing.T) {
	impl := review.Route{ProviderID: "vendor-a", ModelID: "big"}
	ver := review.Route{ProviderID: "vendor-b", ModelID: "other"}

	for name, families := range map[string]review.Families{
		"neither declared":  {},
		"implementer only":  {impl: "alpha"},
		"verifier only":     {ver: "beta"},
		"declared as empty": {impl: "alpha", ver: "  "},
	} {
		d := review.Independent(families, impl, ver)
		if d.Independent {
			t.Errorf("%s: independence was claimed without both families declared", name)
		}
		if d.Reason == "" {
			t.Errorf("%s: no reason given", name)
		}
	}

	// Fully declared and different is the only independent case.
	d := review.Independent(review.Families{impl: "alpha", ver: "beta"}, impl, ver)
	if !d.Independent {
		t.Fatalf("two routes in different declared families were not independent: %+v", d)
	}
	if d.Reason != "" {
		t.Fatalf("an independent verdict carries a reason: %q", d.Reason)
	}
}

// Sorting is stable and severity-first, so a report does not reshuffle between runs.
func TestSortIsSeverityFirstAndStable(t *testing.T) {
	low := good()
	low.ID, low.Severity, low.Location = "low", review.SeverityLow, review.Location{Path: "a.go", Line: 1}
	high := good()
	high.ID, high.Severity, high.Location = "high", review.SeverityHigh, review.Location{Path: "z.go", Line: 9}

	findings := []review.Finding{low, high}
	review.Sort(findings)
	if findings[0].ID != "high" {
		t.Fatalf("order = %s,%s; want high severity first", findings[0].ID, findings[1].ID)
	}
}
