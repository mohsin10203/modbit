package authz_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/authz"
)

// R-TEN-05 invariants (Z1–Z7). One test each; a test without a Z-number, or a Z-number without a
// test, is a gap.
//
//	Z1 All ten dimensions are required; the list matches R-TEN-05.
//	Z2 The zero Verdict is NotEvaluated and denies.
//	Z3 An unevaluated dimension denies and is reported as a gap, not as a denial.
//	Z4 A single denial refuses, whatever the other nine say.
//	Z5 The refusal names one dimension, not the whole failing set.
//	Z6 An unknown dimension or verdict is refused rather than ignored.
//	Z7 An allowed decision discloses nothing about the model.

func allow() authz.Evaluation {
	e := authz.Evaluation{}
	for _, d := range authz.Dimensions() {
		e[d] = authz.Allow
	}
	return e
}

// Z1. R-TEN-05 names ten dimensions and all ten are required.
func TestAllTenDimensionsAreRequired(t *testing.T) {
	dims := authz.Dimensions()
	if len(dims) != 10 {
		t.Fatalf("R-TEN-05 names ten dimensions, the package declares %d", len(dims))
	}
	seen := map[authz.Dimension]bool{}
	for _, d := range dims {
		if seen[d] {
			t.Errorf("%s appears twice", d)
		}
		seen[d] = true
	}
	for _, want := range []authz.Dimension{
		authz.DimIdentity, authz.DimOrgRole, authz.DimSpaceMembership, authz.DimRepositoryAccess,
		authz.DimArtifactClassification, authz.DimSettingsPolicy, authz.DimServiceIdentity,
		authz.DimWorkerOwnership, authz.DimTaintState, authz.DimTrustState,
	} {
		if !seen[want] {
			t.Errorf("R-TEN-05 names %s and the package does not", want)
		}
	}

	d, err := authz.Authorize(allow())
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allow {
		t.Fatalf("a fully permitting evaluation was refused by %s", d.RefusedBy)
	}
}

// Z2, Z3. The zero Verdict denies, and a gap is reported as a gap.
//
// With a bool per dimension, a dimension nobody evaluated is indistinguishable from one that
// allowed — and with ten of them, forgetting one is a matter of time. The third state is what makes
// the omission visible instead of permissive.
func TestSecurityAnUnevaluatedDimensionDenies(t *testing.T) {
	var unset authz.Verdict
	if unset != authz.NotEvaluated {
		t.Fatalf("the zero Verdict is %q, want not-evaluated", unset)
	}
	if unset.Permits() {
		t.Fatal("the zero Verdict permits")
	}

	for _, missing := range authz.Dimensions() {
		e := allow()
		delete(e, missing)

		d, err := authz.Authorize(e)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if d.Allow {
			t.Errorf("authorization allowed with %s unevaluated", missing)
			continue
		}
		if d.RefusedBy != missing {
			t.Errorf("refused by %s, want the unevaluated %s", d.RefusedBy, missing)
		}
		// A gap and a denial need different responses: one is a permission question, the other is a
		// bug in the caller's wiring.
		if !strings.Contains(d.Reason, "not evaluated") {
			t.Errorf("%s: reason %q does not distinguish a gap from a denial", missing, d.Reason)
		}
		if len(d.Unevaluated) != 1 || d.Unevaluated[0] != missing {
			t.Errorf("%s: unevaluated = %v, want exactly it", missing, d.Unevaluated)
		}
	}
}

// Z4. One denial refuses, whatever the other nine say.
func TestSecurityASingleDenialRefuses(t *testing.T) {
	for _, denied := range authz.Dimensions() {
		e := allow()
		e[denied] = authz.Deny

		d, err := authz.Authorize(e)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if d.Allow {
			t.Errorf("authorization allowed with %s denying", denied)
		}
		if d.RefusedBy != denied {
			t.Errorf("refused by %s, want %s", d.RefusedBy, denied)
		}
		if strings.Contains(d.Reason, "not evaluated") {
			t.Errorf("%s: a denial was reported as a gap", denied)
		}
	}
}

// Z5. The refusal names one dimension, not the whole failing set.
//
// Listing every failure would tell a caller how much of the boundary they are past, which is a map
// of the remaining distance. It names the first in a fixed order, so the answer is stable and says
// one thing.
func TestSecurityTheRefusalNamesOneDimension(t *testing.T) {
	e := allow()
	e[authz.DimRepositoryAccess] = authz.Deny
	e[authz.DimTaintState] = authz.Deny
	e[authz.DimTrustState] = authz.Deny

	d, err := authz.Authorize(e)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.Allow {
		t.Fatal("three denials allowed")
	}
	// Repository access comes before taint and trust in the evaluation order.
	if d.RefusedBy != authz.DimRepositoryAccess {
		t.Fatalf("refused by %s, want the first in evaluation order", d.RefusedBy)
	}
	for _, later := range []string{string(authz.DimTaintState), string(authz.DimTrustState)} {
		if strings.Contains(d.Reason, later) {
			t.Errorf("the reason disclosed a later failing dimension %q: %q", later, d.Reason)
		}
	}
}

// Z6. An unknown dimension or verdict is refused rather than ignored.
//
// Ignoring an unrecognised dimension would let a caller believe it had supplied a check that
// nothing consumed — an authorization that silently does less than its author thinks.
func TestSecurityAnUnknownDimensionOrVerdictIsRefused(t *testing.T) {
	e := allow()
	e["moon_phase"] = authz.Allow
	if _, err := authz.Authorize(e); err == nil {
		t.Fatal("an unknown dimension was accepted")
	}

	e = allow()
	e[authz.DimIdentity] = authz.Verdict("probably")
	if _, err := authz.Authorize(e); err == nil {
		t.Fatal("an unknown verdict was accepted")
	}

	if _, err := authz.Authorize(nil); err == nil {
		t.Fatal("a nil evaluation was decided")
	}
}

// Z7. An allowed decision discloses nothing about the model.
//
// Enumerating which dimensions permitted would put the shape of the authorization model into every
// log line. The interesting record is the refusal.
func TestSecurityAnAllowedDecisionDisclosesNothing(t *testing.T) {
	d, err := authz.Authorize(allow())
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got := d.Describe(); got != "allow" {
		t.Fatalf("Describe = %q for an allowed decision, want just \"allow\"", got)
	}
	if d.RefusedBy != "" || d.Reason != "" {
		t.Fatalf("an allowed decision carries a refusal: %+v", d)
	}
}

// Complete lets a caller check its own wiring before serving traffic.
//
// Discovering a missing dimension on the first request that reaches it is the same defect found at
// the worst time.
func TestCompleteReportsMissingDimensionsUpFront(t *testing.T) {
	ok, missing := authz.Complete(allow())
	if !ok || len(missing) != 0 {
		t.Fatalf("a full evaluation reported missing = %v", missing)
	}

	partial := allow()
	delete(partial, authz.DimWorkerOwnership)
	delete(partial, authz.DimTrustState)
	ok, missing = authz.Complete(partial)
	if ok {
		t.Fatal("an evaluation missing two dimensions reported itself complete")
	}
	if len(missing) != 2 {
		t.Fatalf("missing = %v, want both", missing)
	}
}
