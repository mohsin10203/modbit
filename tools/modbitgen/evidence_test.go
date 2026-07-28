package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The evidence gate had no tests of its own. That is a circular hole worth naming: it is the check
// every other capability's coverage claim rests on, and until now nothing demonstrated that it can
// fail. A gate nobody has seen fail is indistinguishable from one that passes everything.

// fixture writes a small tree of test files and returns its root.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for path, body := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	return root
}

func testFile(pkg string, names ...string) string {
	var b strings.Builder
	b.WriteString("package " + pkg + "\n\nimport \"testing\"\n\n")
	for _, name := range names {
		b.WriteString("func " + name + "(t *testing.T) {}\n")
	}
	return b.String()
}

func catalogWith(tests ...string) *capabilityCatalog {
	return &capabilityCatalog{Capabilities: []capability{{
		ID: "test.capability", Version: 1, Owner: "platform",
		SecurityClass: "critical", Tests: tests, source: "fixture.yaml",
	}}}
}

// A capability citing a test that does not exist must fail the build. This is the whole point of
// the gate: a renamed or deleted test otherwise leaves the registry reporting coverage it lost.
func TestMissingEvidenceIsFatal(t *testing.T) {
	root := fixture(t, map[string]string{
		"pkg/thing/thing_test.go": testFile("thing", "TestPresent"),
	})

	if err := verifyCapabilityEvidence(catalogWith("pkg/thing:TestPresent"), root); err != nil {
		t.Fatalf("a citation of an existing test was rejected: %v", err)
	}

	err := verifyCapabilityEvidence(catalogWith("pkg/thing:TestRenamedAway"), root)
	if err == nil {
		t.Fatalf("a citation of a nonexistent test was accepted")
	}
	if !strings.Contains(err.Error(), "TestRenamedAway") {
		t.Fatalf("the error does not name the missing test: %v", err)
	}
}

// An external reference must match a declared form. A typo that passes as an external suite is how
// the gate stops gating without anyone noticing.
func TestExternalEvidenceMustMatchADeclaredForm(t *testing.T) {
	root := fixture(t, map[string]string{
		"pkg/thing/thing_test.go": testFile("thing", "TestPresent"),
	})

	if err := verifyCapabilityEvidence(catalogWith("conformance/model-adapter"), root); err != nil {
		t.Fatalf("a declared external form was rejected: %v", err)
	}
	if err := verifyCapabilityEvidence(catalogWith("confrmance/typo"), root); err == nil {
		t.Fatalf("a misspelled external prefix was accepted as evidence")
	}
}

// A TestSecurity... test no capability cites is adversarial work nobody is counting.
func TestOrphanedSecurityTestsAreReported(t *testing.T) {
	root := fixture(t, map[string]string{
		"pkg/thing/thing_test.go": testFile("thing", "TestSecurityCited", "TestSecurityForgotten", "TestOrdinary"),
	})

	orphans, err := orphanedSecurityTests(catalogWith("pkg/thing:TestSecurityCited"), root)
	if err != nil {
		t.Fatalf("orphanedSecurityTests: %v", err)
	}
	if len(orphans) != 1 || orphans[0] != "pkg/thing:TestSecurityForgotten" {
		t.Fatalf("orphans = %v, want exactly [pkg/thing:TestSecurityForgotten]", orphans)
	}
}

// A whole tested package no capability claims is behaviour the registry cannot see.
//
// This is the case that motivated the check. `pkg/event` held seventeen tests and no capability, and
// the orphan check above stayed silent because none of them were named `TestSecurity...` — so the
// registry reported full health while a package's worth of behaviour was invisible to it.
func TestUnclaimedPackagesAreReported(t *testing.T) {
	root := fixture(t, map[string]string{
		"pkg/claimed/a_test.go":   testFile("claimed", "TestClaimed"),
		"pkg/unclaimed/b_test.go": testFile("unclaimed", "TestUnclaimedOne", "TestUnclaimedTwo"),
	})

	unclaimed, err := unclaimedPackages(catalogWith("pkg/claimed:TestClaimed"), root)
	if err != nil {
		t.Fatalf("unclaimedPackages: %v", err)
	}
	if len(unclaimed) != 1 {
		t.Fatalf("unclaimed = %v, want exactly one entry", unclaimed)
	}
	if !strings.Contains(unclaimed[0], "pkg/unclaimed") {
		t.Fatalf("unclaimed = %v, want the unclaimed package named", unclaimed)
	}
	// The count is reported because "2 tests" and "20 tests" are different sizes of gap.
	if !strings.Contains(unclaimed[0], "2 tests") {
		t.Fatalf("unclaimed = %v, want the test count reported", unclaimed)
	}
}

// A package on the infrastructure allowlist is claimed by nothing on purpose, and must stay quiet.
//
// The allowlist is the pressure valve that keeps the check honest: without it, the only way to
// silence a permanently-unclaimed infrastructure package would be to invent a product capability
// for it, which ADR-0100 forbids — or to delete the check.
func TestInfrastructurePackagesAreNotReportedAsUnclaimed(t *testing.T) {
	for pkg, reason := range infrastructurePackages {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s is allowlisted with no reason; an entry without one is an exemption, not a decision", pkg)
		}
	}

	root := fixture(t, map[string]string{
		"pkg/claimed/a_test.go": testFile("claimed", "TestClaimed"),
		"pkg/modberr/b_test.go": testFile("modberr", "TestErrorCode"),
	})

	unclaimed, err := unclaimedPackages(catalogWith("pkg/claimed:TestClaimed"), root)
	if err != nil {
		t.Fatalf("unclaimedPackages: %v", err)
	}
	if len(unclaimed) != 0 {
		t.Fatalf("unclaimed = %v, want none: pkg/modberr is allowlisted infrastructure", unclaimed)
	}
}

// A package with no test functions is not an unclaimed package — it is a package with nothing to
// claim. Reporting it would train readers to ignore the list.
func TestPackagesWithoutTestsAreNotReported(t *testing.T) {
	root := fixture(t, map[string]string{
		"pkg/claimed/a_test.go": testFile("claimed", "TestClaimed"),
		"pkg/helpers/help.go":   "package helpers\n\nfunc Help() {}\n",
	})

	unclaimed, err := unclaimedPackages(catalogWith("pkg/claimed:TestClaimed"), root)
	if err != nil {
		t.Fatalf("unclaimedPackages: %v", err)
	}
	if len(unclaimed) != 0 {
		t.Fatalf("unclaimed = %v, want none: pkg/helpers has no tests", unclaimed)
	}
}
