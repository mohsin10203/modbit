package rules_test

import (
	"testing"

	"github.com/modbit/modbit/pkg/rules"
	"github.com/modbit/modbit/pkg/taint"
)

// RUL invariants (P1–P8). One test each; a test without a P-number, or a P-number without a test,
// is a gap.
//
//	P1 RUL-1: precedence is deterministic and total.
//	P2 RUL-5/INV-13: a repository rule never outranks an administrator rule.
//	P3 The zero Source is repository, so an unattributed rule cannot outrank one.
//	P4 RUL-2: a conflict is surfaced, not silently resolved away.
//	P5 Agreement is not a conflict, or the real disagreements get buried.
//	P6 RUL-3: path and task-type conditions both narrow application.
//	P7 A malformed glob is refused, not treated as non-matching.
//	P8 RUL-4: the recorded hash distinguishes rules that differ only by source.

func rule(id string, src rules.Source, key, value string) rules.Rule {
	return rules.Rule{ID: id, Source: src, Key: key, Value: value}
}

// P1, P2. Precedence is deterministic, and a repository rule never wins against a trusted one.
//
// A precedence order that let repository content win would mean a file in a cloned repository could
// switch off an organization's controls — prompt injection with a config file as the delivery
// mechanism.
func TestSecurityARepositoryRuleNeverOutranksAdministratorPolicy(t *testing.T) {
	set := []rules.Rule{
		rule("repo-1", rules.SourceRepository, "run_linter", "never"),
		rule("admin-1", rules.SourceAdministrator, "run_linter", "always"),
		rule("user-1", rules.SourceUser, "run_linter", "sometimes"),
		rule("org-1", rules.SourceOrganization, "run_linter", "usually"),
	}

	// Order of input must not matter, which is RUL-1's determinism.
	for _, ordering := range [][]rules.Rule{
		set,
		{set[3], set[2], set[1], set[0]},
		{set[1], set[0], set[3], set[2]},
	} {
		got, err := rules.Resolve(ordering, rules.Context{Path: "pkg/a.go", TaskType: "code"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(got.Effective) != 1 {
			t.Fatalf("effective = %d rules, want 1 winner for one key", len(got.Effective))
		}
		if got.Effective[0].Source != rules.SourceAdministrator {
			t.Fatalf("winner came from %s, want administrator", got.Effective[0].Source)
		}
		if got.Effective[0].Value != "always" {
			t.Fatalf("value = %q, want the administrator's", got.Effective[0].Value)
		}
	}
}

// P3. The zero Source is repository — untrusted and weakest.
//
// An unattributed rule outranking an administrator's is the exact inversion RUL-5 prevents, so the
// default has to be the bottom of the order rather than the top or the middle.
func TestSecurityTheZeroSourceIsUntrustedRepository(t *testing.T) {
	var unset rules.Source
	if unset != rules.SourceRepository {
		t.Fatalf("the zero Source is %v, want repository", unset)
	}
	if unset.Trusted() {
		t.Fatal("the zero Source reports itself trusted")
	}
	if unset.Provenance() != taint.RepositoryUntrusted {
		t.Fatalf("the zero Source has provenance %v, want repository-untrusted", unset.Provenance())
	}

	got, err := rules.Resolve([]rules.Rule{
		{ID: "unattributed", Key: "run_linter", Value: "never"},
		rule("admin-1", rules.SourceAdministrator, "run_linter", "always"),
	}, rules.Context{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Effective[0].Value != "always" {
		t.Fatal("an unattributed rule outranked administrator policy")
	}
}

// P4. RUL-2: the conflict is surfaced, not resolved away.
//
// Precedence already picks a winner, so a resolver could apply it silently and still be
// deterministic. That is the failure RUL-2 names: a repository rule saying "never" and an
// administrator rule saying "always" is not a settled precedence question to either author.
func TestSecurityAConflictIsSurfacedNotSilentlyResolved(t *testing.T) {
	got, err := rules.Resolve([]rules.Rule{
		rule("repo-1", rules.SourceRepository, "run_linter", "never"),
		rule("admin-1", rules.SourceAdministrator, "run_linter", "always"),
	}, rules.Context{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1 surfaced", len(got.Conflicts))
	}
	c := got.Conflicts[0]
	if c.Winner.Source != rules.SourceAdministrator || c.Loser.Source != rules.SourceRepository {
		t.Fatalf("conflict = %+v, want administrator over repository", c)
	}
	// The trust-boundary crossing is flagged, because it is either a mistake or an attempt and an
	// operator should look at it before the others.
	if !c.AcrossTrustBoundary {
		t.Fatal("a repository rule displacing administrator policy was not flagged as crossing trust")
	}

	// Two rules from the same source disagreeing is still a conflict: authority does not settle it,
	// and the id tiebreak is for reproducibility rather than a judgement about which is right.
	got, err = rules.Resolve([]rules.Rule{
		rule("a", rules.SourceUser, "k", "1"),
		rule("b", rules.SourceUser, "k", "2"),
	}, rules.Context{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Conflicts) != 1 {
		t.Fatalf("same-source disagreement produced %d conflicts, want 1", len(got.Conflicts))
	}
	if got.Conflicts[0].AcrossTrustBoundary {
		t.Fatal("a same-source conflict was flagged as crossing trust")
	}
}

// P5. Agreement is not a conflict.
//
// Two sources stating the same thing is redundancy. Reporting it would bury the disagreements RUL-2
// exists to surface, which is how a conflict list stops being read.
func TestAgreementIsNotAConflict(t *testing.T) {
	got, err := rules.Resolve([]rules.Rule{
		rule("repo-1", rules.SourceRepository, "run_linter", "always"),
		rule("admin-1", rules.SourceAdministrator, "run_linter", "always"),
	}, rules.Context{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Conflicts) != 0 {
		t.Fatalf("conflicts = %d for two rules that agree, want 0", len(got.Conflicts))
	}
}

// P6. RUL-3: both condition kinds narrow application.
func TestConditionsNarrowByPathAndTaskType(t *testing.T) {
	set := []rules.Rule{
		{ID: "go-only", Source: rules.SourceUser, Key: "k", Value: "go",
			Condition: rules.Condition{PathGlob: "*.go"}},
		{ID: "review-only", Source: rules.SourceUser, Key: "j", Value: "rev",
			Condition: rules.Condition{TaskType: "review"}},
	}

	got, err := rules.Resolve(set, rules.Context{Path: "main.go", TaskType: "code"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Effective) != 1 || got.Effective[0].ID != "go-only" {
		t.Fatalf("effective = %+v, want only the path-matched rule", got.Effective)
	}

	got, err = rules.Resolve(set, rules.Context{Path: "readme.md", TaskType: "review"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Effective) != 1 || got.Effective[0].ID != "review-only" {
		t.Fatalf("effective = %+v, want only the task-matched rule", got.Effective)
	}
}

// P7. A malformed glob is refused rather than silently never matching.
//
// Never matching would disable a rule its author believes is active. For an administrator rule that
// means a control which is off and looks on, which is the worst of the three possible outcomes.
func TestSecurityAMalformedGlobIsRefusedNotIgnored(t *testing.T) {
	_, err := rules.Resolve([]rules.Rule{
		{ID: "bad", Source: rules.SourceAdministrator, Key: "k", Value: "v",
			Condition: rules.Condition{PathGlob: "[unclosed"}},
	}, rules.Context{Path: "a.go"})
	if err == nil {
		t.Fatal("a rule with a malformed glob resolved; the rule would be silently inactive")
	}
}

// P8. RUL-4: the hash distinguishes rules differing only by source.
//
// The same text from a repository and from an administrator are different rules. A digest that
// collapsed them would make the recorded set unable to prove which one applied.
func TestSecurityTheHashDistinguishesSource(t *testing.T) {
	repo := rule("x", rules.SourceRepository, "k", "v")
	admin := rule("x", rules.SourceAdministrator, "k", "v")
	if repo.Hash() == admin.Hash() {
		t.Fatal("identical text from different sources hashed the same")
	}

	// The set hash is stable across input ordering, or a run could not compare two resolutions.
	a, err := rules.Resolve([]rules.Rule{
		rule("1", rules.SourceUser, "a", "1"), rule("2", rules.SourceUser, "b", "2"),
	}, rules.Context{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	b, err := rules.Resolve([]rules.Rule{
		rule("2", rules.SourceUser, "b", "2"), rule("1", rules.SourceUser, "a", "1"),
	}, rules.Context{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if a.SetHash != b.SetHash {
		t.Fatalf("set hash depends on input order: %s vs %s", a.SetHash, b.SetHash)
	}
}

// Untrusted rules are separately enumerable (RUL-5).
//
// A reviewer asking what a repository told the agent should not have to filter it out of a merged
// list, which is what "distinguishable" has to mean to be useful.
func TestUntrustedRulesAreSeparatelyEnumerable(t *testing.T) {
	got, err := rules.Resolve([]rules.Rule{
		rule("repo-1", rules.SourceRepository, "style", "tabs"),
		rule("admin-1", rules.SourceAdministrator, "lint", "always"),
	}, rules.Context{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	untrusted := got.UntrustedRules()
	if len(untrusted) != 1 || untrusted[0].ID != "repo-1" {
		t.Fatalf("untrusted = %+v, want exactly the repository rule", untrusted)
	}
}

// An invalid rule fails resolution rather than being skipped.
func TestAnInvalidRuleFailsResolution(t *testing.T) {
	for name, r := range map[string]rules.Rule{
		"no id":      {Source: rules.SourceUser, Key: "k", Value: "v"},
		"no key":     {ID: "x", Source: rules.SourceUser, Value: "v"},
		"bad source": {ID: "x", Source: rules.Source(99), Key: "k", Value: "v"},
	} {
		if _, err := rules.Resolve([]rules.Rule{r}, rules.Context{}); err == nil {
			t.Errorf("%s: an invalid rule resolved", name)
		}
	}
}
