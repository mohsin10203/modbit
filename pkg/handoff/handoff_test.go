package handoff_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/handoff"
)

// HND invariants (H1–H9). One test each; a test without an H-number, or an H-number without a test,
// is a gap.
//
//	H1 HND-2: every part of the payload is required; a missing one is refused.
//	H2 HND-3/INV-2: references cross, material never does.
//	H3 HND-4: an unvalidated target refuses before anything moves.
//	H4 HND-5: differences are derived from both environments, never declared by the source.
//	H5 HND-5: all five dimensions are covered.
//	H6 INS-5: a manifest difference is reported rather than dropped, and rather than refused.
//	H7 HND-6: the return form is one of four and the zero is not one.
//	H8 INV-10: a target in another organization or Space is a boundary, not a disclosure.
//	H9 Unresolved questions are a required field, distinguishing "none" from "nobody collected them".

func task() handoff.Task {
	return handoff.Task{
		Goal: "fix the flaky login test", Plan: "reproduce, then bisect",
		Messages:            []string{"the test fails on CI only"},
		ContextRefs:         []string{"ctx-1"},
		SelectedFiles:       []string{"auth/login_test.go"},
		Revision:            "abc123",
		SettingsSnapshot:    "snap-9",
		ProfileVersion:      4,
		UnresolvedQuestions: []string{"is the CI clock skewed?"},
		SecretRefs:          []string{"ci/github-token"},
		InstructionManifest: "man-7",
		ReturnAs:            handoff.ReturnPullRequest,
	}
}

func local() handoff.Environment {
	return handoff.Environment{
		ID: "laptop", OrganizationID: "org-a", SpaceID: "space-1",
		OS: "darwin/arm64", Tools: []string{"go", "docker", "git"},
		ModelPolicy: "standard", NetworkPolicy: "open",
		Integrations: []string{"github"}, Validated: true,
	}
}

func remote() handoff.Environment {
	r := local()
	r.ID = "worker-3"
	return r
}

// H1. HND-2 lists nine things and a handoff missing one produces a remote agent working with less
// than the local one had, on a run that looks normal and is subtly wrong.
func TestSecurityEveryPartOfTheHandoffPayloadIsRequired(t *testing.T) {
	for name, mutate := range map[string]func(*handoff.Task){
		"no goal":      func(t *handoff.Task) { t.Goal = " " },
		"no plan":      func(t *handoff.Task) { t.Plan = "" },
		"no messages":  func(t *handoff.Task) { t.Messages = nil },
		"no context":   func(t *handoff.Task) { t.ContextRefs = nil },
		"no files":     func(t *handoff.Task) { t.SelectedFiles = nil },
		"no revision":  func(t *handoff.Task) { t.Revision = "" },
		"no settings":  func(t *handoff.Task) { t.SettingsSnapshot = "" },
		"no profile":   func(t *handoff.Task) { t.ProfileVersion = 0 },
		"no questions": func(t *handoff.Task) { t.UnresolvedQuestions = nil },
		"no manifest":  func(t *handoff.Task) { t.InstructionManifest = "" },
		"no return":    func(t *handoff.Task) { t.ReturnAs = handoff.ReturnUnspecified },
	} {
		tk := task()
		mutate(&tk)
		if err := tk.Validate(); err == nil {
			t.Errorf("%s: an incomplete handoff validated", name)
		}
		if _, err := handoff.Prepare(tk, local(), remote(), "man-7"); err == nil {
			t.Errorf("%s: an incomplete handoff was prepared", name)
		}
	}
	if err := task().Validate(); err != nil {
		t.Fatalf("a complete handoff was refused: %v", err)
	}
}

// H2. HND-3 and INV-2: references cross, material never does.
//
// Both halves of HND-3 matter. Not copying is the credential boundary. "Separately authorized" is
// the half that is easy to lose — a handoff carrying resolved values makes the remote's own
// authorization unreachable.
func TestSecurityAHandoffCarriesSecretReferencesAndNeverMaterial(t *testing.T) {
	for _, material := range []string{
		"ghp_" + strings.Repeat("a", 36),
		"sk-" + strings.Repeat("b", 48),
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		strings.Repeat("q", 64),
		" ",
	} {
		tk := task()
		tk.SecretRefs = []string{material}
		if err := tk.Validate(); err == nil {
			t.Errorf("a handoff carrying %.12s... validated", material)
		}
	}

	// Names cross, and the plan carries them for the remote to resolve under its own authority.
	tk := task()
	tk.SecretRefs = []string{"ci/github-token", "vault://prod/db"}
	p, err := handoff.Prepare(tk, local(), remote(), "man-7")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(p.SecretRefs) != 2 {
		t.Fatalf("secret refs = %v, want both names carried", p.SecretRefs)
	}
	for _, ref := range p.SecretRefs {
		if strings.HasPrefix(ref, "ghp_") || len(ref) > 40 {
			t.Errorf("the plan carries %q, which is not a name", ref)
		}
	}

	// A handoff needing no secrets is fine; the field is not a formality to fill.
	none := task()
	none.SecretRefs = nil
	if err := none.Validate(); err != nil {
		t.Fatalf("a handoff needing no secrets was refused: %v", err)
	}
}

// H3. HND-4: validated before handoff, not on arrival.
//
// A task that has already moved cannot be un-moved, and the user is now watching a run that will
// not start.
func TestSecurityAnUnvalidatedTargetRefusesBeforeAnythingMoves(t *testing.T) {
	unchecked := remote()
	unchecked.Validated = false
	if _, err := handoff.Prepare(task(), local(), unchecked, "man-7"); err == nil {
		t.Fatal("a handoff to an unvalidated target was prepared")
	}

	// The zero Environment is not a validated one.
	var zero handoff.Environment
	if zero.Validated {
		t.Fatal("the zero Environment reports itself validated")
	}
	if _, err := handoff.Prepare(task(), local(), zero, "man-7"); err == nil {
		t.Fatal("a handoff to an empty target was prepared")
	}

	if _, err := handoff.Prepare(task(), local(), remote(), "man-7"); err != nil {
		t.Fatalf("a handoff to a validated target was refused: %v", err)
	}
}

// H4. HND-5: differences are derived, not declared.
//
// The tempting shape is a disclosure the source fills in, and it fails the way a self-labelling
// worker does: the thing being described describes itself, and the case that matters is the one
// where it is wrong. A source that has not noticed the target lacks Docker will not disclose it.
func TestSecurityDifferencesAreDerivedFromBothEnvironments(t *testing.T) {
	poorer := remote()
	poorer.Tools = []string{"go"}
	poorer.Integrations = nil

	diffs := handoff.Differences(local(), poorer)
	if len(diffs) == 0 {
		t.Fatal("a target missing docker, git and github produced no differences")
	}

	byDim := map[string]handoff.Difference{}
	for _, d := range diffs {
		byDim[d.Dimension] = d
	}
	tools, ok := byDim["tools"]
	if !ok {
		t.Fatal("the missing tools were not reported")
	}
	for _, want := range []string{"docker", "git"} {
		if !strings.Contains(tools.Local, want) {
			t.Errorf("tools difference %q does not name %q", tools.Local, want)
		}
	}
	if _, ok := byDim["integrations"]; !ok {
		t.Fatal("the missing integration was not reported")
	}

	// Identical environments produce nothing, so the disclosure is not noise.
	if got := handoff.Differences(local(), remote()); len(got) != 0 {
		t.Fatalf("identical environments produced %v", got)
	}

	// A richer target is not a difference the user needs to weigh: gaining a tool does not change
	// what the task can do, and listing it turns a disclosure into a diff nobody reads.
	richer := remote()
	richer.Tools = append(richer.Tools, "kubectl")
	richer.Integrations = append(richer.Integrations, "jira")
	if got := handoff.Differences(local(), richer); len(got) != 0 {
		t.Fatalf("a target with extra tools reported differences: %v", got)
	}

	// The plan surfaces them and says a disclosure is required.
	p, err := handoff.Prepare(task(), local(), poorer, "man-7")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !p.RequiresDisclosure() {
		t.Fatal("a plan with differences did not require disclosure")
	}
	if !strings.Contains(p.Describe(), "docker") {
		t.Fatalf("describe = %q, must name the missing tool", p.Describe())
	}
}

// H5. HND-5 names five dimensions and each must be covered on its own.
func TestSecurityAllFiveDifferenceDimensionsAreCovered(t *testing.T) {
	if len(handoff.DifferenceDimensions) != 5 {
		t.Fatalf("dimensions = %v, want HND-5's five", handoff.DifferenceDimensions)
	}

	cases := map[string]func(*handoff.Environment){
		"os":           func(e *handoff.Environment) { e.OS = "linux/amd64" },
		"tools":        func(e *handoff.Environment) { e.Tools = []string{"go"} },
		"model_policy": func(e *handoff.Environment) { e.ModelPolicy = "restricted" },
		"network":      func(e *handoff.Environment) { e.NetworkPolicy = "deny" },
		"integrations": func(e *handoff.Environment) { e.Integrations = nil },
	}
	for _, dim := range handoff.DifferenceDimensions {
		mutate, ok := cases[dim]
		if !ok {
			t.Fatalf("dimension %q has no case, so it is untested", dim)
		}
		r := remote()
		mutate(&r)
		diffs := handoff.Differences(local(), r)
		if len(diffs) != 1 {
			t.Errorf("%s: differences = %v, want exactly one", dim, diffs)
			continue
		}
		if diffs[0].Dimension != dim {
			t.Errorf("%s: reported as %q", dim, diffs[0].Dimension)
		}
	}
}

// H6. INS-5: the manifest difference is reported rather than dropped — and rather than refused.
//
// Refusing would push users to work around the check. The requirement asks for visibility, not
// uniformity.
func TestSecurityAManifestDifferenceIsReportedNotDropped(t *testing.T) {
	same, err := handoff.Prepare(task(), local(), remote(), "man-7")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !same.ManifestPreserved {
		t.Fatal("an identical manifest was reported as differing")
	}
	if same.RequiresDisclosure() {
		t.Fatalf("an identical handoff required disclosure: %s", same.Describe())
	}

	drifted, err := handoff.Prepare(task(), local(), remote(), "man-9")
	if err != nil {
		t.Fatalf("a differing manifest was refused rather than reported: %v", err)
	}
	if drifted.ManifestPreserved {
		t.Fatal("a differing manifest was reported as preserved")
	}
	if !drifted.RequiresDisclosure() {
		t.Fatal("a manifest difference did not require disclosure")
	}
	for _, want := range []string{"man-9", "man-7"} {
		if !strings.Contains(drifted.ManifestNote, want) {
			t.Errorf("note = %q, must name %q", drifted.ManifestNote, want)
		}
	}

	// A remote reporting no manifest at all is refused: INS-5's comparison cannot be made, and
	// treating "unknown" as "preserved" is the reading that reports nothing.
	if _, err := handoff.Prepare(task(), local(), remote(), " "); err == nil {
		t.Fatal("a remote reporting no manifest was treated as preserving one")
	}
}

// H7. HND-6: the return form is one of four, and the zero is not one.
//
// A handoff whose results have nowhere to go produces work nobody can review.
func TestSecurityTheReturnFormIsOneOfFour(t *testing.T) {
	if handoff.ReturnUnspecified.Valid() {
		t.Fatal("the zero ReturnForm reports itself valid")
	}
	if handoff.ReturnForm("email").Valid() {
		t.Fatal("an invented return form reports itself valid")
	}
	for _, f := range []handoff.ReturnForm{
		handoff.ReturnBranch, handoff.ReturnPullRequest,
		handoff.ReturnArtifactBundle, handoff.ReturnPatch,
	} {
		if !f.Valid() {
			t.Errorf("%s is not accepted as a return form", f)
		}
		tk := task()
		tk.ReturnAs = f
		if err := tk.Validate(); err != nil {
			t.Errorf("a handoff returning as %s was refused: %v", f, err)
		}
	}
}

// H8. INV-10: crossing an organization or Space is a boundary, not a difference to weigh.
func TestSecurityATargetInAnotherOrganizationOrSpaceIsABoundary(t *testing.T) {
	for name, mutate := range map[string]func(*handoff.Environment){
		"another organization": func(e *handoff.Environment) { e.OrganizationID = "org-b" },
		"another Space":        func(e *handoff.Environment) { e.SpaceID = "space-2" },
		"no organization":      func(e *handoff.Environment) { e.OrganizationID = "" },
		"no Space":             func(e *handoff.Environment) { e.SpaceID = "" },
	} {
		r := remote()
		mutate(&r)
		_, err := handoff.Prepare(task(), local(), r, "man-7")
		if err == nil {
			t.Errorf("%s: a handoff crossed the boundary", name)
			continue
		}
		// Not surfaced as something the user may approve past.
		if strings.Contains(err.Error(), "difference") {
			t.Errorf("%s: the boundary was reported as a difference", name)
		}
	}
}

// H9. Unresolved questions distinguish "there are none" from "nobody collected them".
//
// They are the most droppable item on HND-2's list and the most consequential: an agent that
// resumes without them does not know it is missing anything.
func TestSecurityUnresolvedQuestionsDistinguishNoneFromUncollected(t *testing.T) {
	uncollected := task()
	uncollected.UnresolvedQuestions = nil
	if err := uncollected.Validate(); err == nil {
		t.Fatal("a handoff that never collected unresolved questions validated")
	}

	// An empty non-nil list is a real answer: the user was asked and there were none.
	none := task()
	none.UnresolvedQuestions = []string{}
	if err := none.Validate(); err != nil {
		t.Fatalf("a handoff with no open questions was refused: %v", err)
	}

	// The same distinction holds for the other list fields, which have the same failure mode.
	for name, mutate := range map[string]func(*handoff.Task){
		"context refs":   func(t *handoff.Task) { t.ContextRefs = []string{} },
		"selected files": func(t *handoff.Task) { t.SelectedFiles = []string{} },
	} {
		tk := task()
		mutate(&tk)
		if err := tk.Validate(); err != nil {
			t.Errorf("%s: an explicitly empty list was refused: %v", name, err)
		}
	}
}
