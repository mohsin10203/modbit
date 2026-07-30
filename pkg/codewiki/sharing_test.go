package codewiki_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/codewiki"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// Sharing and configuration invariants (W16–W22). One test each; a test without a W-number, or a
// W-number without a test, is a gap. W1–W8 cover the citation validator, W9–W15 generation.
//
//	W16 WIKI-22 / rejected element 7: a private repository's wiki cannot be published publicly.
//	W17 WIKI-22: publishing is off by default, and the zero Visibility is private.
//	W18 WIKI-14: an annotation is attributed, and lives outside the citation-validated statements.
//	W19 WIKI-12: an explicit page overrides cluster planning for its path and not globally.
//	W20 WIKI-15: every configuration problem is reported, with its line.
//	W21 WIKI-13: a rename carries annotations, configuration and hierarchy with it.
//	W22 WIKI-11: one schema serves the UI and YAML, so a UI caller needs no line map.

func share() codewiki.Share {
	return codewiki.Share{
		RepositoryID: "acme/api", Requested: codewiki.VisibilityPublic,
		RepositoryVisibility: codewiki.VisibilityPublic, PolicyPermitsPublishing: true,
	}
}

// W16. The case the PRD rejected outright.
//
// A wiki generated from a private repository, published publicly. Easy to reach because the wiki
// feels like a separate artifact — prose somebody generated, not the code — and it is a description
// of the private code detailed enough to be worth writing down.
func TestSecurityAPrivateRepositorysWikiCannotBePublished(t *testing.T) {
	s := share()
	s.RepositoryVisibility = codewiki.VisibilityPrivate

	err := s.Authorize()
	if err == nil {
		t.Fatal("a private repository's wiki was published publicly")
	}
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Errorf("error = %v, want POLICY_DENIED", err)
	}
	if !strings.Contains(err.Error(), "not public") {
		t.Errorf("error = %v; it must name the repository's visibility as the reason", err)
	}

	// A public repository's wiki may be published.
	if err := share().Authorize(); err != nil {
		t.Fatalf("a public repository's wiki was refused: %v", err)
	}

	// Keeping it private needs no publishing permission and no public repository.
	private := codewiki.Share{RepositoryID: "acme/api", Requested: codewiki.VisibilityPrivate}
	if err := private.Authorize(); err != nil {
		t.Fatalf("keeping a wiki private was refused: %v", err)
	}
	if err := (codewiki.Share{}).Authorize(); err == nil {
		t.Fatal("a share naming no repository was authorized")
	}
}

// W17. WIKI-22: publishing is optional and disabled by default.
func TestSecurityPublishingIsOffByDefaultAndTheZeroVisibilityIsPrivate(t *testing.T) {
	var zero codewiki.Visibility
	if zero != codewiki.VisibilityPrivate {
		t.Fatalf("the zero Visibility is %q, want private", zero)
	}

	// A deployment that has not enabled publishing has not enabled it, whatever the repository is.
	s := share()
	s.PolicyPermitsPublishing = false
	err := s.Authorize()
	if err == nil {
		t.Fatal("a wiki was published in a deployment that has not enabled publishing")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("error = %v; the deployment's stance must be the stated reason", err)
	}

	// Both gates must pass, so neither can stand in for the other.
	neither := share()
	neither.PolicyPermitsPublishing = false
	neither.RepositoryVisibility = codewiki.VisibilityPrivate
	if err := neither.Authorize(); err == nil {
		t.Fatal("a private repository was published in a deployment that forbids publishing")
	}
}

// W18. WIKI-14: generated content and user annotations stay apart.
//
// The cheap way to satisfy the requirement is a flag on each statement, and it works until
// something appends to the wrong list — then WIKI-3's citation rule either starts rejecting human
// prose or starts accepting uncited generated claims. The second is the one that ships.
func TestSecurityAnAnnotationIsAttributedAndOutsideTheCitationRules(t *testing.T) {
	a := codewiki.Annotation{
		PagePath: "arch.md", AuthorID: "user-3",
		Body: "this module is overdue for a rewrite",
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("a complete annotation was refused: %v", err)
	}

	for name, mutate := range map[string]func(*codewiki.Annotation){
		"no page":   func(a *codewiki.Annotation) { a.PagePath = "" },
		"no author": func(a *codewiki.Annotation) { a.AuthorID = " " },
		"no body":   func(a *codewiki.Annotation) { a.Body = "" },
	} {
		an := a
		mutate(&an)
		if err := an.Validate(); err == nil {
			t.Errorf("%s: an unattributable annotation validated", name)
		}
	}

	// The zero Author is not an attribution, and generated and user are distinguishable.
	var zero codewiki.Author
	if zero != codewiki.AuthorUnattributed {
		t.Fatalf("the zero Author is %q", zero)
	}
	if codewiki.AuthorGenerated == codewiki.AuthorUser {
		t.Fatal("generated and user-authored content are the same value")
	}

	// The structural point, asserted through the validator rather than through the type system: a
	// page carrying only annotations has no statements for WIKI-3 to reject, so a human opinion is
	// never asked to invent a source span. If annotations were merged into Statements, this page
	// would fail validation for an uncited technical claim.
	page := basePage(t, id.MustNew(id.IndexSnapshot))
	page.Statements = []codewiki.Statement{}
	report, err := codewiki.Validate(page)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("a page whose only content is a user annotation produced findings: %v",
			report.Findings)
	}
}

// W19. WIKI-12: "where configured" is per path, not global.
//
// A configuration naming one page would otherwise switch cluster planning off for the whole
// repository, and the user who added one page did not ask for that.
func TestSecurityAnExplicitPageOverridesOnlyItsOwnPath(t *testing.T) {
	clustered := []string{"arch.md", "auth.md", "db.md"}
	c := codewiki.Config{ExplicitPages: []string{"auth.md", "custom.md"}}

	got := codewiki.PlanPages(clustered, c)

	for _, want := range []string{"arch.md", "auth.md", "custom.md", "db.md"} {
		if !contains(got, want) {
			t.Errorf("%s is missing from the plan", want)
		}
	}
	if len(got) != 4 {
		t.Fatalf("plan = %v, want four pages with no duplicate for the overridden path", got)
	}

	// Clustering still contributes the pages nobody configured.
	if !contains(got, "arch.md") || !contains(got, "db.md") {
		t.Fatal("one explicit page switched cluster planning off for the repository")
	}

	// No configuration means pure clustering.
	if plain := codewiki.PlanPages(clustered, codewiki.Config{}); len(plain) != 3 {
		t.Fatalf("plan = %v with no configuration, want the three clustered pages", plain)
	}
	// An empty path in the configuration is not a page.
	blank := codewiki.PlanPages(clustered, codewiki.Config{ExplicitPages: []string{" "}})
	if len(blank) != 3 {
		t.Fatalf("plan = %v, an empty explicit path became a page", blank)
	}
}

// W20. WIKI-15: line-level diagnostics, all of them.
//
// A configuration with four mistakes should take one round trip to fix, not four.
func TestSecurityEveryConfigurationProblemIsReportedWithItsLine(t *testing.T) {
	c := codewiki.Config{
		ExplicitPages: []string{"a.md", "a.md", " "},
		Hierarchy: map[string]string{
			"b.md": "missing.md",
			"c.md": "c.md",
		},
		RequestedCoverage: []string{""},
	}
	lines := map[string]int{"a.md": 3, "b.md": 7, "c.md": 9}

	got := codewiki.ValidateConfig(c, lines)
	if len(got) < 5 {
		t.Fatalf("diagnostics = %v, want one per problem", got)
	}

	byLine := map[int]string{}
	for _, d := range got {
		byLine[d.Line] += d.Message
	}
	if !strings.Contains(byLine[3], "twice") {
		t.Errorf("the duplicate page was not reported on line 3: %v", got)
	}
	if !strings.Contains(byLine[7], "not declared") {
		t.Errorf("the undeclared parent was not reported on line 7: %v", got)
	}
	if !strings.Contains(byLine[9], "own parent") {
		t.Errorf("the self-parent was not reported on line 9: %v", got)
	}

	// Sorted by line, so a reader works down the file.
	for i := 1; i < len(got); i++ {
		if got[i-1].Line > got[i].Line {
			t.Fatalf("diagnostics are not in line order: %v", got)
		}
	}

	// A hierarchy cycle is caught, which a per-entry check alone would miss.
	cyclic := codewiki.Config{
		ExplicitPages: []string{"x.md", "y.md"},
		Hierarchy:     map[string]string{"x.md": "y.md", "y.md": "x.md"},
	}
	if diags := codewiki.ValidateConfig(cyclic, nil); len(diags) == 0 {
		t.Fatal("a hierarchy cycle produced no diagnostic")
	}

	// A valid configuration produces nothing, so the diagnostics are not noise.
	ok := codewiki.Config{
		ExplicitPages: []string{"root.md", "child.md"},
		Hierarchy:     map[string]string{"child.md": "root.md"},
	}
	if diags := codewiki.ValidateConfig(ok, nil); len(diags) != 0 {
		t.Fatalf("a valid configuration produced %v", diags)
	}
}

// W21. WIKI-13: a rename carries everything attached to the page.
//
// Annotations are the one part of a wiki that cannot be regenerated. A rename that leaves them
// behind orphans them against a path that no longer exists.
func TestSecurityARenameCarriesAnnotationsAndConfiguration(t *testing.T) {
	pages := []codewiki.Page{{Path: "old.md"}, {Path: "other.md"}}
	annotations := []codewiki.Annotation{
		{PagePath: "old.md", AuthorID: "u1", Body: "note"},
		{PagePath: "other.md", AuthorID: "u2", Body: "elsewhere"},
	}
	c := codewiki.Config{
		ExplicitPages: []string{"old.md", "other.md"},
		Hierarchy:     map[string]string{"other.md": "old.md"},
	}

	gotPages, gotAnn, gotConfig, err := codewiki.RenamePage("old.md", "new.md", pages, annotations, c)
	if err != nil {
		t.Fatalf("RenamePage: %v", err)
	}

	if gotPages[0].Path != "new.md" {
		t.Fatalf("page path = %q, want new.md", gotPages[0].Path)
	}
	if gotAnn[0].PagePath != "new.md" {
		t.Fatalf("the annotation stayed on %q and is now orphaned", gotAnn[0].PagePath)
	}
	if gotAnn[1].PagePath != "other.md" {
		t.Fatal("an unrelated annotation was moved")
	}
	if !contains(gotConfig.ExplicitPages, "new.md") {
		t.Fatalf("the configuration still names the old path: %v", gotConfig.ExplicitPages)
	}
	// The hierarchy follows too, on the parent side — the side a per-key rewrite misses.
	if gotConfig.Hierarchy["other.md"] != "new.md" {
		t.Fatalf("hierarchy parent = %q, want new.md", gotConfig.Hierarchy["other.md"])
	}

	// Renaming onto an existing page is refused rather than merging two pages silently.
	if _, _, _, err := codewiki.RenamePage("old.md", "other.md", pages, annotations, c); err == nil {
		t.Fatal("a rename collided with an existing page and was accepted")
	}
	// Renaming a page that does not exist is an error, not a no-op that reports success.
	_, _, _, err = codewiki.RenamePage("absent.md", "new.md", pages, annotations, c)
	if err == nil {
		t.Fatal("renaming a page that does not exist succeeded")
	}
	if !modberr.Is(err, modberr.CodeNotFound) {
		t.Errorf("error = %v, want NOT_FOUND", err)
	}
	// A rename to the same path is a no-op rather than a collision with itself.
	if _, _, _, err := codewiki.RenamePage("old.md", "old.md", pages, annotations, c); err != nil {
		t.Fatalf("renaming a page to its own path failed: %v", err)
	}
}

// W22. WIKI-11: one schema for the UI and YAML.
//
// Two structs kept in sync by intention drift apart the first time someone adds a field to the
// form, so there is one Config and one validator. A UI caller has no lines and passes none.
func TestOneConfigurationSchemaServesBothSurfaces(t *testing.T) {
	c := codewiki.Config{ExplicitPages: []string{"a.md", "a.md"}}

	fromYAML := codewiki.ValidateConfig(c, map[string]int{"a.md": 12})
	fromUI := codewiki.ValidateConfig(c, nil)

	if len(fromYAML) != len(fromUI) {
		t.Fatalf("the YAML path found %d problems and the UI path %d", len(fromYAML), len(fromUI))
	}
	if fromYAML[0].Message != fromUI[0].Message {
		t.Fatalf("the same configuration produced different messages: %q and %q",
			fromYAML[0].Message, fromUI[0].Message)
	}
	// The line is the only difference, and a UI caller gets zero rather than a wrong line.
	if fromYAML[0].Line != 12 {
		t.Errorf("the YAML diagnostic is on line %d, want 12", fromYAML[0].Line)
	}
	if fromUI[0].Line != 0 {
		t.Errorf("the UI diagnostic claims line %d; it has no line", fromUI[0].Line)
	}
}
