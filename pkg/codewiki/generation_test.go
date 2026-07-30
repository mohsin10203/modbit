package codewiki_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/codewiki"
	"github.com/modbit/modbit/pkg/modberr"
)

// Generation invariants (W9–W15). One test each; a test without a W-number, or a W-number without a
// test, is a gap. W1–W8 cover the citation validator in validate_test.go.
//
//	W9  WIKI-1: policy disables generation absolutely; a user setting cannot re-enable it.
//	W10 WIKI-10: the dedicated documentation model is not exempt from provider policy.
//	W11 WIKI-6: the zero Freshness is not fresh, and a page naming no sources is stale.
//	W12 WIKI-6: freshness moves on a changed symbol or a changed dependency edge.
//	W13 WIKI-5: the refresh set is derived from freshness, so the two cannot disagree.
//	W14 WIKI-7: an effort with no cost or no duration class cannot be offered.
//	W15 WIKI-8/WIKI-9: a stopped run keeps its completed pages and separates retryable from terminal.

func settings() codewiki.Settings {
	return codewiki.Settings{PolicyEnabled: true, UserEnabled: true}
}

// W9. WIKI-1: policy first and absolutely.
//
// A user setting that could re-enable what policy disabled would make the policy a suggestion, and
// this is the direction INV-9 forbids.
func TestSecurityAUserSettingCannotReEnableGenerationPolicyDisabled(t *testing.T) {
	on, reason := codewiki.AutoGenerate(settings())
	if !on {
		t.Fatalf("generation was not started for an enabled deployment: %s", reason)
	}

	policyOff := settings()
	policyOff.PolicyEnabled = false
	// The user wants it on. Policy says no, and policy wins.
	policyOff.UserEnabled = true
	on, reason = codewiki.AutoGenerate(policyOff)
	if on {
		t.Fatal("a user setting re-enabled generation that policy had disabled")
	}
	if !strings.Contains(reason, "policy") {
		t.Fatalf("reason = %q; a policy refusal must say so, not blame the user setting", reason)
	}

	// A user can still turn it off where policy permits it — tightening is the allowed direction.
	userOff := settings()
	userOff.UserEnabled = false
	on, reason = codewiki.AutoGenerate(userOff)
	if on {
		t.Fatal("a user who turned generation off still got it")
	}
	if !strings.Contains(reason, "user") {
		t.Fatalf("reason = %q; a user refusal must be distinguishable from a policy one", reason)
	}

	// With both off, policy is the reason reported. This is the only case where the order of the
	// two checks is observable, and it is the case that matters: telling a user their setting
	// disabled it sends them to flip a switch that changes nothing, because policy still forbids it.
	// The first version of this test never set both, and a mutant swapping the checks survived.
	bothOff := codewiki.Settings{PolicyEnabled: false, UserEnabled: false}
	on, reason = codewiki.AutoGenerate(bothOff)
	if on {
		t.Fatal("generation started with both policy and the user against it")
	}
	if !strings.Contains(reason, "policy") {
		t.Fatalf("reason = %q with both disabled; policy is the one the user cannot change", reason)
	}

	// The zero Settings generates nothing, so an unconfigured deployment does not start work.
	var zero codewiki.Settings
	if on, _ := codewiki.AutoGenerate(zero); on {
		t.Fatal("an unconfigured deployment started generating")
	}
}

// W10. WIKI-10: a dedicated documentation model remains provider-policy compliant.
//
// The "but" is the requirement. A dedicated model arrives as a special case in the config and the
// natural place to wire it is around whatever picks models for runs — which is also where the
// policy check lives. Then a deployment that forbids a provider finds itself documented by it.
func TestSecurityTheDocumentationModelIsNotExemptFromProviderPolicy(t *testing.T) {
	s := settings()
	s.DocumentationProvider = "prose-co"
	s.AllowedProviders = []string{"vendor-a", "vendor-b"}

	err := codewiki.CheckDocumentationProvider(s)
	if err == nil {
		t.Fatal("a forbidden provider was permitted because it was the documentation model")
	}
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Errorf("error = %v, want POLICY_DENIED", err)
	}

	s.AllowedProviders = []string{"vendor-a", "prose-co"}
	if err := codewiki.CheckDocumentationProvider(s); err != nil {
		t.Fatalf("a permitted documentation provider was refused: %v", err)
	}

	// No dedicated model: the default path applies and is policed where it always was.
	none := settings()
	none.AllowedProviders = []string{"vendor-a"}
	if err := codewiki.CheckDocumentationProvider(none); err != nil {
		t.Fatalf("a deployment with no dedicated documentation model was refused: %v", err)
	}

	// nil versus empty, the same distinction an allowlist carries everywhere else.
	undefined := settings()
	undefined.DocumentationProvider = "anything"
	undefined.AllowedProviders = nil
	if err := codewiki.CheckDocumentationProvider(undefined); err != nil {
		t.Fatalf("an undefined allowlist restricted a provider: %v", err)
	}
	empty := undefined
	empty.AllowedProviders = []string{}
	if err := codewiki.CheckDocumentationProvider(empty); err == nil {
		t.Fatal("a defined-but-empty allowlist permitted a provider; it permits nothing")
	}
}

// W11. WIKI-6: the zero Freshness is not fresh.
//
// "Fresh" as a zero value means a page goes stale silently the first time nobody runs the
// calculation, which is exactly when it matters.
func TestSecurityTheZeroFreshnessIsNotFresh(t *testing.T) {
	var zero codewiki.Freshness
	if zero != codewiki.FreshnessUnknown {
		t.Fatalf("the zero Freshness is %q", zero)
	}
	if zero.Fresh() {
		t.Fatal("the zero Freshness reports itself fresh")
	}
	if codewiki.FreshnessStale.Fresh() {
		t.Fatal("a stale page reports itself fresh")
	}
	if !codewiki.FreshnessFresh.Fresh() {
		t.Fatal("a fresh page does not report itself fresh")
	}

	// A page that cannot say what it was derived from cannot be shown to be unaffected. Reporting
	// it fresh is the reading under which a page generated before this field existed never goes
	// stale again.
	orphan := []codewiki.Page{{Path: "arch.md"}}
	got := codewiki.Recalculate(orphan, codewiki.Change{Symbols: []string{"unrelated"}})
	if got["arch.md"].Fresh() {
		t.Fatal("a page naming no symbols and no edges reported itself fresh")
	}
}

// W12. WIKI-6: freshness moves on a changed symbol *or* a changed dependency edge.
//
// Both, independently — a version checking only symbols passes a test that changes a symbol.
func TestSecurityFreshnessMovesOnASymbolOrAnEdge(t *testing.T) {
	pages := []codewiki.Page{
		{Path: "auth.md", Symbols: []string{"Login", "Logout"}, Edges: []string{"auth->db"}},
		{Path: "ui.md", Symbols: []string{"Render"}, Edges: []string{"ui->auth"}},
	}

	for name, tc := range map[string]struct {
		change    codewiki.Change
		wantStale string
		wantFresh string
	}{
		"symbol changed": {codewiki.Change{Symbols: []string{"Login"}}, "auth.md", "ui.md"},
		"edge changed":   {codewiki.Change{Edges: []string{"ui->auth"}}, "ui.md", "auth.md"},
	} {
		got := codewiki.Recalculate(pages, tc.change)
		if got[tc.wantStale].Fresh() {
			t.Errorf("%s: %s stayed fresh", name, tc.wantStale)
		}
		if !got[tc.wantFresh].Fresh() {
			t.Errorf("%s: %s went stale without being affected", name, tc.wantFresh)
		}
	}

	// An unrelated change leaves both fresh, so staleness is not simply always-on.
	quiet := codewiki.Recalculate(pages, codewiki.Change{Symbols: []string{"Unrelated"}})
	for _, p := range pages {
		if !quiet[p.Path].Fresh() {
			t.Errorf("%s went stale on an unrelated change", p.Path)
		}
	}

	// A symbol name and an edge name do not collide: a changed edge called "Login" must not stale a
	// page because the page uses a *symbol* called "Login".
	collide := codewiki.Recalculate(pages, codewiki.Change{Edges: []string{"Login"}})
	if !collide["auth.md"].Fresh() {
		t.Fatal("an edge named like a symbol staled a page that only uses the symbol")
	}
}

// W13. WIKI-5: the refresh set is derived from freshness.
//
// Two implementations of "which pages are affected" is how a page ends up marked stale forever
// because the refresh planner disagrees with the freshness calculation.
func TestSecurityTheRefreshSetAgreesWithFreshness(t *testing.T) {
	pages := []codewiki.Page{
		{Path: "auth.md", Symbols: []string{"Login"}},
		{Path: "ui.md", Symbols: []string{"Render"}},
		{Path: "db.md", Edges: []string{"db->fs"}},
		{Path: "orphan.md"},
	}
	change := codewiki.Change{Symbols: []string{"Login"}, Edges: []string{"db->fs"}}

	freshness := codewiki.Recalculate(pages, change)
	affected := codewiki.Affected(pages, change)

	inRefresh := map[string]bool{}
	for _, id := range affected {
		inRefresh[id] = true
	}
	for _, p := range pages {
		stale := !freshness[p.Path].Fresh()
		if stale != inRefresh[p.Path] {
			t.Errorf("%s: stale=%v but in refresh set=%v", p.Path, stale, inRefresh[p.Path])
		}
	}

	// The orphan is in the set too — a page that cannot prove it is unaffected gets rebuilt, which
	// costs a regeneration rather than leaving a wrong page up.
	if !inRefresh["orphan.md"] {
		t.Fatal("a page that cannot say what it was derived from was skipped by the refresh")
	}
	// And an unaffected page is not, or "incremental" means nothing.
	if inRefresh["ui.md"] {
		t.Fatal("an unaffected page was scheduled for regeneration")
	}
	if len(affected) != 3 {
		t.Fatalf("affected = %v, want the three that could not be shown unaffected", affected)
	}
}

// W14. WIKI-7: an effort a user cannot price is one they cannot agree to.
func TestSecurityAnEffortWithoutACostOrDurationCannotBeOffered(t *testing.T) {
	good := codewiki.Estimate{
		Effort: codewiki.EffortBalanced, CostMicros: 250000,
		Currency: "USD", Duration: codewiki.DurationTensOfMinutes,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("a complete estimate was refused: %v", err)
	}

	for name, mutate := range map[string]func(*codewiki.Estimate){
		"no effort":       func(e *codewiki.Estimate) { e.Effort = codewiki.EffortUnspecified },
		"invented effort": func(e *codewiki.Estimate) { e.Effort = "exhaustive" },
		"no cost":         func(e *codewiki.Estimate) { e.CostMicros = 0 },
		"negative cost":   func(e *codewiki.Estimate) { e.CostMicros = -1 },
		"no currency":     func(e *codewiki.Estimate) { e.Currency = " " },
		"no duration":     func(e *codewiki.Estimate) { e.Duration = codewiki.DurationUnknown },
		"bad duration":    func(e *codewiki.Estimate) { e.Duration = "a while" },
	} {
		est := good
		mutate(&est)
		if err := est.Validate(); err == nil {
			t.Errorf("%s: an unpriceable effort was offered", name)
		}
	}

	// All four of WIKI-7's levels are offerable.
	for _, e := range []codewiki.Effort{
		codewiki.EffortQuick, codewiki.EffortBalanced,
		codewiki.EffortDeep, codewiki.EffortCustom,
	} {
		est := good
		est.Effort = e
		if err := est.Validate(); err != nil {
			t.Errorf("the %s effort was refused: %v", e, err)
		}
	}
}

// W15. WIKI-8 and WIKI-9: a stopped run keeps what it finished.
//
// A run that throws away four hours of finished pages because stage six failed will be retried from
// scratch or not at all, and neither is what anybody wanted.
func TestSecurityAStoppedGenerationKeepsItsCompletedPages(t *testing.T) {
	stages := []codewiki.Stage{
		{Name: "plan", State: codewiki.StageComplete, Pages: []string{"index.md"}},
		{Name: "architecture", State: codewiki.StageComplete, Pages: []string{"arch.md", "flow.md"}},
		// Failed after writing a page: that page is real.
		{Name: "diagrams", State: codewiki.StageFailed, Retryable: true, Pages: []string{"dep.md"}},
		{Name: "prose", State: codewiki.StageFailed, Retryable: false},
		{Name: "publish", State: codewiki.StagePending},
	}

	got, err := codewiki.Conclude(stages, false)
	if err != nil {
		t.Fatalf("Conclude: %v", err)
	}
	if len(got.CompletedPages) != 4 {
		t.Fatalf("completed pages = %v, want all four that were written", got.CompletedPages)
	}
	for _, want := range []string{"arch.md", "dep.md", "flow.md", "index.md"} {
		if !contains(got.CompletedPages, want) {
			t.Errorf("%s was discarded", want)
		}
	}

	// Retryable and terminal are separated, because offering a retry for a stage that will fail
	// again wastes the run and the user's patience.
	if !contains(got.RetryableStages, "diagrams") || !contains(got.RetryableStages, "publish") {
		t.Errorf("retryable = %v, want the failed-retryable and the never-started stages",
			got.RetryableStages)
	}
	if contains(got.RetryableStages, "prose") {
		t.Error("a stage declared non-retryable was offered for retry")
	}
	if !contains(got.TerminalStages, "prose") {
		t.Errorf("terminal = %v, want prose", got.TerminalStages)
	}

	// WIKI-8's cancellation keeps its pages too, and stays distinguishable from a failure: one is a
	// user changing their mind and the other is a defect.
	cancelled, err := codewiki.Conclude([]codewiki.Stage{
		{Name: "plan", State: codewiki.StageComplete, Pages: []string{"index.md"}},
		{Name: "architecture", State: codewiki.StageCancelled},
	}, true)
	if err != nil {
		t.Fatalf("Conclude: %v", err)
	}
	if !cancelled.Cancelled {
		t.Fatal("a cancelled run did not report itself cancelled")
	}
	if got.Cancelled {
		t.Fatal("a failed run reported itself cancelled")
	}
	if len(cancelled.CompletedPages) != 1 {
		t.Fatalf("a cancelled run kept %v, want index.md", cancelled.CompletedPages)
	}
	if !contains(cancelled.RetryableStages, "architecture") {
		t.Error("a cancelled stage was not offered for retry; nothing about it failed")
	}
	if len(cancelled.TerminalStages) != 0 {
		t.Errorf("a cancellation produced terminal stages: %v", cancelled.TerminalStages)
	}

	// An unnamed stage is refused rather than producing a retry offer nobody can act on.
	if _, err := codewiki.Conclude([]codewiki.Stage{{State: codewiki.StageFailed}}, false); err == nil {
		t.Fatal("a stage with no name was concluded")
	}
}

func contains(in []string, v string) bool {
	for _, s := range in {
		if s == v {
			return true
		}
	}
	return false
}
