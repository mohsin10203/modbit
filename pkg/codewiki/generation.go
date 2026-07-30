package codewiki

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Generation admission (WIKI-1, WIKI-5..WIKI-10).
//
// Requirements: PRD §9 WIKI-1 (generated automatically after onboarding unless disabled by policy
// or user settings), WIKI-5 (incremental refresh updates affected pages), WIKI-6 (freshness
// recalculated when indexed symbols or dependency edges change), WIKI-7 (quick, balanced, deep or
// custom effort with an estimated cost and duration class), WIKI-8 (in-progress generation can be
// cancelled), WIKI-9 (failures retain completed pages and expose retryable stages), WIKI-10 (a
// dedicated documentation model remains provider-policy compliant).
//
// # A dedicated model is not an exemption
//
// WIKI-10 says CodeWiki may use a dedicated documentation model *but remains provider-policy
// compliant*. The "but" is the requirement. A dedicated model arrives as a special case in the
// config — a different provider, chosen for prose quality — and the natural place to wire it is
// around whatever picks models for runs, which is also where the policy check lives. Then a
// deployment that forbids a provider finds its repositories being documented by that provider.
//
// So the documentation model is checked against the same policy, and there is no field here that
// exempts it.
//
// # A failure that discards completed pages is worse than the failure
//
// WIKI-9 asks that failures retain completed pages and expose retryable stages, and both halves are
// about the same thing: a wiki generation over a large repository is expensive, and a run that
// throws away four hours of finished pages because stage six failed will be retried from scratch
// or not at all. Neither is what anybody wanted.

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// Effort is WIKI-7's generation effort.
type Effort string

const (
	// EffortUnspecified is the zero value and is never admissible. Generation effort is what a user
	// is agreeing to spend, and defaulting it silently spends their budget on their behalf.
	EffortUnspecified Effort = ""
	EffortQuick       Effort = "quick"
	EffortBalanced    Effort = "balanced"
	EffortDeep        Effort = "deep"
	EffortCustom      Effort = "custom"
)

// Valid reports whether e is one of WIKI-7's four.
func (e Effort) Valid() bool {
	switch e {
	case EffortQuick, EffortBalanced, EffortDeep, EffortCustom:
		return true
	}
	return false
}

// DurationClass is WIKI-7's coarse duration estimate.
//
// A class rather than a number, because a generation estimate that says "14 minutes" will be wrong
// and will be quoted back. A class is honest about its own precision.
type DurationClass string

const (
	// DurationUnknown is the zero value and is never admissible on an offered effort.
	DurationUnknown       DurationClass = ""
	DurationMinutes       DurationClass = "minutes"
	DurationTensOfMinutes DurationClass = "tens_of_minutes"
	DurationHours         DurationClass = "hours"
)

// Valid reports whether d is a declared class.
func (d DurationClass) Valid() bool {
	switch d {
	case DurationMinutes, DurationTensOfMinutes, DurationHours:
		return true
	}
	return false
}

// Estimate is what a user is shown before choosing an effort (WIKI-7).
type Estimate struct {
	Effort Effort `json:"effort"`
	// CostMicros is the estimated cost. Zero is a real estimate only for a run that costs nothing,
	// which no generation does, so it is refused.
	CostMicros int64         `json:"cost_micros"`
	Currency   string        `json:"currency"`
	Duration   DurationClass `json:"duration"`
}

// Validate enforces WIKI-7's "with an estimated cost and duration class".
func (e Estimate) Validate() error {
	switch {
	case !e.Effort.Valid():
		return field("an estimate names no effort level", "effort")
	case e.CostMicros <= 0:
		// A user choosing an effort is agreeing to spend something. An estimate of nothing is not
		// an estimate, and presenting one gets the agreement without the disclosure.
		return field(fmt.Sprintf("the %s estimate quotes no cost", e.Effort), "cost_micros")
	case strings.TrimSpace(e.Currency) == "":
		return field(fmt.Sprintf("the %s estimate quotes a cost in no currency", e.Effort), "currency")
	case !e.Duration.Valid():
		return field(fmt.Sprintf("the %s estimate gives no duration class", e.Effort), "duration")
	}
	return nil
}

// Settings are the user's and the deployment's stance on generation (WIKI-1).
type Settings struct {
	// PolicyEnabled is the deployment's decision. False disables generation regardless of the user.
	PolicyEnabled bool `json:"policy_enabled"`
	// UserEnabled is the user's preference. It can turn generation off and cannot turn it on where
	// policy has turned it off — INV-9's direction: a lower scope tightens and never loosens.
	UserEnabled bool `json:"user_enabled"`
	// DocumentationProvider is WIKI-10's dedicated model provider, empty when the default is used.
	DocumentationProvider string `json:"documentation_provider,omitempty"`
	// AllowedProviders is the deployment's provider policy. Nil means no restriction; a non-nil
	// empty slice means nothing is permitted — the same nil-versus-empty distinction an allowlist
	// carries everywhere else.
	AllowedProviders []string `json:"allowed_providers"`
}

// AutoGenerate decides whether onboarding starts a generation (WIKI-1).
//
// Policy first and absolutely: a user setting that could re-enable what policy disabled would make
// the policy a suggestion, and this is the one direction INV-9 forbids.
func AutoGenerate(s Settings) (bool, string) {
	switch {
	case !s.PolicyEnabled:
		return false, "CodeWiki generation is disabled by policy"
	case !s.UserEnabled:
		return false, "CodeWiki generation is disabled in user settings"
	}
	return true, ""
}

// CheckDocumentationProvider enforces WIKI-10.
//
// The dedicated documentation model is checked against the same provider policy as everything else.
// A deployment that forbids a provider must not find its repositories documented by that provider
// because the documentation path had its own wiring.
func CheckDocumentationProvider(s Settings) error {
	provider := strings.TrimSpace(s.DocumentationProvider)
	if provider == "" {
		// No dedicated model: the default path applies and is policed where it always was.
		return nil
	}
	if s.AllowedProviders == nil {
		// No provider allowlist is defined, so nothing is restricted by it.
		return nil
	}
	for _, p := range s.AllowedProviders {
		if p == provider {
			return nil
		}
	}
	return modberr.Newf(modberr.CodePolicyDenied,
		"the documentation model provider %q is not permitted by this deployment; WIKI-10's dedicated "+
			"model is not an exemption from provider policy", provider).
		WithDetail("constraint", "documentation_provider")
}

// Freshness is a page's state relative to the index (WIKI-6).
type Freshness string

const (
	// FreshnessUnknown is the zero value and is never treated as fresh. A page whose freshness
	// nobody recomputed is one we cannot vouch for, and "fresh" as a zero value means a page goes
	// stale silently the first time nobody runs the calculation.
	FreshnessUnknown Freshness = ""
	FreshnessFresh   Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
)

// Fresh reports whether the page may be presented without a staleness warning. Only FreshnessFresh
// may.
func (f Freshness) Fresh() bool { return f == FreshnessFresh }

// Change is what moved in the index since the wiki was generated.
type Change struct {
	Symbols []string `json:"symbols"`
	Edges   []string `json:"edges"`
}

// Recalculate returns each page's freshness after a change (WIKI-6).
//
// A page that names no symbols and no edges is stale rather than fresh: it was derived from
// something, and a page that cannot say what cannot be shown to be unaffected. Reporting it fresh
// is the reading under which a page generated before this field existed never goes stale again.
func Recalculate(pages []Page, c Change) map[string]Freshness {
	moved := make(map[string]bool, len(c.Symbols)+len(c.Edges))
	for _, s := range c.Symbols {
		moved["sym:"+s] = true
	}
	for _, e := range c.Edges {
		moved["edge:"+e] = true
	}

	out := make(map[string]Freshness, len(pages))
	for _, p := range pages {
		if len(p.Symbols) == 0 && len(p.Edges) == 0 {
			out[p.Path] = FreshnessStale
			continue
		}
		state := FreshnessFresh
		for _, s := range p.Symbols {
			if moved["sym:"+s] {
				state = FreshnessStale
			}
		}
		for _, e := range p.Edges {
			if moved["edge:"+e] {
				state = FreshnessStale
			}
		}
		out[p.Path] = state
	}
	return out
}

// Affected returns the pages an incremental refresh must regenerate (WIKI-5), sorted.
//
// Derived from Recalculate rather than computed separately, so "which pages are stale" and "which
// pages do we rebuild" cannot drift apart — two implementations of the same question is how a page
// ends up marked stale forever because the refresh planner disagrees about it.
func Affected(pages []Page, c Change) []string {
	freshness := Recalculate(pages, c)
	var out []string
	for id, f := range freshness {
		if !f.Fresh() {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// StageState is where a generation stage got to (WIKI-9).
type StageState string

const (
	// StagePending is the zero value.
	StagePending   StageState = ""
	StageComplete  StageState = "complete"
	StageFailed    StageState = "failed"
	StageCancelled StageState = "cancelled"
)

// Stage is one step of a generation run.
type Stage struct {
	Name  string     `json:"name"`
	State StageState `json:"state"`
	// Retryable declares whether re-running this stage could succeed. Declared rather than inferred
	// from the state, because a stage that failed because the repository is malformed will fail
	// again, and offering a retry button for it wastes the run and the user's patience.
	Retryable bool `json:"retryable"`
	// Pages are the pages this stage completed.
	Pages []string `json:"pages"`
}

// Outcome is what survives a generation run that did not finish (WIKI-8, WIKI-9).
type Outcome struct {
	// CompletedPages are the pages that finished and are kept. WIKI-9 and WIKI-8 both require this:
	// a run that discards four hours of finished pages because stage six failed will be retried from
	// scratch or not at all, and neither is what anybody wanted.
	CompletedPages []string `json:"completed_pages"`
	// RetryableStages are the stages worth running again.
	RetryableStages []string `json:"retryable_stages,omitempty"`
	// TerminalStages failed in a way that re-running will not fix.
	TerminalStages []string `json:"terminal_stages,omitempty"`
	// Cancelled distinguishes WIKI-8's cancellation from WIKI-9's failure. Both keep their pages and
	// they are not the same event: one is a user changing their mind and the other is a defect.
	Cancelled bool `json:"cancelled"`
}

// Conclude assembles what a stopped generation leaves behind (WIKI-8, WIKI-9).
func Conclude(stages []Stage, cancelled bool) (Outcome, error) {
	out := Outcome{Cancelled: cancelled, CompletedPages: []string{}}
	for _, s := range stages {
		if strings.TrimSpace(s.Name) == "" {
			return Outcome{}, field("a generation stage has no name", "name")
		}
		// Pages completed by a stage are kept whatever the stage's final state: a stage that failed
		// after writing three pages wrote three real pages.
		out.CompletedPages = append(out.CompletedPages, s.Pages...)

		switch s.State {
		case StageFailed:
			if s.Retryable {
				out.RetryableStages = append(out.RetryableStages, s.Name)
			} else {
				out.TerminalStages = append(out.TerminalStages, s.Name)
			}
		case StageCancelled, StagePending:
			// A cancelled or never-started stage is retryable by construction: nothing about it
			// failed.
			out.RetryableStages = append(out.RetryableStages, s.Name)
		}
	}
	sort.Strings(out.CompletedPages)
	sort.Strings(out.RetryableStages)
	sort.Strings(out.TerminalStages)
	return out, nil
}
