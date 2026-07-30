// Package insights admits generated session analysis (§23.22).
//
// Boundary: it decides whether an insight may be published and what it must carry. It analyses no
// run, computes no metric, and calls no model — a caller supplies observations and this decides
// whether they support a recommendation.
//
// Requirements: PRD §23.22 Session Insights Service — classify run size and outcome, identify
// repeated user corrections, detect missing context, environment, rule, Skill or settings
// configuration, produce actionable recommendations, aggregate quality and cost metrics, suggest
// reusable Playbooks or Agent Profile improvements, and: "Insights must be visibly labeled as
// generated analysis and remain subject to retention policy." INV-10 governs aggregation.
//
// # A recommendation is the most persuasive thing this system produces
//
// §23.22 requires insights to be visibly labelled as generated analysis, and the reason is the same
// one behind WIKI-3's labelled inferences, with more force. A CodeWiki page says what the code does
// and a reader can check it. An insight says "your team keeps correcting the agent about error
// handling; consider adding a Rule" — a claim about people, derived from a sample, phrased as
// advice. It is acted on rather than verified.
//
// So the label is not a display concern. An insight cannot be constructed without it, the same way
// LCD-3's degradation cannot be constructed without a reason.
//
// # Two is not a pattern
//
// "Repeated user corrections" needs a floor, for the reason MEM-2 refuses to promote on a single
// trajectory: a correction that happened twice in two runs is a coincidence with a sample size, and
// a recommendation built on it tells a team to change how they work on the strength of nothing.
package insights

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// Label marks how an insight was produced.
type Label string

const (
	// LabelUnlabelled is the zero value and is never publishable. An insight nobody labelled is
	// rendered as whatever the surface's default is, and the default is not "generated analysis".
	LabelUnlabelled Label = ""
	// LabelGeneratedAnalysis is the only label this package produces. There is deliberately no
	// "verified" label: nothing here verifies anything, and offering the value would invite it.
	LabelGeneratedAnalysis Label = "generated_analysis"
)

// Valid reports whether l may be published.
func (l Label) Valid() bool { return l == LabelGeneratedAnalysis }

// Kind is what an insight is about (§23.22's responsibilities).
type Kind string

const (
	// KindUnspecified is the zero value and is never admissible.
	KindUnspecified Kind = ""
	// KindRepeatedCorrection reports a correction pattern across runs.
	KindRepeatedCorrection Kind = "repeated_correction"
	// KindMissingConfiguration reports absent context, environment, rule, Skill or settings.
	KindMissingConfiguration Kind = "missing_configuration"
	// KindProfileImprovement suggests an Agent Profile or Playbook change.
	KindProfileImprovement Kind = "profile_improvement"
	// KindCostQuality reports an aggregate quality or cost movement.
	KindCostQuality Kind = "cost_quality"
)

// Valid reports whether k is a declared kind.
func (k Kind) Valid() bool {
	switch k {
	case KindRepeatedCorrection, KindMissingConfiguration, KindProfileImprovement, KindCostQuality:
		return true
	}
	return false
}

// ConfigurationArea is what §23.22 asks to be checked for absence.
type ConfigurationArea string

const (
	AreaContext     ConfigurationArea = "context"
	AreaEnvironment ConfigurationArea = "environment"
	AreaRule        ConfigurationArea = "rule"
	AreaSkill       ConfigurationArea = "skill"
	AreaSettings    ConfigurationArea = "settings"
)

// ConfigurationAreas are the five §23.22 names.
var ConfigurationAreas = []ConfigurationArea{
	AreaContext, AreaEnvironment, AreaRule, AreaSkill, AreaSettings,
}

// Presence is what a configuration check found.
type Presence string

const (
	// PresenceNotChecked is the zero value. Distinct from absent, because a recommendation to add a
	// Rule is worthless if nobody looked at whether one exists, and the two produce the same
	// "there is no Rule here" if collapsed.
	PresenceNotChecked Presence = ""
	PresencePresent    Presence = "present"
	PresenceAbsent     Presence = "absent"
)

// MinRuns is how many runs must show a correction before it is a pattern.
//
// Three, for the reason MEM-2 refuses to promote on a single trajectory and benchmark.MinTrials
// refuses a rate from one: a correction that happened twice is a coincidence with a sample size,
// and a recommendation built on it tells a team to change how they work on the strength of nothing.
const MinRuns = 3

// Observation is what was seen across a set of runs.
type Observation struct {
	// OrganizationID scopes the aggregation. Insights never span organizations (INV-10).
	OrganizationID string `json:"organization_id"`
	// RunIDs are the runs this observation covers. They are the evidence: a recommendation citing
	// none is an opinion in the shape of a finding.
	RunIDs []string `json:"run_ids"`
	// CorrectionTopic is what users kept correcting, for KindRepeatedCorrection.
	CorrectionTopic string `json:"correction_topic,omitempty"`
	// RunsWithCorrection is how many of RunIDs showed it.
	RunsWithCorrection int `json:"runs_with_correction,omitempty"`
	// Configuration is what each area check found, for KindMissingConfiguration.
	Configuration map[ConfigurationArea]Presence `json:"configuration,omitempty"`
}

// Insight is a publishable piece of generated analysis.
type Insight struct {
	Kind Kind `json:"kind"`
	// Label is required and may only be LabelGeneratedAnalysis. See the package comment for why it
	// is a constructed property rather than a rendering choice.
	Label          Label  `json:"label"`
	OrganizationID string `json:"organization_id"`
	// Statement is the finding.
	Statement string `json:"statement"`
	// Recommendation is what to do about it. §23.22 asks for actionable recommendations, and an
	// insight that describes a problem without one is a complaint.
	Recommendation string `json:"recommendation"`
	// DerivedFrom are the runs. Required: this is what makes the analysis checkable.
	DerivedFrom []string `json:"derived_from"`
	// GeneratedAt is when it was produced, for the retention window.
	GeneratedAt time.Time `json:"generated_at"`
}

// Validate enforces §23.22's labelling and evidence requirements.
func (i Insight) Validate() error {
	switch {
	case !i.Kind.Valid():
		return field("an insight declares no kind", "kind")
	case !i.Label.Valid():
		// Not a display concern. An insight nobody labelled renders as whatever the surface's
		// default is, and the default is not "generated analysis".
		return field(fmt.Sprintf(
			"a %s insight is not labelled as generated analysis; it is a claim derived from a sample "+
				"and phrased as advice, and it will be acted on rather than checked", i.Kind), "label")
	case strings.TrimSpace(i.OrganizationID) == "":
		return field("an insight names no organization", "organization_id")
	case strings.TrimSpace(i.Statement) == "":
		return field("an insight states nothing", "statement")
	case strings.TrimSpace(i.Recommendation) == "":
		return field(fmt.Sprintf(
			"the insight %q recommends nothing; §23.22 asks for actionable recommendations and an "+
				"insight that describes a problem without one is a complaint", i.Statement),
			"recommendation")
	case len(i.DerivedFrom) == 0:
		return field(fmt.Sprintf(
			"the insight %q cites no runs; a recommendation from no evidence is an opinion in the shape "+
				"of a finding", i.Statement), "derived_from")
	case i.GeneratedAt.IsZero():
		// Without this the retention window cannot be applied, and an insight outlives the data it
		// was derived from.
		return field(fmt.Sprintf("the insight %q has no timestamp", i.Statement), "generated_at")
	}
	return nil
}

// Expired reports whether the insight has passed the retention window (§23.22).
//
// A zero window means no retention limit is configured, which is the only reading that does not
// silently delete: an unconfigured deployment keeping insights is recoverable, one discarding them
// is not.
func (i Insight) Expired(window time.Duration, now time.Time) bool {
	if window <= 0 {
		return false
	}
	return now.Sub(i.GeneratedAt) > window
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// CorrectionInsight produces a repeated-correction insight, or explains why there is none.
//
// Returns ok=false with a reason rather than an error when the evidence is simply insufficient:
// "not enough runs yet" is an ordinary outcome and making it an error would push a caller to ignore
// errors from this function.
func CorrectionInsight(o Observation, now time.Time) (Insight, bool, string) {
	if strings.TrimSpace(o.OrganizationID) == "" {
		return Insight{}, false, "the observation names no organization"
	}
	if strings.TrimSpace(o.CorrectionTopic) == "" {
		return Insight{}, false, "the observation names no correction topic"
	}
	if len(o.RunIDs) < MinRuns {
		return Insight{}, false, fmt.Sprintf(
			"%d run(s) observed and %d are needed before a correction is a pattern",
			len(o.RunIDs), MinRuns)
	}
	if o.RunsWithCorrection < MinRuns {
		// The floor is on the runs that *showed* it, not on the runs observed. Two corrections
		// across fifty runs is a rarer coincidence, not a stronger one.
		return Insight{}, false, fmt.Sprintf(
			"the correction appeared in %d run(s) and %d are needed", o.RunsWithCorrection, MinRuns)
	}
	if o.RunsWithCorrection > len(o.RunIDs) {
		return Insight{}, false, "more runs showed the correction than were observed"
	}

	return Insight{
		Kind: KindRepeatedCorrection, Label: LabelGeneratedAnalysis,
		OrganizationID: o.OrganizationID,
		Statement: fmt.Sprintf("users corrected the agent about %s in %d of %d runs",
			o.CorrectionTopic, o.RunsWithCorrection, len(o.RunIDs)),
		Recommendation: fmt.Sprintf(
			"consider a Rule or Agent Profile change covering %s", o.CorrectionTopic),
		DerivedFrom: append([]string(nil), o.RunIDs...),
		GeneratedAt: now,
	}, true, ""
}

// MissingConfiguration reports the areas found absent, and refuses to guess about unchecked ones.
//
// An area nobody checked is not reported as missing. Recommending that a team add a Rule when
// nobody looked at whether one exists is the failure this distinction prevents, and it is the one
// that destroys trust in the whole feature the first time it happens.
func MissingConfiguration(o Observation) (absent, unchecked []ConfigurationArea) {
	for _, area := range ConfigurationAreas {
		switch o.Configuration[area] {
		case PresenceAbsent:
			absent = append(absent, area)
		case PresencePresent:
		default:
			unchecked = append(unchecked, area)
		}
	}
	sort.Slice(absent, func(i, j int) bool { return absent[i] < absent[j] })
	sort.Slice(unchecked, func(i, j int) bool { return unchecked[i] < unchecked[j] })
	return absent, unchecked
}

// Aggregate combines insights for presentation, refusing to cross an organization (INV-10).
//
// The organization is a parameter rather than being read from the first insight, because deriving
// the scope from the data means a single mis-scoped record silently widens it.
func Aggregate(organizationID string, in []Insight, window time.Duration, now time.Time) ([]Insight, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, field("an aggregation names no organization", "organization_id")
	}
	var out []Insight
	for _, i := range in {
		if err := i.Validate(); err != nil {
			return nil, err
		}
		if i.OrganizationID != organizationID {
			// INV-10. Not filtered silently: an insight that reached this call from another
			// organization means something upstream is mis-scoped, and quietly dropping it leaves
			// that in place.
			return nil, modberr.Newf(modberr.CodePolicyDenied,
				"an insight for %s was aggregated under %s", i.OrganizationID, organizationID).
				WithDetail("constraint", "tenant_aggregation")
		}
		if i.Expired(window, now) {
			continue
		}
		out = append(out, i)
	}
	return out, nil
}
