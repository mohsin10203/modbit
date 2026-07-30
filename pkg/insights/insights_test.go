package insights_test

import (
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/insights"
	"github.com/modbit/modbit/pkg/modberr"
)

// Session Insights invariants (Q1–Q7). One test each; a test without a Q-number, or a Q-number
// without a test, is a gap.
//
//	Q1 §23.22: an insight cannot be constructed without the generated-analysis label.
//	Q2 An insight cites the runs it came from; a recommendation from no evidence is an opinion.
//	Q3 Two corrections is not a pattern; the floor is on the runs that showed it.
//	Q4 "Not checked" is not "absent", so nobody is told to add a Rule that already exists.
//	Q5 §23.22's retention: an expired insight is not served, and an unset window does not delete.
//	Q6 INV-10: aggregation never crosses an organization, and a stray record is an error.
//	Q7 An insight that describes a problem without a recommendation is a complaint.

var now = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

func insight() insights.Insight {
	return insights.Insight{
		Kind: insights.KindRepeatedCorrection, Label: insights.LabelGeneratedAnalysis,
		OrganizationID: "org-a",
		Statement:      "users corrected the agent about error handling in 4 of 6 runs",
		Recommendation: "consider a Rule covering error handling",
		DerivedFrom:    []string{"run-1", "run-2", "run-3", "run-4"},
		GeneratedAt:    now,
	}
}

func observation() insights.Observation {
	return insights.Observation{
		OrganizationID:  "org-a",
		RunIDs:          []string{"run-1", "run-2", "run-3", "run-4"},
		CorrectionTopic: "error handling", RunsWithCorrection: 4,
	}
}

// Q1. §23.22: visibly labelled as generated analysis.
//
// The same reason behind WIKI-3's labelled inferences, with more force. A wiki page says what the
// code does and a reader can check it. An insight says "your team keeps correcting the agent" — a
// claim about people, derived from a sample, phrased as advice. It is acted on rather than verified.
func TestSecurityAnInsightCannotBeConstructedWithoutItsLabel(t *testing.T) {
	var zero insights.Label
	if zero != insights.LabelUnlabelled {
		t.Fatalf("the zero Label is %q", zero)
	}
	if zero.Valid() {
		t.Fatal("the zero Label is publishable")
	}
	// There is deliberately no "verified" label: nothing here verifies anything.
	for _, l := range []insights.Label{"verified", "fact", "measured"} {
		if l.Valid() {
			t.Errorf("the label %q is publishable", l)
		}
	}
	if !insights.LabelGeneratedAnalysis.Valid() {
		t.Fatal("the generated-analysis label is not publishable")
	}

	unlabelled := insight()
	unlabelled.Label = insights.LabelUnlabelled
	if err := unlabelled.Validate(); err == nil {
		t.Fatal("an unlabelled insight validated")
	}

	// Everything this package produces carries the label, so it cannot be omitted by a caller who
	// assembles an insight through the constructor.
	got, ok, why := insights.CorrectionInsight(observation(), now)
	if !ok {
		t.Fatalf("a well-supported correction produced no insight: %s", why)
	}
	if got.Label != insights.LabelGeneratedAnalysis {
		t.Fatalf("a constructed insight carries label %q", got.Label)
	}
}

// Q2. An insight cites the runs it came from.
func TestSecurityAnInsightCitesTheRunsItCameFrom(t *testing.T) {
	uncited := insight()
	uncited.DerivedFrom = nil
	if err := uncited.Validate(); err == nil {
		t.Fatal("an insight citing no runs validated")
	}

	got, ok, _ := insights.CorrectionInsight(observation(), now)
	if !ok {
		t.Fatal("a well-supported correction produced no insight")
	}
	if len(got.DerivedFrom) != len(observation().RunIDs) {
		t.Fatalf("derived from %v, want all the observed runs", got.DerivedFrom)
	}

	// The citation is a copy: mutating the observation afterwards must not rewrite the evidence.
	o := observation()
	got, _, _ = insights.CorrectionInsight(o, now)
	o.RunIDs[0] = "tampered"
	if got.DerivedFrom[0] == "tampered" {
		t.Fatal("an insight's evidence changed when the observation did")
	}

	for name, mutate := range map[string]func(*insights.Insight){
		"no kind":         func(i *insights.Insight) { i.Kind = insights.KindUnspecified },
		"invented kind":   func(i *insights.Insight) { i.Kind = "vibes" },
		"no organization": func(i *insights.Insight) { i.OrganizationID = " " },
		"no statement":    func(i *insights.Insight) { i.Statement = "" },
		"no timestamp":    func(i *insights.Insight) { i.GeneratedAt = time.Time{} },
	} {
		in := insight()
		mutate(&in)
		if err := in.Validate(); err == nil {
			t.Errorf("%s: an unusable insight validated", name)
		}
	}
	if err := insight().Validate(); err != nil {
		t.Fatalf("a complete insight was refused: %v", err)
	}
}

// Q3. Two is not a pattern, and the floor is on the runs that showed it.
//
// Two corrections across fifty runs is a rarer coincidence, not a stronger one.
func TestSecurityACorrectionNeedsMoreThanACoincidenceToBecomeAdvice(t *testing.T) {
	if insights.MinRuns < 3 {
		t.Fatalf("MinRuns = %d; two occurrences is a coincidence with a sample size",
			insights.MinRuns)
	}

	// Too few runs observed.
	few := observation()
	few.RunIDs = []string{"run-1", "run-2"}
	few.RunsWithCorrection = 2
	if _, ok, why := insights.CorrectionInsight(few, now); ok {
		t.Fatal("a two-run observation produced advice")
	} else if !strings.Contains(why, "pattern") {
		t.Errorf("reason = %q, want it to say why not", why)
	}

	// Plenty of runs, too few showing it. This is the case a floor on the observed count misses.
	sparse := observation()
	sparse.RunIDs = make([]string, 50)
	for i := range sparse.RunIDs {
		sparse.RunIDs[i] = "run"
	}
	sparse.RunsWithCorrection = 2
	if _, ok, why := insights.CorrectionInsight(sparse, now); ok {
		t.Fatal("two corrections across fifty runs produced advice")
	} else if why == "" {
		t.Error("the refusal gave no reason")
	}

	// At the floor it produces advice, so the floor is a floor and not a wall.
	at := observation()
	at.RunIDs = []string{"run-1", "run-2", "run-3"}
	at.RunsWithCorrection = 3
	if _, ok, why := insights.CorrectionInsight(at, now); !ok {
		t.Fatalf("an observation at the floor produced nothing: %s", why)
	}

	// Incoherent counts are refused rather than reported.
	impossible := observation()
	impossible.RunsWithCorrection = 99
	if _, ok, _ := insights.CorrectionInsight(impossible, now); ok {
		t.Fatal("more corrections than runs produced advice")
	}
	// And an observation with no topic or organization has nothing to say.
	for name, mutate := range map[string]func(*insights.Observation){
		"no topic":        func(o *insights.Observation) { o.CorrectionTopic = " " },
		"no organization": func(o *insights.Observation) { o.OrganizationID = "" },
	} {
		o := observation()
		mutate(&o)
		if _, ok, _ := insights.CorrectionInsight(o, now); ok {
			t.Errorf("%s: an unusable observation produced advice", name)
		}
	}
}

// Q4. "Not checked" is not "absent".
//
// Recommending that a team add a Rule when nobody looked at whether one exists is the failure this
// distinction prevents, and it is the one that destroys trust in the feature the first time it
// happens.
func TestSecurityAnUncheckedConfigurationAreaIsNotReportedMissing(t *testing.T) {
	var zero insights.Presence
	if zero != insights.PresenceNotChecked {
		t.Fatalf("the zero Presence is %q, want not-checked", zero)
	}

	o := observation()
	o.Configuration = map[insights.ConfigurationArea]insights.Presence{
		insights.AreaRule:        insights.PresenceAbsent,
		insights.AreaEnvironment: insights.PresencePresent,
		// context, skill and settings were never checked.
	}

	absent, unchecked := insights.MissingConfiguration(o)
	if len(absent) != 1 || absent[0] != insights.AreaRule {
		t.Fatalf("absent = %v, want only the Rule", absent)
	}
	for _, a := range unchecked {
		if a == insights.AreaRule || a == insights.AreaEnvironment {
			t.Errorf("%s was checked and reported unchecked", a)
		}
	}
	if len(unchecked) != 3 {
		t.Fatalf("unchecked = %v, want the three nobody looked at", unchecked)
	}

	// All five §23.22 areas are covered, and a fully checked observation reports nothing unchecked.
	if len(insights.ConfigurationAreas) != 5 {
		t.Fatalf("areas = %v, want §23.22's five", insights.ConfigurationAreas)
	}
	full := observation()
	full.Configuration = map[insights.ConfigurationArea]insights.Presence{}
	for _, a := range insights.ConfigurationAreas {
		full.Configuration[a] = insights.PresencePresent
	}
	gotAbsent, gotUnchecked := insights.MissingConfiguration(full)
	if len(gotAbsent) != 0 || len(gotUnchecked) != 0 {
		t.Fatalf("a fully configured observation reported absent=%v unchecked=%v",
			gotAbsent, gotUnchecked)
	}

	// An observation that checked nothing reports nothing absent — not everything absent.
	none := observation()
	nothingAbsent, allUnchecked := insights.MissingConfiguration(none)
	if len(nothingAbsent) != 0 {
		t.Fatalf("an unchecked observation reported %v as missing", nothingAbsent)
	}
	if len(allUnchecked) != 5 {
		t.Fatalf("unchecked = %v, want all five", allUnchecked)
	}
}

// Q5. §23.22's retention window.
//
// An unset window does not delete: an unconfigured deployment keeping insights is recoverable, one
// discarding them is not.
func TestSecurityRetentionExpiresInsightsAndAnUnsetWindowKeepsThem(t *testing.T) {
	old := insight()
	old.GeneratedAt = now.Add(-40 * 24 * time.Hour)

	if !old.Expired(30*24*time.Hour, now) {
		t.Fatal("a forty-day-old insight survived a thirty-day window")
	}
	if old.Expired(90*24*time.Hour, now) {
		t.Fatal("a forty-day-old insight expired under a ninety-day window")
	}
	// An unset window keeps rather than deletes.
	for _, window := range []time.Duration{0, -1} {
		if old.Expired(window, now) {
			t.Errorf("a window of %v deleted an insight", window)
		}
	}
	// Exactly at the window is not yet expired; a tick past it is.
	boundary := insight()
	boundary.GeneratedAt = now.Add(-30 * 24 * time.Hour)
	if boundary.Expired(30*24*time.Hour, now) {
		t.Fatal("an insight exactly at the window was expired")
	}

	// Aggregation drops the expired ones and keeps the rest.
	got, err := insights.Aggregate("org-a", []insights.Insight{insight(), old}, 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("aggregate returned %d insights, want the one inside the window", len(got))
	}
}

// Q6. INV-10: aggregation never crosses an organization.
//
// A stray record is an error rather than a silent filter: it means something upstream is
// mis-scoped, and dropping it quietly leaves that in place.
func TestSecurityAggregationNeverCrossesAnOrganization(t *testing.T) {
	other := insight()
	other.OrganizationID = "org-b"

	_, err := insights.Aggregate("org-a", []insights.Insight{insight(), other}, 0, now)
	if err == nil {
		t.Fatal("an insight from another organization was aggregated")
	}
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Errorf("error = %v, want POLICY_DENIED", err)
	}

	// The scope is a parameter, not derived from the data: deriving it means one mis-scoped record
	// silently widens it.
	if _, err := insights.Aggregate("", []insights.Insight{insight()}, 0, now); err == nil {
		t.Fatal("an aggregation with no organization succeeded")
	}
	// And with nothing to aggregate, where the per-insight mismatch check has nothing to catch. A
	// caller whose scope came out empty by mistake would otherwise be handed an empty list and
	// conclude the organization has no insights, rather than discovering the bug.
	if _, err := insights.Aggregate("", nil, 0, now); err == nil {
		t.Fatal("an aggregation with no organization and no insights reported 'none' rather than refusing")
	}
	// An aggregation of only other-organization insights is refused rather than returning empty,
	// which would look like "this organization has no insights".
	if _, err := insights.Aggregate("org-a", []insights.Insight{other}, 0, now); err == nil {
		t.Fatal("an aggregation of another organization's insights returned empty rather than refusing")
	}

	same, err := insights.Aggregate("org-a", []insights.Insight{insight()}, 0, now)
	if err != nil {
		t.Fatalf("a same-organization aggregation was refused: %v", err)
	}
	if len(same) != 1 {
		t.Fatalf("aggregate returned %d, want 1", len(same))
	}
}

// Q7. An insight that describes a problem without a recommendation is a complaint.
func TestSecurityAnInsightMustRecommendSomething(t *testing.T) {
	silent := insight()
	silent.Recommendation = "  "
	err := silent.Validate()
	if err == nil {
		t.Fatal("an insight recommending nothing validated")
	}
	if !strings.Contains(err.Error(), "recommend") {
		t.Errorf("error = %v; it must name the missing recommendation", err)
	}

	// The constructor always produces one.
	got, ok, _ := insights.CorrectionInsight(observation(), now)
	if !ok {
		t.Fatal("a well-supported correction produced no insight")
	}
	if strings.TrimSpace(got.Recommendation) == "" {
		t.Fatal("a constructed insight recommends nothing")
	}
	if !strings.Contains(got.Recommendation, "error handling") {
		t.Fatalf("recommendation = %q; it must name the topic", got.Recommendation)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("a constructed insight does not satisfy its own validator: %v", err)
	}
}
