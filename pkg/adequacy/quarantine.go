package adequacy

import (
	"fmt"
	"sort"

	"github.com/modbit/modbit/pkg/modberr"
)

// Observation is one execution of one test.
type Observation struct {
	// Passed is what the runner reported.
	Passed bool `json:"passed"`
	// Revision is the source revision it ran against. Observations from different revisions are not
	// evidence of flakiness — the code changed — and mixing them is how a real regression gets
	// filed as flaky and ignored.
	Revision string `json:"revision"`
}

// History is the observations for one test, oldest first.
type History struct {
	Test         string        `json:"test"`
	Observations []Observation `json:"observations"`
}

// Stability is what repeated execution established about a test (VAD-5).
type Stability string

const (
	// StabilityUnknown is the zero value: too few observations to say anything.
	//
	// Zero for the same reason VerdictInconclusive is: an unmeasured test must not read as a stable
	// one. A single green run is the most common evidence there is, and it establishes nothing about
	// consistency.
	StabilityUnknown Stability = ""
	// StabilityStable means every observation at this revision agreed.
	StabilityStable Stability = "stable"
	// StabilityFlaky means observations at the same revision disagreed.
	StabilityFlaky Stability = "flaky"
)

// minObservations is how many same-revision runs are needed before stability is claimed.
//
// Two agreeing runs are weak evidence of consistency and the cheapest available; three is the point
// where a coin-flip test is more likely than not to have shown both faces. This is a floor on
// claiming *stable* — a single disagreement proves flaky immediately, because inconsistency needs
// only one counterexample.
const minObservations = 3

// Verdict resolves a history to a stability and an adequacy verdict (VAD-5).
//
// The rule VAD-5 states is narrow and absolute: repeated statistically inconsistent results mark
// evidence `inconclusive`, **never** `passed`. So a flaky test does not fail a run either — failing
// would tell an agent to fix code that may be correct, and the honest report is that the evidence
// cannot settle the question.
//
// This is the case the session that wrote it actually hit: a gate failed once under CPU contention,
// passed eighteen times after, and the truthful answer was neither "passing" nor "broken".
func (h History) Verdict() (Stability, Verdict, string, error) {
	if h.Test == "" {
		return StabilityUnknown, VerdictInconclusive, "",
			modberr.New(modberr.CodeInvalidArgument, "a history names no test").
				WithDetail("field", "test")
	}

	byRevision := map[string][]bool{}
	for _, o := range h.Observations {
		if o.Revision == "" {
			return StabilityUnknown, VerdictInconclusive, "",
				modberr.Newf(modberr.CodeInvalidArgument,
					"an observation of %q names no revision", h.Test).WithDetail("field", "revision")
		}
		byRevision[o.Revision] = append(byRevision[o.Revision], o.Passed)
	}

	// Flakiness is disagreement *within* a revision. Checked across every revision rather than the
	// latest, because a test that was flaky last week is flaky now unless something changed it, and
	// looking only at the newest revision loses that the moment a run happens to be consistent.
	for _, revision := range sortedKeys(byRevision) {
		results := byRevision[revision]
		if disagrees(results) {
			return StabilityFlaky, VerdictInconclusive, fmt.Sprintf(
				"%s produced inconsistent results at revision %s (%d of %d runs passed); "+
					"VAD-5 marks inconsistent evidence inconclusive, never passed",
				h.Test, revision, countTrue(results), len(results)), nil
		}
	}

	// No disagreement. That is only *stable* if there were enough runs to have seen one.
	latest, results := latestRevision(byRevision, h.Observations)
	switch {
	case len(results) == 0:
		return StabilityUnknown, VerdictInconclusive,
			fmt.Sprintf("%s has no observations", h.Test), nil
	case len(results) < minObservations:
		return StabilityUnknown, VerdictInconclusive, fmt.Sprintf(
			"%s ran %d time(s) at revision %s; %d consistent runs are needed to call it stable",
			h.Test, len(results), latest, minObservations), nil
	case !results[0]:
		// Consistently failing is not flaky and not inconclusive. The test is telling the truth.
		return StabilityStable, VerdictInadequate, fmt.Sprintf(
			"%s failed consistently across %d runs at revision %s", h.Test, len(results), latest), nil
	default:
		return StabilityStable, VerdictAdequate, "", nil
	}
}

// Quarantine partitions histories into those that may serve as evidence and those that may not.
//
// The flaky set is returned rather than dropped: VAD-5 quarantines evidence, and a quarantine
// nobody can enumerate is deletion. A run whose completion contract depends on a quarantined test
// needs to say which one.
func Quarantine(histories []History) (usable []History, quarantined []History, err error) {
	for _, h := range histories {
		stability, _, _, verr := h.Verdict()
		if verr != nil {
			return nil, nil, verr
		}
		if stability == StabilityFlaky {
			quarantined = append(quarantined, h)
			continue
		}
		usable = append(usable, h)
	}
	return usable, quarantined, nil
}

func disagrees(results []bool) bool {
	if len(results) < 2 {
		return false
	}
	first := results[0]
	for _, r := range results[1:] {
		if r != first {
			return true
		}
	}
	return false
}

func countTrue(results []bool) int {
	n := 0
	for _, r := range results {
		if r {
			n++
		}
	}
	return n
}

// latestRevision returns the revision of the most recent observation and its results.
//
// "Most recent" is observation order, not lexical order of the revision string — a revision is an
// opaque identifier and sorting it would invent a chronology it does not carry.
func latestRevision(byRevision map[string][]bool, observations []Observation) (string, []bool) {
	if len(observations) == 0 {
		return "", nil
	}
	latest := observations[len(observations)-1].Revision
	return latest, byRevision[latest]
}

func sortedKeys(m map[string][]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Sorted for a deterministic report, not for chronology.
	sort.Strings(out)
	return out
}
