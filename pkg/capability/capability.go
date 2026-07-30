// Package capability implements the local capability degradation contract (LCD-1..LCD-5).
//
// Boundary: it decides what a run may attempt under an operating mode and the models actually
// available, and it records why anything was withheld. It performs no inference, opens no network
// connection, and knows nothing about how a feature is implemented — only whether it can be.
//
// Requirements: PRD §8A.4 LCD-1..LCD-5, on top of §8A.1's five operating modes.
//
// # Why the negotiated set is a value and not a lookup
//
// LCD-1 asks for a published matrix, which is static. LCD-2 asks for negotiation "against the
// effective mode **and the available models**", which is not: the same mode yields a different
// answer on a laptop with one small local model than on one with a large one. So the matrix is the
// floor and the negotiation is the answer, and the answer is frozen into the run snapshot (LCD-5)
// rather than recomputed — a run that re-derived its capabilities mid-flight would change what it
// was allowed to do while doing it.
//
// # Why every withholding carries a reason
//
// LCD-3 states that silent degradation is prohibited. That is a constraint on the *data structure*,
// not on the UI: a `Support` value with no explanation cannot be disclosed usefully however careful
// the surface rendering it is, and the surface is not where the reason is known. So a degraded or
// unavailable outcome is unrepresentable without a reason — see `Outcome`.
package capability

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Mode is a local-first operating mode (§8A.1).
type Mode string

const (
	// ModeLocalPrivate keeps context, inference and execution on the device, denying egress except
	// approved updates.
	ModeLocalPrivate Mode = "local_private"
	// ModeLocalHybrid allows approved hosted inference through the Model Gateway.
	ModeLocalHybrid Mode = "local_hybrid"
	// ModeTeamHybrid adds approved shared context and customer workers.
	ModeTeamHybrid Mode = "team_hybrid"
	// ModeRemotePrivate places context and execution on customer infrastructure.
	ModeRemotePrivate Mode = "remote_private"
	// ModeOffline is device-only with zero external egress.
	ModeOffline Mode = "offline"
)

// Modes returns every mode in a stable order.
func Modes() []Mode {
	return []Mode{ModeLocalPrivate, ModeLocalHybrid, ModeTeamHybrid, ModeRemotePrivate, ModeOffline}
}

// Valid reports whether m is a declared mode. An unknown mode is refused rather than defaulted,
// because defaulting one would silently pick an egress posture.
func (m Mode) Valid() bool {
	for _, known := range Modes() {
		if m == known {
			return true
		}
	}
	return false
}

// HostedInference reports whether the mode permits hosted models at all (§8A.1).
//
// Local Private and Offline are device-only. This is the single fact that drives most of the
// matrix, and it is stated once so a feature's availability cannot disagree with the mode's
// declared egress posture.
func (m Mode) HostedInference() bool {
	return m == ModeLocalHybrid || m == ModeTeamHybrid || m == ModeRemotePrivate
}

// Feature is a capability LCD-1 requires the matrix to describe.
type Feature string

const (
	FeatureAsk               Feature = "ask"
	FeaturePlan              Feature = "plan"
	FeatureCode              Feature = "code"
	FeatureDebug             Feature = "debug"
	FeatureReview            Feature = "review"
	FeatureVerify            Feature = "verify"
	FeatureTabCompletion     Feature = "tab_completion"
	FeatureNextEditRipple    Feature = "next_edit_ripple"
	FeatureCodeWikiGeneraton Feature = "codewiki_generation"
	FeatureSecuritySwarm     Feature = "security_swarm"
)

// Features returns the ten features LCD-1 names, in a stable order.
//
// The list is closed and matches the requirement exactly. A feature absent from LCD-1 has no
// published support level, and inventing one here would publish a promise the PRD does not make.
func Features() []Feature {
	return []Feature{
		FeatureAsk, FeaturePlan, FeatureCode, FeatureDebug, FeatureReview, FeatureVerify,
		FeatureTabCompletion, FeatureNextEditRipple, FeatureCodeWikiGeneraton, FeatureSecuritySwarm,
	}
}

// Support is how well a feature works under a mode and the models present.
type Support string

const (
	// SupportUnavailable is the zero value: the feature cannot run at all.
	//
	// It is the zero deliberately, matching sandbox.EnforcementUnsupported and taint's unknown
	// class. A feature missing from a matrix reads as unavailable, which is the only safe reading
	// of no answer — the alternative silently promises a capability nobody declared.
	SupportUnavailable Support = ""
	// SupportDegraded means the feature runs with reduced quality, scope or speed.
	SupportDegraded Support = "degraded"
	// SupportFull means the feature runs as specified.
	SupportFull Support = "full"
)

// Usable reports whether the feature can run at all.
func (s Support) Usable() bool { return s == SupportFull || s == SupportDegraded }

// Outcome is one feature's negotiated result.
//
// Reason is required whenever Support is not Full. LCD-3 prohibits silent degradation, and a
// degraded outcome carrying no explanation is silent no matter how it is later rendered — the
// surface displaying it does not know why the model was too small or the mode too narrow. Making
// the pair inseparable is what turns LCD-3 from a UI guideline into a property of the record.
type Outcome struct {
	Feature Feature `json:"feature"`
	Support Support `json:"support"`
	// Reason explains anything short of full support, in product language (LCL-8). Empty when
	// Support is Full.
	Reason string `json:"reason,omitempty"`
}

// Validate enforces the reason-or-full rule.
func (o Outcome) Validate() error {
	switch {
	case o.Feature == "":
		return modberr.New(modberr.CodeInvalidArgument, "an outcome names no feature").
			WithDetail("field", "feature")
	case o.Support == SupportFull && o.Reason != "":
		// A reason on a full outcome is a leftover from an earlier decision, and leaving it would
		// disclose a degradation that is not happening.
		return modberr.Newf(modberr.CodeInvalidArgument,
			"feature %q is fully supported but carries a degradation reason", o.Feature).
			WithDetail("field", "reason")
	case o.Support != SupportFull && strings.TrimSpace(o.Reason) == "":
		return modberr.Newf(modberr.CodeInvalidArgument,
			"feature %q is %s with no reason; LCD-3 prohibits silent degradation",
			o.Feature, o.Support.Describe()).
			WithDetail("field", "reason")
	}
	return nil
}

// Describe renders a support level in product language (LCL-8).
func (s Support) Describe() string {
	switch s {
	case SupportFull:
		return "fully supported"
	case SupportDegraded:
		return "degraded"
	default:
		return "unavailable"
	}
}

// Set is a negotiated capability set, frozen into a run snapshot (LCD-2, LCD-5).
type Set struct {
	Mode Mode `json:"mode"`
	// Outcomes is one entry per feature in Features() order. It is complete by construction:
	// a feature absent from a published set would be indistinguishable from one nobody considered.
	Outcomes []Outcome `json:"outcomes"`
}

// Support returns a feature's negotiated level, defaulting to unavailable.
func (s Set) Support(f Feature) Support {
	for _, o := range s.Outcomes {
		if o.Feature == f {
			return o.Support
		}
	}
	return SupportUnavailable
}

// Outcome returns a feature's full negotiated outcome and whether it was present.
func (s Set) Outcome(f Feature) (Outcome, bool) {
	for _, o := range s.Outcomes {
		if o.Feature == f {
			return o, true
		}
	}
	return Outcome{}, false
}

// Degradations returns every outcome short of full support, in feature order.
//
// This is what LCD-3's disclosure renders. It is a method rather than a caller-side filter so that
// every surface discloses the same set — a UI that filtered differently from the CLI would make
// "disclosed" mean two things.
func (s Set) Degradations() []Outcome {
	var out []Outcome
	for _, o := range s.Outcomes {
		if o.Support != SupportFull {
			out = append(out, o)
		}
	}
	return out
}

// Validate checks the set is complete and internally consistent.
func (s Set) Validate() error {
	if !s.Mode.Valid() {
		return modberr.Newf(modberr.CodeInvalidArgument, "unknown operating mode %q", s.Mode).
			WithDetail("field", "mode")
	}
	seen := make(map[Feature]bool, len(s.Outcomes))
	for _, o := range s.Outcomes {
		if err := o.Validate(); err != nil {
			return err
		}
		if seen[o.Feature] {
			return modberr.Newf(modberr.CodeInvalidArgument, "feature %q appears twice", o.Feature).
				WithDetail("field", "outcomes")
		}
		seen[o.Feature] = true
	}
	for _, f := range Features() {
		if !seen[f] {
			// LCD-1 asks for a matrix over all ten. An incomplete set is not a smaller promise, it
			// is an unreadable one: the caller cannot tell "unavailable" from "not considered".
			return modberr.Newf(modberr.CodeInvalidArgument,
				"the negotiated set omits feature %q; LCD-1 covers all %d", f, len(Features())).
				WithDetail("field", "outcomes")
		}
	}
	return nil
}

// String renders the set for a trace line (LCL-1).
func (s Set) String() string {
	degraded := s.Degradations()
	if len(degraded) == 0 {
		return fmt.Sprintf("%s: all %d features fully supported", s.Mode, len(s.Outcomes))
	}
	names := make([]string, 0, len(degraded))
	for _, o := range degraded {
		names = append(names, fmt.Sprintf("%s=%s", o.Feature, o.Support.Describe()))
	}
	sort.Strings(names)
	return fmt.Sprintf("%s: %s", s.Mode, strings.Join(names, " "))
}
