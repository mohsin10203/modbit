package capability

import (
	"fmt"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// Tier is a minimum local-model capability contract (LCD-4).
//
// LCD-4 requires the contract to be stated per degraded-mode tier in terms of context length,
// tool-call reliability and completion latency class, and to be testable through the benchmark
// framework. Stating it as data rather than prose is what makes it testable: a benchmark asserts a
// model meets `TierStandard`, and the same value decides what the model is allowed to do.
type Tier struct {
	Name string `json:"name"`
	// MinContextTokens is the context window the tier requires.
	MinContextTokens int `json:"min_context_tokens"`
	// MinToolCallReliability is the share of tool calls that must be well formed, 0..1. Agentic
	// features fail in a particular way below this — they loop, producing plausible transcripts and
	// no edits — which is why it gates Code, Debug and the swarm rather than Ask.
	MinToolCallReliability float64 `json:"min_tool_call_reliability"`
	// MaxFirstTokenLatency is the latency class the tier admits. Tab completion is the only feature
	// where this dominates: a correct suggestion after two seconds is not a suggestion.
	MaxFirstTokenLatency time.Duration `json:"max_first_token_latency"`
}

// The declared tiers, weakest first. A model is placed in the highest tier it satisfies.
var (
	// TierMinimal runs conversational features only.
	TierMinimal = Tier{
		Name: "minimal", MinContextTokens: 4096,
		MinToolCallReliability: 0, MaxFirstTokenLatency: 5 * time.Second,
	}
	// TierStandard runs the agentic loop, degraded.
	TierStandard = Tier{
		Name: "standard", MinContextTokens: 32768,
		MinToolCallReliability: 0.90, MaxFirstTokenLatency: 2 * time.Second,
	}
	// TierFull runs everything a hosted model would.
	TierFull = Tier{
		Name: "full", MinContextTokens: 128000,
		MinToolCallReliability: 0.98, MaxFirstTokenLatency: 800 * time.Millisecond,
	}
)

// Tiers returns the declared tiers, weakest first.
func Tiers() []Tier { return []Tier{TierMinimal, TierStandard, TierFull} }

// LocalModel is what a device offers, measured rather than declared.
//
// The fields mirror Tier because the comparison must be total: a model that reported only its
// context window would be placed by the one dimension that is easiest to advertise and hardest to
// be wrong about, which is not the dimension that decides whether the agentic loop works.
type LocalModel struct {
	ID                  string        `json:"id"`
	ContextTokens       int           `json:"context_tokens"`
	ToolCallReliability float64       `json:"tool_call_reliability"`
	FirstTokenLatency   time.Duration `json:"first_token_latency"`
}

// Meets reports whether the model satisfies a tier on every dimension.
func (m LocalModel) Meets(t Tier) bool {
	return m.ContextTokens >= t.MinContextTokens &&
		m.ToolCallReliability >= t.MinToolCallReliability &&
		(t.MaxFirstTokenLatency == 0 || m.FirstTokenLatency <= t.MaxFirstTokenLatency)
}

// Tier returns the highest tier the model satisfies, and whether it satisfies any.
func (m LocalModel) Tier() (Tier, bool) {
	best, found := Tier{}, false
	for _, t := range Tiers() {
		if m.Meets(t) {
			best, found = t, true
		}
	}
	return best, found
}

// Available describes the inference a run can actually reach.
type Available struct {
	// Hosted reports whether an approved hosted model is reachable through the Model Gateway.
	Hosted bool `json:"hosted"`
	// Local lists the local models present on the device.
	Local []LocalModel `json:"local,omitempty"`
}

// BestLocal returns the strongest local tier available.
func (a Available) BestLocal() (Tier, bool) {
	best, found := Tier{}, false
	for _, m := range a.Local {
		if t, ok := m.Tier(); ok && (!found || t.MinContextTokens > best.MinContextTokens) {
			best, found = t, true
		}
	}
	return best, found
}

// featureNeeds maps a feature to the local tier it needs when no hosted model is available.
//
// Hosted inference is assumed to clear every tier, which is why this table is only consulted for
// the local path. The assignments follow what each feature actually demands rather than a uniform
// rule: Ask is conversational, the agentic modes need reliable tool calls, and the two whole-repo
// features need the context window a summarisation pass cannot substitute for.
var featureNeeds = map[Feature]Tier{
	FeatureAsk:               TierMinimal,
	FeaturePlan:              TierMinimal,
	FeatureCode:              TierStandard,
	FeatureDebug:             TierStandard,
	FeatureReview:            TierStandard,
	FeatureVerify:            TierStandard,
	FeatureTabCompletion:     TierStandard,
	FeatureNextEditRipple:    TierFull,
	FeatureCodeWikiGeneraton: TierFull,
	FeatureSecuritySwarm:     TierFull,
}

// Negotiate produces the capability set for a mode and what is actually available (LCD-2).
//
// The result is complete over Features(), every non-full outcome carries a reason (LCD-3), and the
// value is what a run snapshot freezes (LCD-5).
func Negotiate(mode Mode, available Available) (Set, error) {
	if !mode.Valid() {
		return Set{}, modberr.Newf(modberr.CodeInvalidArgument, "unknown operating mode %q", mode).
			WithDetail("field", "mode")
	}

	// A mode that forbids hosted inference forbids it regardless of what is reachable. LCL-5 routes
	// hosted traffic through the gateway; §8A.1 says Local Private and Offline have no hosted path
	// at all, and honouring a reachable hosted model here would let network topology override a
	// declared boundary.
	hosted := available.Hosted && mode.HostedInference()
	localTier, hasLocal := available.BestLocal()

	set := Set{Mode: mode, Outcomes: make([]Outcome, 0, len(Features()))}
	for _, f := range Features() {
		set.Outcomes = append(set.Outcomes, negotiateFeature(f, mode, hosted, localTier, hasLocal))
	}
	if err := set.Validate(); err != nil {
		// A set that fails its own validation is a bug here, not a caller error. Returning it would
		// put an unreadable record into a run snapshot.
		return Set{}, err
	}
	return set, nil
}

func negotiateFeature(f Feature, mode Mode, hosted bool, localTier Tier, hasLocal bool) Outcome {
	if hosted {
		return Outcome{Feature: f, Support: SupportFull}
	}

	need := featureNeeds[f]
	switch {
	case !hasLocal && mode.HostedInference():
		return Outcome{Feature: f, Support: SupportUnavailable,
			Reason: "no local model is installed and no approved hosted model is reachable"}
	case !hasLocal:
		return Outcome{Feature: f, Support: SupportUnavailable,
			Reason: fmt.Sprintf("%s keeps inference on the device and no local model is installed",
				describeMode(mode))}
	case localTier.MinContextTokens >= need.MinContextTokens &&
		localTier.MinToolCallReliability >= need.MinToolCallReliability:
		// The local model clears the bar. It is still not the hosted path, and saying so is the
		// difference between an honest "full" and one that quietly means "as good as this device
		// gets" — but the feature runs as specified, which is what full means.
		return Outcome{Feature: f, Support: SupportFull}
	case localTier.MinContextTokens >= TierMinimal.MinContextTokens && need.MinContextTokens <= TierStandard.MinContextTokens:
		return Outcome{Feature: f, Support: SupportDegraded,
			Reason: fmt.Sprintf("the local model meets the %s tier; %s is specified for the %s tier",
				localTier.Name, f, need.Name)}
	default:
		return Outcome{Feature: f, Support: SupportUnavailable,
			Reason: fmt.Sprintf("%s needs the %s tier and the strongest local model meets only %s",
				f, need.Name, localTier.Name)}
	}
}

// describeMode renders a mode in product language (LCL-8).
func describeMode(m Mode) string {
	switch m {
	case ModeOffline:
		return "Offline mode"
	case ModeLocalPrivate:
		return "Local Private mode"
	case ModeLocalHybrid:
		return "Local Hybrid mode"
	case ModeTeamHybrid:
		return "Team Hybrid mode"
	case ModeRemotePrivate:
		return "Remote Private mode"
	default:
		return string(m)
	}
}

// Published returns the static per-mode matrix LCD-1 requires.
//
// It is the floor, not the answer: it assumes an approved hosted model wherever the mode permits
// one, and the strongest declared tier where it does not. A run gets `Negotiate`, which accounts for
// what is actually installed. Publishing the optimistic case is correct for a matrix whose job is to
// describe the *mode* — but it is why LCD-2 exists, and why nothing frozen into a snapshot comes
// from here.
func Published(mode Mode) (Set, error) {
	return Negotiate(mode, Available{
		Hosted: true,
		Local: []LocalModel{{
			ID:                  "reference-full-tier",
			ContextTokens:       TierFull.MinContextTokens,
			ToolCallReliability: TierFull.MinToolCallReliability,
			FirstTokenLatency:   TierFull.MaxFirstTokenLatency,
		}},
	})
}
