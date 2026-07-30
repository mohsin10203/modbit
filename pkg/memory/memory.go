// Package memory implements tiered agent memory and its promotion rules (MEM-1..MEM-5).
//
// Boundary: it decides whether a learned fact may be applied automatically, and records why. It
// stores nothing durably, retrieves nothing, and never applies a memory itself — a caller asks
// whether it may, and this answers with a reason either way.
//
// Requirements: PRD §10A.3 MEM-1..MEM-5 (v5.1 tiering). The earlier §10A.2 MEM-1..MEM-7 govern the
// store itself and are a different deliverable.
//
// # The rule the whole package exists to enforce
//
// MEM-2: "A single trajectory never changes behavior automatically, preserving PLY-1." One run
// concluding something is a hypothesis. The same conclusion reached independently by several runs is
// evidence. Everything here follows from refusing to conflate those.
//
// The subtle half is *independent*. Corroboration counted by occurrence rather than by trajectory
// would let one run that retried three times promote its own guess, which is the failure mode
// wearing the disguise of the fix — three confirmations, one source. So corroboration counts
// distinct run identifiers and nothing else.
//
// # Why Tier B has no automatic path at all
//
// Tier O is mechanically checkable — a build flag, a test invocation quirk, a toolchain version. If
// it is wrong, the next run fails visibly. Tier B changes how the agent decides, plans, phrases,
// reviews or judges, and a wrong Tier B memory produces confident work that is subtly off in a way
// no test catches. MEM-1 requires explicit human review for Tier B promotion, so this package
// offers no corroboration threshold that could ever substitute for it.
package memory

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// Tier is what kind of thing a memory is (MEM-1).
type Tier string

const (
	// TierBehavioral is the zero value, and it is the restrictive one.
	//
	// A memory whose tier nobody set is treated as behavioral, so it can never reach the automatic
	// path. The alternative — defaulting to operational — would let an unclassified memory apply
	// itself after three runs, which is exactly the promotion MEM-1 reserves for human review.
	TierBehavioral Tier = ""
	// TierOperational is a mechanically checkable environment or process fact.
	TierOperational Tier = "operational"
)

// Valid reports whether t is a declared tier. Both are.
func (t Tier) Valid() bool { return t == TierBehavioral || t == TierOperational }

// Scope is who owns a memory (MEM-3).
type Scope string

const (
	// ScopeUnset is the zero value and is never valid: an unowned memory could not be governed by
	// the organization policy MEM-6 permits, nor deleted by the owner MEM-2 grants that right to.
	ScopeUnset        Scope = ""
	ScopeRepository   Scope = "repository"
	ScopeSpace        Scope = "space"
	ScopeOrganization Scope = "organization"
)

// Valid reports whether s is a declared owner scope.
func (s Scope) Valid() bool {
	return s == ScopeRepository || s == ScopeSpace || s == ScopeOrganization
}

// State is a memory's lifecycle position (MEM-3).
type State string

const (
	// StateProposed is the zero value: observed, not yet corroborated or reviewed.
	StateProposed State = ""
	// StateActive means the memory may be applied.
	StateActive State = "active"
	// StateRetired means it was rolled back or expired. Retired is recorded rather than deleted so
	// MEM-5's rollback is auditable and a re-proposal is recognisable as one.
	StateRetired State = "retired"
)

// Corroboration is one run trajectory independently reaching the memory's conclusion (MEM-2, MEM-3).
type Corroboration struct {
	// RunID is the trajectory. Corroboration counts distinct run identifiers, so the same run
	// observed twice adds nothing.
	RunID id.ID `json:"run_id"`
	// EvidenceRef points at what in that run supports the conclusion. MEM-3 requires provenance
	// links to source runs *and evidence*; a run id alone says a run agreed without saying why.
	EvidenceRef string    `json:"evidence_ref"`
	ObservedAt  time.Time `json:"observed_at"`
}

// Memory is a learned fact and everything MEM-3 requires it to carry.
type Memory struct {
	ID    id.ID `json:"id"`
	Tier  Tier  `json:"tier"`
	Scope Scope `json:"scope"`
	// OwnerID is the repository, Space or organization the Scope names.
	OwnerID id.ID  `json:"owner_id"`
	Claim   string `json:"claim"`
	State   State  `json:"state"`
	// Corroborations are the independent trajectories supporting the claim.
	Corroborations []Corroboration `json:"corroborations"`
	// ReviewedBy records the human who approved a Tier B promotion (MEM-1, §10A.2). Empty until
	// reviewed, and meaningless on Tier O.
	ReviewedBy string `json:"reviewed_by,omitempty"`
}

// Validate checks a memory carries what MEM-3 requires.
func (m Memory) Validate() error {
	switch {
	case m.ID.IsZero():
		return field("a memory has no identifier", "id")
	case !m.Tier.Valid():
		return field(fmt.Sprintf("memory %s has an unknown tier", m.ID), "tier")
	case !m.Scope.Valid():
		return field(fmt.Sprintf("memory %s has no owner scope", m.ID), "scope")
	case m.OwnerID.IsZero():
		return field(fmt.Sprintf("memory %s names no owner", m.ID), "owner_id")
	case strings.TrimSpace(m.Claim) == "":
		return field(fmt.Sprintf("memory %s states no claim", m.ID), "claim")
	}
	for _, c := range m.Corroborations {
		if c.RunID.IsZero() {
			return field(fmt.Sprintf("memory %s cites a corroboration with no run", m.ID), "corroborations")
		}
		if strings.TrimSpace(c.EvidenceRef) == "" {
			// MEM-3 asks for links to source runs and evidence. A run id with no evidence records
			// that a run agreed without recording why, which is not a provenance link.
			return field(
				fmt.Sprintf("memory %s cites run %s with no evidence", m.ID, c.RunID), "corroborations")
		}
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// IndependentTrajectories counts distinct corroborating runs (MEM-2).
//
// Distinct is the whole point. Counting occurrences would let one run that retried three times
// corroborate its own conclusion — three confirmations from one source, which is the failure this
// requirement exists to prevent, wearing the appearance of the fix.
func (m Memory) IndependentTrajectories() int {
	seen := make(map[id.ID]bool, len(m.Corroborations))
	for _, c := range m.Corroborations {
		if !c.RunID.IsZero() {
			seen[c.RunID] = true
		}
	}
	return len(seen)
}

// Policy is the configurable part of MEM-2.
type Policy struct {
	// MinCorroborations is how many independent trajectories a Tier O memory needs. MEM-2 sets the
	// default at 3 and the floor at 2.
	MinCorroborations int `json:"min_corroborations"`
	// DisabledScopes lists owner scopes the organization has switched off (MEM-6).
	DisabledScopes []Scope `json:"disabled_scopes,omitempty"`
}

// DefaultMinCorroborations and MinAllowedCorroborations come straight from MEM-2.
const (
	DefaultMinCorroborations = 3
	MinAllowedCorroborations = 2
)

// Validate refuses a policy weaker than MEM-2 permits.
func (p Policy) Validate() error {
	if p.MinCorroborations != 0 && p.MinCorroborations < MinAllowedCorroborations {
		// A configurable minimum with no floor would let an operator set it to 1, which is the
		// single-trajectory promotion MEM-2 forbids outright. Configuration may tighten the rule and
		// may not repeal it.
		return field(fmt.Sprintf(
			"a corroboration minimum of %d permits single-trajectory promotion; MEM-2 sets the floor at %d",
			p.MinCorroborations, MinAllowedCorroborations), "min_corroborations")
	}
	return nil
}

func (p Policy) threshold() int {
	if p.MinCorroborations == 0 {
		return DefaultMinCorroborations
	}
	return p.MinCorroborations
}

func (p Policy) scopeDisabled(s Scope) bool {
	for _, d := range p.DisabledScopes {
		if d == s {
			return true
		}
	}
	return false
}

// Decision is whether a memory may be applied automatically, and why (MEM-4).
type Decision struct {
	// Apply is true only when every condition is met.
	Apply bool `json:"apply"`
	// Reason explains a refusal. MEM-4 prohibits silent application, and the converse matters as
	// much: a memory withheld without explanation cannot be inspected in the Instruction Inspector,
	// so a user cannot tell a memory that was rejected from one that was never learned.
	Reason string `json:"reason,omitempty"`
	// Trajectories and Required are recorded so the Instruction Manifest can show the arithmetic
	// rather than just the verdict.
	Trajectories int `json:"trajectories"`
	Required     int `json:"required"`
}

// MayApplyAutomatically decides whether a memory can change behaviour without a human in the loop.
//
// Tier B never can, whatever its corroboration count. Tier O can, once enough independent
// trajectories agree and its scope is enabled.
func MayApplyAutomatically(m Memory, p Policy) (Decision, error) {
	if err := m.Validate(); err != nil {
		return Decision{}, err
	}
	if err := p.Validate(); err != nil {
		return Decision{}, err
	}

	required := p.threshold()
	trajectories := m.IndependentTrajectories()
	d := Decision{Trajectories: trajectories, Required: required}

	switch {
	case m.State == StateRetired:
		d.Reason = "the memory is retired"
	case p.scopeDisabled(m.Scope):
		// MEM-6 lets an organization switch a scope off, and that outranks corroboration.
		d.Reason = fmt.Sprintf("organization policy has disabled %s-scoped memory", m.Scope)
	case m.Tier == TierBehavioral:
		// No threshold reaches this branch. MEM-1 reserves Tier B promotion for explicit human
		// review, so corroboration is not a substitute however much of it there is — a wrong
		// behavioural memory produces confident work that is subtly off, which no run fails on.
		if m.ReviewedBy == "" {
			d.Reason = "behavioural memory requires explicit human review before it changes agent behaviour"
		} else {
			d.Reason = fmt.Sprintf(
				"behavioural memory reviewed by %s is applied by that approval, not automatically",
				m.ReviewedBy)
		}
	case trajectories < required:
		d.Reason = fmt.Sprintf(
			"%d independent trajectory/trajectories corroborate this; %d are required",
			trajectories, required)
	default:
		d.Apply = true
	}
	return d, nil
}

// Retire rolls a memory back (MEM-5).
//
// It returns a copy rather than mutating, and sets Retired rather than deleting: MEM-5 wants
// rollback recorded as a canonical event, and a deleted memory leaves nothing for the event to
// reference — nor any way to recognise a later re-proposal as a return.
func Retire(m Memory) Memory {
	out := m
	out.State = StateRetired
	return out
}

// Manifest renders the active memories a run applied, for the Instruction Manifest (MEM-4).
//
// Every entry carries its decision, because MEM-4's prohibition on silent application is not
// satisfied by listing what was applied — a user also needs to see what was withheld and why.
func Manifest(memories []Memory, p Policy) ([]string, error) {
	lines := make([]string, 0, len(memories))
	for _, m := range memories {
		d, err := MayApplyAutomatically(m, p)
		if err != nil {
			return nil, err
		}
		status := "withheld"
		if d.Apply {
			status = "applied"
		}
		line := fmt.Sprintf("%s %s [%s, %d/%d trajectories]", status, m.ID, m.Tier.describe(),
			d.Trajectories, d.Required)
		if d.Reason != "" {
			line += ": " + d.Reason
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines, nil
}

func (t Tier) describe() string {
	if t == TierOperational {
		return "operational"
	}
	return "behavioural"
}
