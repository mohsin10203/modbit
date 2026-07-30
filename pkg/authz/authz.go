// Package authz evaluates the authorization dimensions R-TEN-05 requires.
//
// Boundary: it combines per-dimension verdicts into one decision and names what refused. It looks
// nothing up, calls no directory, and holds no roles — a caller supplies verdicts and this decides
// what they mean together.
//
// Requirements: rules.md R-TEN-05, which lists ten dimensions authorization "evaluates": identity,
// org/team role, Space membership, repository access, artifact classification, settings policy,
// service identity, worker ownership, taint state and trust state.
//
// # Why a verdict is three-valued
//
// The obvious model is a bool per dimension and an AND across them. It has one failure and it is the
// only one that matters: a dimension nobody evaluated is indistinguishable from one that allowed.
// Ten dimensions is enough that forgetting one is a matter of time, and the forgotten one reads as
// permission.
//
// So `Verdict` has three states and the zero is `NotEvaluated`, which denies. A caller that adds a
// dimension and forgets to supply it gets a refusal naming the gap, rather than an authorization
// that quietly stopped checking something.
//
// # Why the refusal names one dimension and not all of them
//
// A decision that listed every failing dimension would tell a caller how much of the boundary they
// are past, which is a map of the remaining distance. It names the first refusal in a fixed order,
// so the answer is stable and says only that one thing.
package authz

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Dimension is one axis R-TEN-05 requires authorization to evaluate.
type Dimension string

const (
	DimIdentity               Dimension = "identity"
	DimOrgRole                Dimension = "org_team_role"
	DimSpaceMembership        Dimension = "space_membership"
	DimRepositoryAccess       Dimension = "repository_access"
	DimArtifactClassification Dimension = "artifact_classification"
	DimSettingsPolicy         Dimension = "settings_policy"
	DimServiceIdentity        Dimension = "service_identity"
	DimWorkerOwnership        Dimension = "worker_ownership"
	DimTaintState             Dimension = "taint_state"
	DimTrustState             Dimension = "trust_state"
)

// Dimensions returns all ten in evaluation order.
//
// The order is the refusal order, and it runs from the most fundamental to the most contextual:
// being the wrong identity is a different conversation from being the right identity with too much
// taint, and telling someone the second when the first is also true would send them down the wrong
// path.
func Dimensions() []Dimension {
	return []Dimension{
		DimIdentity, DimServiceIdentity, DimOrgRole, DimSpaceMembership,
		DimRepositoryAccess, DimWorkerOwnership, DimArtifactClassification,
		DimSettingsPolicy, DimTrustState, DimTaintState,
	}
}

// Verdict is one dimension's answer.
type Verdict string

const (
	// NotEvaluated is the zero value and denies.
	//
	// This is the whole design. With a boolean per dimension, a dimension nobody evaluated is
	// indistinguishable from one that allowed, and with ten of them forgetting one is a matter of
	// time. A distinct third state makes the gap visible instead of permissive.
	NotEvaluated Verdict = ""
	// Allow means the dimension permits the operation.
	Allow Verdict = "allow"
	// Deny means it does not.
	Deny Verdict = "deny"
)

// Permits reports whether the verdict allows. Only Allow does.
func (v Verdict) Permits() bool { return v == Allow }

// Evaluation is the per-dimension input to a decision.
type Evaluation map[Dimension]Verdict

// Decision is the combined outcome.
type Decision struct {
	Allow bool `json:"allow"`
	// RefusedBy names the first dimension that did not allow, in Dimensions() order. Empty when
	// allowed.
	RefusedBy Dimension `json:"refused_by,omitempty"`
	// Reason distinguishes a denial from a gap, because they need different responses: a denial is
	// a permission question and a gap is a bug in the caller.
	Reason string `json:"reason,omitempty"`
	// Unevaluated lists every dimension with no verdict. It is reported in full even though
	// RefusedBy names only one, because a missing dimension is a defect in the authorization path
	// and an operator fixing it needs the whole list rather than one per deployment.
	Unevaluated []Dimension `json:"unevaluated,omitempty"`
}

// Authorize combines per-dimension verdicts (R-TEN-05).
//
// Every dimension must be present and must allow. A dimension absent from the evaluation is a gap,
// not a permission.
func Authorize(e Evaluation) (Decision, error) {
	if e == nil {
		// A nil evaluation is a caller that has not started rather than one that found nothing, and
		// treating it as ten gaps would bury that.
		return Decision{}, modberr.New(modberr.CodeInvalidArgument,
			"authorization was asked to decide with no evaluation at all").
			WithDetail("field", "evaluation")
	}
	for d, v := range e {
		if !known(d) {
			// An unrecognised dimension is refused rather than ignored. Ignoring it would let a
			// caller believe it had supplied a check that nothing consumed.
			return Decision{}, modberr.Newf(modberr.CodeInvalidArgument,
				"authorization received an unknown dimension %q", d).WithDetail("field", "dimension")
		}
		if v != Allow && v != Deny && v != NotEvaluated {
			return Decision{}, modberr.Newf(modberr.CodeInvalidArgument,
				"dimension %q has an unknown verdict %q", d, v).WithDetail("field", "verdict")
		}
	}

	var unevaluated []Dimension
	for _, d := range Dimensions() {
		if e[d] == NotEvaluated {
			unevaluated = append(unevaluated, d)
		}
	}

	for _, d := range Dimensions() {
		switch e[d] {
		case Allow:
			continue
		case Deny:
			return Decision{RefusedBy: d, Unevaluated: unevaluated,
				Reason: fmt.Sprintf("%s does not permit this operation", d)}, nil
		default:
			return Decision{RefusedBy: d, Unevaluated: unevaluated,
				Reason: fmt.Sprintf(
					"%s was not evaluated; R-TEN-05 requires every dimension to be decided", d)}, nil
		}
	}
	return Decision{Allow: true}, nil
}

func known(d Dimension) bool {
	for _, k := range Dimensions() {
		if d == k {
			return true
		}
	}
	return false
}

// Complete reports whether an evaluation covers every dimension.
//
// Separate from Authorize so a caller can check its own wiring at startup rather than discovering a
// gap on the first request that happens to reach the missing dimension.
func Complete(e Evaluation) (bool, []Dimension) {
	var missing []Dimension
	for _, d := range Dimensions() {
		if e[d] == NotEvaluated {
			missing = append(missing, d)
		}
	}
	return len(missing) == 0, missing
}

// Describe renders a decision for an audit line.
//
// An allowed decision says so and nothing else: enumerating which dimensions permitted it would put
// the shape of the authorization model into every log line, and the interesting record is the
// refusal.
func (d Decision) Describe() string {
	if d.Allow {
		return "allow"
	}
	line := fmt.Sprintf("deny (%s)", d.RefusedBy)
	if len(d.Unevaluated) > 0 {
		names := make([]string, 0, len(d.Unevaluated))
		for _, u := range d.Unevaluated {
			names = append(names, string(u))
		}
		sort.Strings(names)
		line += fmt.Sprintf(" [unevaluated: %s]", strings.Join(names, " "))
	}
	return line
}
