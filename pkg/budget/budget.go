// Package budget enforces nested spend limits and entitlement admission (§21.3, ENTL-1..ENTL-4).
//
// Boundary: it decides whether a cost may be incurred and records which limit stopped it. It meters
// nothing, bills nothing, and never touches an evidence record.
//
// Requirements: PRD §21.3 budgets and usage controls, §21.4 ENTL-1..ENTL-4, and the separation §5
// states outright: "Seats, entitlements, ACUs, credits, and billing groups may control access and
// budgets, but they must not change audit records, evidence, security decisions, or technical
// success metrics."
//
// # Three gates that all have to open
//
// ENTL-2 says entitlement, RBAC and policy are separate decisions and all three must allow an
// operation. The failure worth guarding is the permissive one: an entitlement grant must not
// overrule a policy denial. That direction is the tempting bug because entitlement is the layer a
// customer pays for, and "they bought it" reads like authority — it is not, and a package that let
// it be would turn a billing record into a security decision.
//
// # Why the tightest scope wins
//
// Budgets nest — organization, team, Space, user, automation, agent profile — and a caller sits
// inside several at once. An organization with room does not rescue an exhausted user budget, and
// the reverse is equally true. So admission requires *every* applicable budget to have room, and the
// decision names the one that stopped it: an operator told only "over budget" has to guess which of
// six to raise.
package budget

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
)

// Scope is a level a budget applies at (§21.3).
type Scope string

const (
	ScopeOrganization Scope = "organization"
	ScopeTeam         Scope = "team"
	ScopeSpace        Scope = "space"
	ScopeUser         Scope = "user"
	ScopeAutomation   Scope = "automation"
	ScopeAgentProfile Scope = "agent_profile"
)

// Scopes returns the declared scopes, broadest first.
func Scopes() []Scope {
	return []Scope{ScopeOrganization, ScopeTeam, ScopeSpace, ScopeUser, ScopeAutomation, ScopeAgentProfile}
}

// Valid reports whether s is a declared scope.
func (s Scope) Valid() bool {
	for _, k := range Scopes() {
		if s == k {
			return true
		}
	}
	return false
}

// OverageAction is what happens when a budget is exhausted (§21.3).
type OverageAction string

const (
	// OverageHardStop is the zero value: refuse the spend.
	//
	// Zero for the reason every other zero in this repository is restrictive. A budget whose overage
	// behaviour nobody configured must not default to letting spend through, because the failure is
	// silent, unbounded and only visible on an invoice.
	OverageHardStop OverageAction = ""
	// OverageRequireApproval admits the spend if a human approves it.
	OverageRequireApproval OverageAction = "require_approval"
)

// Budget is one limit at one scope.
type Budget struct {
	Scope Scope `json:"scope"`
	// OwnerID identifies which organization, team, Space, user, automation or profile this bounds.
	OwnerID string          `json:"owner_id"`
	Limit   inference.Money `json:"limit"`
	Spent   inference.Money `json:"spent"`
	Overage OverageAction   `json:"overage"`
	// ChargebackTag is carried through to attribution (ENTL-4). It never affects admission.
	ChargebackTag string `json:"chargeback_tag,omitempty"`
	// PoolID, when set, means this budget's limit is shared with every budget carrying the same
	// PoolID (ENTL-3). Pooled members are summed before comparison rather than checked individually.
	PoolID string `json:"pool_id,omitempty"`
}

// Validate checks a budget is usable.
func (b Budget) Validate() error {
	switch {
	case !b.Scope.Valid():
		return field(fmt.Sprintf("budget for %q has an unknown scope %q", b.OwnerID, b.Scope), "scope")
	case strings.TrimSpace(b.OwnerID) == "":
		return field("a budget names no owner", "owner_id")
	case b.Limit.Micros < 0 || b.Spent.Micros < 0:
		return field(fmt.Sprintf("budget for %q has a negative amount", b.OwnerID), "limit")
	case b.Limit.Currency == "" || (b.Spent.Micros != 0 && b.Spent.Currency != b.Limit.Currency):
		// Comparing across currencies would silently treat 100 of one as 100 of another. There is no
		// conversion here and inventing one would be inventing a financial control.
		return field(fmt.Sprintf("budget for %q mixes or omits currencies", b.OwnerID), "currency")
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// Remaining is what is left before the limit.
func (b Budget) Remaining() inference.Money {
	return inference.Money{Micros: b.Limit.Micros - b.Spent.Micros, Currency: b.Limit.Currency}
}

// Gates are the three independent admission decisions ENTL-2 requires.
//
// They are separate fields rather than one boolean so a refusal can say which gate closed. An
// operator told only "denied" cannot tell a plan limit from a permission problem, and those go to
// different people.
type Gates struct {
	// Entitlement is whether the plan or contract includes the capability (ENTL-1).
	Entitlement bool `json:"entitlement"`
	// RBAC is whether the actor has the role.
	RBAC bool `json:"rbac"`
	// Policy is whether policy permits it.
	Policy bool `json:"policy"`
}

// Decision is the admission outcome.
type Decision struct {
	Allow bool `json:"allow"`
	// Reason explains a refusal, naming the gate or the exhausted budget.
	Reason string `json:"reason,omitempty"`
	// RequiresApproval is set when a budget is exceeded but configured for approval rather than a
	// hard stop. Allow is false in that case: approval is a separate act, and reporting it as
	// allowed would let a caller proceed without ever obtaining one.
	RequiresApproval bool `json:"requires_approval,omitempty"`
	// ExhaustedScope names the budget that stopped the spend, so an operator knows which to raise.
	ExhaustedScope Scope `json:"exhausted_scope,omitempty"`
	// ChargebackTags are the tags of every applicable budget (ENTL-4), recorded whatever the
	// outcome — attribution of a refused spend is still attribution.
	ChargebackTags []string `json:"chargeback_tags,omitempty"`
}

// Admit decides whether a cost may be incurred.
//
// Every gate must open (ENTL-2) and every applicable budget must have room. Pooled budgets are
// summed across their pool before comparison (ENTL-3).
func Admit(cost inference.Money, gates Gates, budgets []Budget) (Decision, error) {
	for _, b := range budgets {
		if err := b.Validate(); err != nil {
			return Decision{}, err
		}
		if b.Limit.Currency != cost.Currency && cost.Micros != 0 {
			return Decision{}, field(fmt.Sprintf(
				"cost is in %s and the %s budget is in %s", cost.Currency, b.Scope, b.Limit.Currency),
				"currency")
		}
	}
	if cost.Micros < 0 {
		return Decision{}, field("a negative cost cannot be admitted", "cost")
	}

	d := Decision{ChargebackTags: tagsOf(budgets)}

	// ENTL-2 first, and in this order deliberately. A caller who is not permitted must be told that
	// rather than that they are over budget: reporting a spend limit to someone who was never
	// allowed to perform the operation misdirects them, and it leaks that the operation exists and
	// is merely unaffordable.
	switch {
	case !gates.Policy:
		d.Reason = "policy does not permit this operation"
		return d, nil
	case !gates.RBAC:
		d.Reason = "the actor does not hold the required role"
		return d, nil
	case !gates.Entitlement:
		d.Reason = "the plan does not include this capability"
		return d, nil
	}

	// Pooled members share one limit, so they are compared as a group (ENTL-3).
	pooled := map[string]int64{}
	pooledLimit := map[string]int64{}
	for _, b := range budgets {
		if b.PoolID == "" {
			continue
		}
		pooled[b.PoolID] += b.Spent.Micros
		pooledLimit[b.PoolID] = b.Limit.Micros
	}

	// Every applicable budget must have room. Broadest first only so the report is stable; the
	// result does not depend on order, because all of them must pass.
	ordered := make([]Budget, len(budgets))
	copy(ordered, budgets)
	sort.SliceStable(ordered, func(i, j int) bool {
		return scopeRank(ordered[i].Scope) < scopeRank(ordered[j].Scope)
	})

	seenPool := map[string]bool{}
	for _, b := range ordered {
		spent, limit := b.Spent.Micros, b.Limit.Micros
		if b.PoolID != "" {
			if seenPool[b.PoolID] {
				continue
			}
			seenPool[b.PoolID] = true
			spent, limit = pooled[b.PoolID], pooledLimit[b.PoolID]
		}
		if spent+cost.Micros <= limit {
			continue
		}
		d.ExhaustedScope = b.Scope
		if b.Overage == OverageRequireApproval {
			d.RequiresApproval = true
			d.Reason = fmt.Sprintf(
				"the %s budget is exceeded; policy allows this to proceed on approval", b.Scope)
			return d, nil
		}
		d.Reason = fmt.Sprintf("the %s budget is exhausted", b.Scope)
		return d, nil
	}

	d.Allow = true
	return d, nil
}

func scopeRank(s Scope) int {
	for i, k := range Scopes() {
		if s == k {
			return i
		}
	}
	return len(Scopes())
}

func tagsOf(budgets []Budget) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range budgets {
		if b.ChargebackTag != "" && !seen[b.ChargebackTag] {
			seen[b.ChargebackTag] = true
			out = append(out, b.ChargebackTag)
		}
	}
	sort.Strings(out)
	return out
}

// Cost computes the price of usage under a model's pricing.
//
// Kept here rather than in the gateway because it is arithmetic over declared rates, and because a
// budget check that computed cost differently from the meter would admit spends it then could not
// account for.
func Cost(u inference.Usage, p inference.Pricing) inference.Money {
	const perMillion = 1_000_000
	micros := int64(u.InputTokens)*p.InputPerMillion.Micros/perMillion +
		int64(u.CachedInputTokens)*p.CachedInputPerMillion.Micros/perMillion +
		int64(u.OutputTokens)*p.OutputPerMillion.Micros/perMillion +
		int64(u.ReasoningTokens)*p.ReasoningPerMillion.Micros/perMillion
	return inference.Money{Micros: micros, Currency: p.InputPerMillion.Currency}
}
