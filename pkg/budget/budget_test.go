package budget_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/budget"
	"github.com/modbit/modbit/pkg/inference"
)

// Budget invariants (B1–B8). One test each; a test without a B-number, or a B-number without a
// test, is a gap.
//
//	B1 ENTL-2: all three gates must open; an entitlement grant never overrules a policy denial.
//	B2 A refusal names which gate closed, because they go to different people.
//	B3 Every applicable budget must have room; a broad one does not rescue a tight one.
//	B4 The refusal names the exhausted scope.
//	B5 The zero OverageAction is a hard stop.
//	B6 Overage-on-approval does not report Allow, because approval is a separate act.
//	B7 ENTL-3: pooled budgets are summed across the pool, not checked individually.
//	B8 Mixed currencies are refused rather than compared numerically.

func gbp(micros int64) inference.Money {
	return inference.Money{Micros: micros, Currency: "GBP"}
}

func at(scope budget.Scope, limit, spent int64) budget.Budget {
	return budget.Budget{
		Scope: scope, OwnerID: string(scope) + "-1", Limit: gbp(limit), Spent: gbp(spent),
	}
}

func open() budget.Gates { return budget.Gates{Entitlement: true, RBAC: true, Policy: true} }

// B1. ENTL-2: entitlement, RBAC and policy are separate and all three must allow.
//
// The permissive direction is the one that matters. Entitlement is what a customer pays for, so
// "they bought it" reads like authority — it is not, and letting it overrule policy would turn a
// billing record into a security decision.
func TestSecurityAnEntitlementNeverOverrulesPolicy(t *testing.T) {
	budgets := []budget.Budget{at(budget.ScopeOrganization, 1_000_000, 0)}

	d, err := budget.Admit(gbp(10), budget.Gates{Entitlement: true, RBAC: true, Policy: false}, budgets)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Allow {
		t.Fatal("an entitled, role-holding actor was admitted despite a policy denial")
	}
	if !strings.Contains(d.Reason, "policy") {
		t.Fatalf("reason = %q; a policy denial must be reported as one", d.Reason)
	}

	// Each gate closed alone refuses.
	for name, g := range map[string]budget.Gates{
		"no policy":      {Entitlement: true, RBAC: true},
		"no rbac":        {Entitlement: true, Policy: true},
		"no entitlement": {RBAC: true, Policy: true},
		"none":           {},
	} {
		d, err := budget.Admit(gbp(10), g, budgets)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.Allow {
			t.Errorf("%s: admitted with a closed gate", name)
		}
	}
}

// B2. A refusal names the gate, because a plan limit and a permission problem go to different
// people.
func TestARefusalNamesTheGate(t *testing.T) {
	budgets := []budget.Budget{at(budget.ScopeOrganization, 1_000_000, 0)}
	for _, tc := range []struct {
		gates budget.Gates
		want  string
	}{
		{budget.Gates{Entitlement: true, RBAC: true}, "policy"},
		{budget.Gates{Entitlement: true, Policy: true}, "role"},
		{budget.Gates{RBAC: true, Policy: true}, "plan"},
	} {
		d, err := budget.Admit(gbp(10), tc.gates, budgets)
		if err != nil {
			t.Fatalf("Admit: %v", err)
		}
		if !strings.Contains(d.Reason, tc.want) {
			t.Errorf("reason = %q, want it to mention %q", d.Reason, tc.want)
		}
	}
}

// B3, B4. Every applicable budget must have room, and the refusal says which one did not.
//
// An organization with room does not rescue an exhausted user budget. An operator told only "over
// budget" has to guess which of six scopes to raise.
func TestSecurityABroadBudgetDoesNotRescueATightOne(t *testing.T) {
	budgets := []budget.Budget{
		at(budget.ScopeOrganization, 1_000_000, 0), // plenty
		at(budget.ScopeUser, 100, 95),              // nearly gone
	}
	d, err := budget.Admit(gbp(10), open(), budgets)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Allow {
		t.Fatal("a spend over the user budget was admitted because the organization had room")
	}
	if d.ExhaustedScope != budget.ScopeUser {
		t.Fatalf("exhausted scope = %q, want user", d.ExhaustedScope)
	}

	// And the reverse: a tight org budget stops a spend the user could afford.
	reversed := []budget.Budget{
		at(budget.ScopeOrganization, 100, 95),
		at(budget.ScopeUser, 1_000_000, 0),
	}
	d, err = budget.Admit(gbp(10), open(), reversed)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Allow || d.ExhaustedScope != budget.ScopeOrganization {
		t.Fatalf("allow=%v scope=%q, want refused at the organization", d.Allow, d.ExhaustedScope)
	}

	// With room everywhere it is admitted.
	ok := []budget.Budget{at(budget.ScopeOrganization, 1000, 0), at(budget.ScopeUser, 1000, 0)}
	if d, err := budget.Admit(gbp(10), open(), ok); err != nil || !d.Allow {
		t.Fatalf("a spend within every budget was refused: allow=%v err=%v", d.Allow, err)
	}
}

// B5. The zero OverageAction is a hard stop.
//
// A budget whose overage behaviour nobody configured must not let spend through: the failure is
// silent, unbounded, and first visible on an invoice.
func TestSecurityTheZeroOverageActionIsAHardStop(t *testing.T) {
	var unset budget.OverageAction
	if unset != budget.OverageHardStop {
		t.Fatalf("the zero OverageAction is %q, want a hard stop", unset)
	}
	b := at(budget.ScopeUser, 100, 100) // exhausted, Overage unset
	d, err := budget.Admit(gbp(1), open(), []budget.Budget{b})
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Allow || d.RequiresApproval {
		t.Fatalf("an unconfigured overage admitted a spend: allow=%v approval=%v",
			d.Allow, d.RequiresApproval)
	}
}

// B6. Overage-on-approval does not report Allow.
//
// Approval is a separate act. Reporting the spend as allowed would let a caller proceed having
// never obtained one, which is the same conflation as treating "may be permitted" as "permitted".
func TestSecurityApprovalOverageDoesNotReportAllow(t *testing.T) {
	b := at(budget.ScopeTeam, 100, 100)
	b.Overage = budget.OverageRequireApproval

	d, err := budget.Admit(gbp(1), open(), []budget.Budget{b})
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Allow {
		t.Fatal("a spend requiring approval was reported as allowed")
	}
	if !d.RequiresApproval {
		t.Fatal("the decision does not say approval would admit it")
	}
	if d.ExhaustedScope != budget.ScopeTeam {
		t.Fatalf("exhausted scope = %q, want team", d.ExhaustedScope)
	}
}

// B7. ENTL-3: pooled budgets share one limit and are summed before comparison.
//
// Checked individually, three members each 40 under a shared 100 would all pass while together
// exceeding it — which is the whole failure pooling introduces.
func TestSecurityPooledBudgetsAreSummedNotCheckedIndividually(t *testing.T) {
	pool := func(owner string, spent int64) budget.Budget {
		return budget.Budget{
			Scope: budget.ScopeTeam, OwnerID: owner, Limit: gbp(100), Spent: gbp(spent),
			PoolID: "shared",
		}
	}
	budgets := []budget.Budget{pool("team-a", 40), pool("team-b", 40), pool("team-c", 15)}

	// 95 spent against a shared 100: a 10 spend must be refused even though no single member is
	// close to the limit on its own.
	d, err := budget.Admit(gbp(10), open(), budgets)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Allow {
		t.Fatal("a pooled overspend was admitted because each member looked affordable alone")
	}

	// Within the pool it passes.
	if d, err := budget.Admit(gbp(4), open(), budgets); err != nil || !d.Allow {
		t.Fatalf("a spend within the pooled limit was refused: allow=%v err=%v", d.Allow, err)
	}
}

// B8. Mixed currencies are refused rather than compared as bare numbers.
func TestSecurityMixedCurrenciesAreRefused(t *testing.T) {
	usd := budget.Budget{
		Scope: budget.ScopeUser, OwnerID: "u1",
		Limit: inference.Money{Micros: 1000, Currency: "USD"},
	}
	if _, err := budget.Admit(gbp(10), open(), []budget.Budget{usd}); err == nil {
		t.Fatal("a GBP cost was compared against a USD budget")
	}

	mixed := budget.Budget{
		Scope: budget.ScopeUser, OwnerID: "u1", Limit: gbp(1000),
		Spent: inference.Money{Micros: 10, Currency: "USD"},
	}
	if err := mixed.Validate(); err == nil {
		t.Fatal("a budget whose spend and limit are in different currencies validated")
	}
}

// Chargeback tags are recorded whatever the outcome (ENTL-4).
//
// Attribution of a refused spend is still attribution, and a tag that appeared only on success
// would make refusals invisible in a chargeback export.
func TestChargebackTagsAreRecordedOnRefusalToo(t *testing.T) {
	b := at(budget.ScopeUser, 10, 10)
	b.ChargebackTag = "cost-centre-42"

	d, err := budget.Admit(gbp(5), open(), []budget.Budget{b})
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if d.Allow {
		t.Fatal("the fixture should refuse")
	}
	if len(d.ChargebackTags) != 1 || d.ChargebackTags[0] != "cost-centre-42" {
		t.Fatalf("tags = %v on a refusal, want the budget's tag", d.ChargebackTags)
	}
}

// Cost is computed from declared per-million rates.
func TestCostIsComputedFromDeclaredRates(t *testing.T) {
	pricing := inference.Pricing{
		InputPerMillion:  inference.Money{Micros: 3_000_000, Currency: "GBP"},
		OutputPerMillion: inference.Money{Micros: 15_000_000, Currency: "GBP"},
	}
	got := budget.Cost(inference.Usage{InputTokens: 1_000_000, OutputTokens: 100_000}, pricing)
	want := int64(3_000_000 + 1_500_000)
	if got.Micros != want {
		t.Fatalf("cost = %d micros, want %d", got.Micros, want)
	}
	if got.Currency != "GBP" {
		t.Fatalf("currency = %q", got.Currency)
	}
}
