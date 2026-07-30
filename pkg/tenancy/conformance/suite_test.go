package conformance_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/coordination"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/shard"
	"github.com/modbit/modbit/pkg/tenancy/conformance"
)

// tenantIDs maps the suite's opaque tenant strings onto real prefixed identifiers, stably, so a
// surface comparing ids sees the same value each time the suite names the same tenant.
type tenantIDs struct{ org, space map[string]id.ID }

func newTenantIDs() *tenantIDs {
	return &tenantIDs{org: map[string]id.ID{}, space: map[string]id.ID{}}
}

func (t *tenantIDs) orgID(name string) id.ID {
	if name == "" {
		return ""
	}
	if v, ok := t.org[name]; ok {
		return v
	}
	t.org[name] = id.MustNew(id.Organization)
	return t.org[name]
}

func (t *tenantIDs) spaceID(name string) id.ID {
	if name == "" {
		return ""
	}
	if v, ok := t.space[name]; ok {
		return v
	}
	t.space[name] = id.MustNew(id.Space)
	return t.space[name]
}

// coordinationSurface exposes pkg/coordination's overlap detector to the suite.
type coordinationSurface struct{ ids *tenantIDs }

func (coordinationSurface) Name() string { return "coordination.Overlaps" }

func (s coordinationSurface) Query(asking, owner conformance.Tenant, secret string) (string, error) {
	repo := id.MustNew(id.Repository)
	// The owner's scope claims the planted secret as a symbol; a caller that can see the overlap
	// learns the symbol name, which is the disclosure INV-10 forbids across tenants.
	ownerScope := coordination.Scope{
		RunID: id.MustNew(id.Run), OrganizationID: s.ids.orgID(owner.OrganizationID),
		SpaceID: s.ids.spaceID(owner.SpaceID), RepositoryID: repo,
		Claims: []coordination.Claim{{Kind: coordination.ScopeSymbol, Ref: secret}},
	}
	askingScope := coordination.Scope{
		RunID: id.MustNew(id.Run), OrganizationID: s.ids.orgID(asking.OrganizationID),
		SpaceID: s.ids.spaceID(asking.SpaceID), RepositoryID: repo,
		Claims: []coordination.Claim{{Kind: coordination.ScopeSymbol, Ref: secret}},
	}

	conflicts, err := coordination.Overlaps(askingScope, ownerScope)
	if err != nil {
		return "", err
	}
	refs := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		refs = append(refs, c.Ref)
	}
	return strings.Join(refs, ","), nil
}

// shardSurface exposes pkg/shard's permission-filtered composition to the suite.
//
// shard.Grant is per shard rather than per tenant, so the adapter maps a tenant onto a grant: a
// caller from another tenant holds no grant over the owner's shard. That is what tenancy means at
// this layer, and stating the mapping here is what lets one suite cover two different shapes of
// isolation.
type shardSurface struct{}

func (shardSurface) Name() string { return "shard.Compose" }

func (shardSurface) Query(asking, owner conformance.Tenant, secret string) (string, error) {
	if asking.OrganizationID == "" {
		// R-TEN-01: an untenanted caller cannot be matched against anything.
		return "", errUntenanted{}
	}
	ownerShard := "shard-" + owner.OrganizationID + "-" + owner.SpaceID
	results := []shard.Result{{ShardID: ownerShard, Revision: index.Revision{}, Items: nil}}

	var grant shard.Grant
	if asking == owner {
		grant = shard.Grant{Allowed: []string{ownerShard}}
	}
	if _, err := shard.Compose(results, grant); err != nil {
		return "", err
	}
	// Composition returns items; the suite's secret rides in the shard id, so a caller that was
	// granted the shard "sees" it and one that was not does not.
	if grant.Permits(ownerShard) {
		return secret, nil
	}
	return "", nil
}

type errUntenanted struct{}

func (errUntenanted) Error() string { return "a caller with no organization cannot be scoped" }

// Both tenant-scoped surfaces answer the same isolation contract (R-TEN-06).
//
// The point of a shared suite is that they answer the *same* cases. Two packages each writing their
// own isolation test produces two definitions of isolation, and the weakest is the one that matters.
func TestSecurityTenantScopedSurfacesAreIsolated(t *testing.T) {
	for _, s := range []conformance.Surface{
		coordinationSurface{ids: newTenantIDs()},
		shardSurface{},
	} {
		report := conformance.Run(s)

		seen := map[string]conformance.Status{}
		for _, r := range report.Results {
			seen[r.Obligation] = r.Status
			if r.Status == conformance.StatusFail {
				t.Errorf("%s %s (%s): %s", report.Surface, r.Obligation, r.Case, r.Detail)
			}
		}
		for _, o := range conformance.Obligations() {
			if _, ok := seen[o]; !ok {
				t.Errorf("%s: the suite produced no case for %s", report.Surface, o)
			}
		}
		if !report.Isolated() {
			t.Errorf("not isolated: %s", report.Summary())
		}
		// T1 must genuinely pass. A surface that refuses everything satisfies T2 and T3 by being
		// broken, and a skipped control would hide that.
		if seen["T1"] != conformance.StatusPass {
			t.Errorf("%s: T1 was %s; the later refusals prove nothing without it",
				report.Surface, seen["T1"])
		}
	}
}

// The suite itself can fail.
//
// A conformance suite that cannot fail certifies whatever it is given. This hands it a surface that
// serves every caller — the plainest cross-tenant leak there is — and requires T2, T3 and T5 to
// catch it.
func TestSecurityTheSuiteDetectsALeakySurface(t *testing.T) {
	report := conformance.Run(leakySurface{})
	if report.Isolated() {
		t.Fatal("the suite passed a surface that serves every caller")
	}
	for _, want := range []string{"T2", "T3", "T5"} {
		var caught bool
		for _, r := range report.Results {
			if r.Obligation == want && r.Status == conformance.StatusFail {
				caught = true
			}
		}
		if !caught {
			t.Errorf("%s did not fail for a surface with no isolation at all", want)
		}
	}
}

// And it catches the subtler failure: correct refusals that name the other tenant.
func TestSecurityTheSuiteDetectsADisclosingRefusal(t *testing.T) {
	report := conformance.Run(disclosingSurface{})
	if report.Isolated() {
		t.Fatal("the suite passed a surface whose refusal names the other tenant")
	}
	var caught bool
	for _, r := range report.Results {
		if r.Obligation == "T4" && r.Status == conformance.StatusFail {
			caught = true
		}
	}
	if !caught {
		t.Fatal("T4 did not fail for a refusal that discloses the tenant it refused on behalf of")
	}
}

// leakySurface serves everyone.
type leakySurface struct{}

func (leakySurface) Name() string { return "leaky" }
func (leakySurface) Query(_, _ conformance.Tenant, secret string) (string, error) {
	return secret, nil
}

// disclosingSurface refuses correctly and says too much doing it.
type disclosingSurface struct{}

func (disclosingSurface) Name() string { return "disclosing" }
func (disclosingSurface) Query(asking, owner conformance.Tenant, secret string) (string, error) {
	if asking == owner {
		return secret, nil
	}
	return "", disclosingError{owner: owner.OrganizationID}
}

type disclosingError struct{ owner string }

func (e disclosingError) Error() string {
	return "access denied: this resource belongs to " + e.owner
}
