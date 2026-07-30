// Package coordination detects overlap between concurrent runs and holds advisory locks
// (CRC-1, CRC-2, CRC-5, CRC-6).
//
// Boundary: it compares what runs have claimed and reports where they collide. It performs no
// rebase, talks to no source-control provider, and blocks nothing — a caller decides what to do
// with a conflict, and CRC-5 says that decision is never silent.
//
// Requirements: PRD §11C CRC-1, CRC-2, CRC-5, CRC-6. CRC-3 (speculative rebase) and CRC-4
// (merge-queue state) need git and a provider and are not here.
//
// # The dangerous instinct in an overlap detector
//
// Overlap detection wants to compare everything. That is what makes it useful and what makes it a
// disclosure risk: CRC-6 scopes coordination metadata per tenant, and INV-10 makes cross-Space or
// cross-organization leakage a release blocker. A detector that reported "another run is editing
// this symbol" across a tenant boundary would leak that a different organization has a run, on
// which repository, touching which symbol — three facts, none of them the caller's.
//
// So scoping is not a filter applied to results. `Overlaps` refuses a comparison between scopes in
// different tenants rather than returning an empty answer, because "no overlap" and "not permitted
// to know" must not be the same reply.
//
// # Why an advisory lock never blocks
//
// CRC-2 says advisory locks are "visible, never silently blocking". Both halves matter, and the
// second is the unusual one: a lock here does not stop a run, it tells the operator that two runs
// intend the same code. Enforcing it would turn a coordination hint into a deadlock between two
// agents that cannot negotiate, and the failure would look like a hung run rather than a conflict.
package coordination

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// ScopeKind is what a run claimed.
type ScopeKind string

const (
	// ScopeSymbol is a qualified symbol name, the finest granularity CRC-1 names.
	ScopeSymbol ScopeKind = "symbol"
	// ScopeFile is a repository-relative path.
	ScopeFile ScopeKind = "file"
	// ScopePackage is a directory prefix.
	ScopePackage ScopeKind = "package"
)

// Claim is one thing a run intends to change.
type Claim struct {
	Kind ScopeKind `json:"kind"`
	// Ref is the symbol name, path, or package prefix, depending on Kind.
	Ref string `json:"ref"`
}

// Valid reports whether the claim is interpretable.
func (c Claim) Valid() bool {
	switch c.Kind {
	case ScopeSymbol, ScopeFile, ScopePackage:
		return strings.TrimSpace(c.Ref) != ""
	default:
		return false
	}
}

// Scope is everything one run has claimed, within one tenant and repository.
type Scope struct {
	RunID id.ID `json:"run_id"`
	// OrganizationID and SpaceID are the tenancy boundary CRC-6 scopes to and INV-10 protects.
	OrganizationID id.ID   `json:"organization_id"`
	SpaceID        id.ID   `json:"space_id"`
	RepositoryID   id.ID   `json:"repository_id"`
	Claims         []Claim `json:"claims"`
	// DependencyClosure is the set of files the claims transitively affect, from the symbol and
	// dependency graph (CTX-A01e). CRC-1 asks for dependency-graph overlap and not only direct
	// overlap: two runs editing different files that import the same changed symbol conflict, and
	// comparing claims alone would miss it.
	DependencyClosure []string `json:"dependency_closure,omitempty"`
}

// Validate checks a scope can participate in a comparison.
func (s Scope) Validate() error {
	switch {
	case s.RunID.IsZero():
		return field("a scope names no run", "run_id")
	case s.OrganizationID.IsZero():
		// Tenancy is not optional. A scope with no organization could not be excluded from a
		// cross-tenant comparison, which is the check CRC-6 and INV-10 depend on.
		return field("a scope names no organization; coordination metadata is tenant scoped", "organization_id")
	case s.RepositoryID.IsZero():
		return field("a scope names no repository", "repository_id")
	}
	for _, c := range s.Claims {
		if !c.Valid() {
			return field(fmt.Sprintf("run %s made an uninterpretable claim", s.RunID), "claims")
		}
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// SameTenant reports whether two scopes share an organization and Space.
func (s Scope) SameTenant(other Scope) bool {
	return s.OrganizationID == other.OrganizationID && s.SpaceID == other.SpaceID
}

// Conflict is a detected overlap between two runs (CRC-1, CRC-5).
type Conflict struct {
	RunA id.ID `json:"run_a"`
	RunB id.ID `json:"run_b"`
	// Kind is how the overlap was found: a shared claim, or a shared dependency-closure file.
	Kind ScopeKind `json:"kind"`
	// Ref is what both runs touch.
	Ref string `json:"ref"`
	// Direct distinguishes an overlap both runs claimed from one reached through the dependency
	// closure. Both are conflicts; only the first is something either author wrote down.
	Direct bool `json:"direct"`
}

// Overlaps reports every conflict between two scopes (CRC-1).
//
// It refuses a cross-tenant comparison rather than returning nothing, because an empty result and a
// forbidden one must be distinguishable to the caller — and indistinguishable to anyone probing.
// See the package comment.
func Overlaps(a, b Scope) ([]Conflict, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if !a.SameTenant(b) {
		// The message names neither run, repository nor claim. A caller learning "your run overlaps
		// something you may not see" has already learned the thing CRC-6 withholds.
		return nil, modberr.New(modberr.CodePolicyDenied,
			"coordination metadata is tenant scoped; these scopes are not comparable").
			WithDetail("constraint", "tenant_scope")
	}
	if a.RepositoryID != b.RepositoryID {
		// Not an error: CRC-1 scopes overlap to "runs targeting the same repository", so two runs on
		// different repositories simply do not overlap.
		return nil, nil
	}
	if a.RunID == b.RunID {
		return nil, nil
	}

	var conflicts []Conflict
	claimed := make(map[Claim]bool, len(a.Claims))
	for _, c := range a.Claims {
		claimed[c] = true
	}
	for _, c := range b.Claims {
		if claimed[c] {
			conflicts = append(conflicts, Conflict{
				RunA: a.RunID, RunB: b.RunID, Kind: c.Kind, Ref: c.Ref, Direct: true,
			})
		}
	}

	// CRC-1's dependency half. Two runs editing different files that both sit in the other's
	// closure conflict semantically even though neither claimed the other's file.
	inClosure := make(map[string]bool, len(a.DependencyClosure))
	for _, p := range a.DependencyClosure {
		inClosure[p] = true
	}
	for _, p := range b.DependencyClosure {
		if inClosure[p] && !hasDirect(conflicts, p) {
			conflicts = append(conflicts, Conflict{
				RunA: a.RunID, RunB: b.RunID, Kind: ScopeFile, Ref: p, Direct: false,
			})
		}
	}

	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Direct != conflicts[j].Direct {
			return conflicts[i].Direct // direct conflicts first: they are what an author recognises
		}
		if conflicts[i].Kind != conflicts[j].Kind {
			return conflicts[i].Kind < conflicts[j].Kind
		}
		return conflicts[i].Ref < conflicts[j].Ref
	})
	return conflicts, nil
}

func hasDirect(conflicts []Conflict, ref string) bool {
	for _, c := range conflicts {
		if c.Ref == ref {
			return true
		}
	}
	return false
}

// Lock is an advisory claim on a scope (CRC-2).
//
// Advisory means exactly what CRC-2 says: visible, and never silently blocking. Nothing in this
// package prevents a run from proceeding against a held lock — `Held` reports, and a caller that
// chose to enforce would be making a decision CRC-2 reserves for a human.
type Lock struct {
	RunID     id.ID     `json:"run_id"`
	Claim     Claim     `json:"claim"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the lock has lapsed at now.
//
// CRC-2 requires locks to expire with the run. A lock with no expiry is treated as already expired
// rather than as eternal: an unbounded advisory lock left by a crashed run would shadow a symbol
// indefinitely, and the failure would be invisible because nothing blocks.
func (l Lock) Expired(now time.Time) bool {
	return l.ExpiresAt.IsZero() || !now.Before(l.ExpiresAt)
}

// Registry holds advisory locks for one tenant.
type Registry struct {
	organizationID id.ID
	spaceID        id.ID
	locks          []Lock
}

// NewRegistry returns a lock registry bound to one tenant.
func NewRegistry(organizationID, spaceID id.ID) (*Registry, error) {
	if organizationID.IsZero() {
		return nil, field("a lock registry names no organization", "organization_id")
	}
	return &Registry{organizationID: organizationID, spaceID: spaceID}, nil
}

// Take records an advisory lock. It never fails on contention (CRC-2).
func (r *Registry) Take(l Lock) error {
	if l.RunID.IsZero() {
		return field("a lock names no run", "run_id")
	}
	if !l.Claim.Valid() {
		return field("a lock makes an uninterpretable claim", "claim")
	}
	if l.ExpiresAt.IsZero() {
		return field("a lock has no expiry; CRC-2 requires locks to expire with the run", "expires_at")
	}
	r.locks = append(r.locks, l)
	return nil
}

// Held returns the live locks on a claim, excluding the asking run's own (CRC-2).
//
// Returning them rather than refusing is the whole of "never silently blocking": the caller sees
// who else intends this code and decides. An empty result means nobody else holds it, which is a
// different statement from being allowed to proceed — this package never makes the second.
func (r *Registry) Held(claim Claim, asking id.ID, now time.Time) []Lock {
	var held []Lock
	for _, l := range r.locks {
		if l.Expired(now) || l.RunID == asking || l.Claim != claim {
			continue
		}
		held = append(held, l)
	}
	sort.Slice(held, func(i, j int) bool { return held[i].ExpiresAt.Before(held[j].ExpiresAt) })
	return held
}

// Release drops every lock a run holds, which is what "expire with the run" means when the run ends
// cleanly.
func (r *Registry) Release(runID id.ID) {
	kept := r.locks[:0]
	for _, l := range r.locks {
		if l.RunID != runID {
			kept = append(kept, l)
		}
	}
	r.locks = kept
}

// Tenant reports the registry's tenancy, so a caller can refuse to mix registries.
func (r *Registry) Tenant() (organizationID, spaceID id.ID) {
	return r.organizationID, r.spaceID
}
