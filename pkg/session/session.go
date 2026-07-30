// Package session issues and rotates client session tokens (§17.4).
//
// Boundary: it decides how long an access token lives, whether a refresh token may be exchanged,
// and what happens when a rotated one comes back. It stores nothing durably, speaks to no identity
// provider, and never hands a token to a caller it has not checked.
//
// Requirements: PRD §17.4 — access tokens are short lived and scoped with a maximum TTL of fifteen
// minutes that organization policy may shorten; refresh tokens are rotating, revocable, and never
// available to agents, tools, sandboxes, plugins or MCP servers. INV-2 makes that last clause the
// same rule the credential boundary follows.
//
// # Rotation is only worth having if replay is detected
//
// A rotating refresh token that is simply invalidated on use stops an attacker reusing a token the
// client already spent. It does nothing about the case that matters: the attacker gets there first.
// Then the *client's* next exchange presents a token that has already been rotated, and a system
// that merely rejects it has told the legitimate user their session ended and told nobody anything
// else.
//
// A rotated token coming back is proof that two parties hold the same secret. Neither can be
// identified as the impostor from the exchange alone, so the whole family is revoked. That costs the
// legitimate user a re-authentication and costs the attacker the session, and it is the only
// outcome that does not require guessing which one is which.
//
// # Why the TTL ceiling cannot be raised
//
// Policy "MAY require a shorter TTL". A configurable maximum with no ceiling would let an operator
// set an eight-hour session and satisfy the letter of a setting while removing the property the
// requirement exists for. Configuration tightens; it does not repeal — the same rule MEM-2's
// corroboration floor follows.
package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// MaxAccessTTL is §17.4's ceiling. Policy may shorten it and may not exceed it.
const MaxAccessTTL = 15 * time.Minute

// Surface is where a token is being requested for.
type Surface string

const (
	// SurfaceUnknown is the zero value and is never permitted a refresh token.
	//
	// The list §17.4 excludes — agents, tools, sandboxes, plugins, MCP servers — is open-ended in
	// practice, so an unrecognised surface is treated as one of them rather than as a client. A new
	// surface added without touching this file gets the restrictive answer.
	SurfaceUnknown Surface = ""
	// SurfaceDesktop, SurfaceCLI and SurfaceWeb are first-party clients.
	SurfaceDesktop Surface = "desktop"
	SurfaceCLI     Surface = "cli"
	SurfaceWeb     Surface = "web"
)

// HoldsRefreshToken reports whether a surface may ever hold a refresh token.
//
// Allowlist rather than denylist, for the reason the zero value is restrictive: §17.4's exclusions
// name today's untrusted surfaces, and tomorrow's would not be on the list.
func (s Surface) HoldsRefreshToken() bool {
	return s == SurfaceDesktop || s == SurfaceCLI || s == SurfaceWeb
}

// Policy is the organization's tightening of the defaults.
type Policy struct {
	// AccessTTL shortens the access-token lifetime. Zero selects MaxAccessTTL.
	AccessTTL time.Duration `json:"access_ttl"`
}

// Validate refuses a policy that tries to exceed the ceiling.
func (p Policy) Validate() error {
	if p.AccessTTL < 0 {
		return field("a negative access TTL", "access_ttl")
	}
	if p.AccessTTL > MaxAccessTTL {
		return field(fmt.Sprintf(
			"an access TTL of %s exceeds the %s maximum; policy may shorten a session and may not extend one",
			p.AccessTTL, MaxAccessTTL), "access_ttl")
	}
	return nil
}

func (p Policy) accessTTL() time.Duration {
	if p.AccessTTL == 0 {
		return MaxAccessTTL
	}
	return p.AccessTTL
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// Access is a short-lived scoped access token.
type Access struct {
	FamilyID  id.ID     `json:"family_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the token has elapsed at now.
func (a Access) Expired(now time.Time) bool {
	return a.ExpiresAt.IsZero() || !now.Before(a.ExpiresAt)
}

// Refresh is a rotating refresh token.
//
// Generation increments on every exchange. It is what makes replay detectable: a token presented
// with a generation the family has moved past is a copy.
type Refresh struct {
	FamilyID   id.ID `json:"family_id"`
	Generation int   `json:"generation"`
}

// familyState is the server-side record for one login.
type familyState struct {
	generation int
	revoked    bool
	surface    Surface
	scopes     []string
}

// Manager issues and rotates tokens for a set of families.
type Manager struct {
	policy Policy

	mu       sync.Mutex
	families map[id.ID]*familyState
}

// NewManager returns a manager, refusing a policy weaker than §17.4 permits.
func NewManager(p Policy) (*Manager, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &Manager{policy: p, families: map[id.ID]*familyState{}}, nil
}

// Begin starts a session and issues the first token pair.
//
// A surface that may not hold a refresh token is refused outright rather than issued an access
// token alone: §17.4 is about who holds session credentials, and an agent holding a short-lived one
// is still an agent holding one.
func (m *Manager) Begin(surface Surface, scopes []string, now time.Time) (Access, Refresh, error) {
	if !surface.HoldsRefreshToken() {
		return Access{}, Refresh{}, modberr.Newf(modberr.CodePolicyDenied,
			"surface %q may not hold session credentials", surfaceName(surface)).
			WithDetail("constraint", "session_surface")
	}
	if len(scopes) == 0 {
		// An unscoped token is a token that grants whatever the endpoint allows, which is the
		// opposite of §17.4's "scoped".
		return Access{}, Refresh{}, field("a session token has no scopes", "scopes")
	}

	family := id.MustNew(id.Session)
	m.mu.Lock()
	m.families[family] = &familyState{generation: 1, surface: surface, scopes: scopes}
	m.mu.Unlock()

	return Access{
			FamilyID: family, Scopes: scopes, ExpiresAt: now.Add(m.policy.accessTTL()),
		}, Refresh{
			FamilyID: family, Generation: 1,
		}, nil
}

// Exchange rotates a refresh token, or detects a replay.
//
// On success the presented token is spent and a new generation is issued. On replay — a generation
// the family has already moved past — the whole family is revoked and an error returned. See the
// package comment for why revocation rather than rejection.
func (m *Manager) Exchange(r Refresh, now time.Time) (Access, Refresh, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, known := m.families[r.FamilyID]
	if !known {
		return Access{}, Refresh{}, denied("the session is not recognised")
	}
	if state.revoked {
		return Access{}, Refresh{}, denied("the session has been revoked")
	}
	if r.Generation != state.generation {
		// Two parties hold this token and the exchange cannot say which one is legitimate. Revoking
		// the family costs the real user a re-authentication and costs the attacker the session,
		// which is the only outcome that does not require guessing.
		state.revoked = true
		return Access{}, Refresh{}, modberr.New(modberr.CodePolicyDenied,
			"the refresh token has already been rotated; the session has been revoked").
			WithDetail("constraint", "refresh_replay")
	}

	state.generation++
	return Access{
			FamilyID: r.FamilyID, Scopes: state.scopes, ExpiresAt: now.Add(m.policy.accessTTL()),
		}, Refresh{
			FamilyID: r.FamilyID, Generation: state.generation,
		}, nil
}

// Revoke ends a session. It is idempotent, for the reason every revocation here is: it arrives from
// several directions and a second call failing turns a safe duplicate into a suppressed error.
func (m *Manager) Revoke(family id.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if state, known := m.families[family]; known {
		state.revoked = true
	}
}

// Live reports whether a family can still be exchanged.
func (m *Manager) Live(family id.ID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, known := m.families[family]
	return known && !state.revoked
}

func denied(msg string) error {
	return modberr.New(modberr.CodePolicyDenied, msg).WithDetail("constraint", "session")
}

func surfaceName(s Surface) string {
	if s == SurfaceUnknown {
		return "unknown"
	}
	return string(s)
}
