package session_test

import (
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/session"
)

// §17.4 invariants (N1–N7). One test each; a test without an N-number, or an N-number without a
// test, is a gap.
//
//	N1 The access TTL ceiling is fifteen minutes and policy may only shorten it.
//	N2 A refresh token rotates: the spent one cannot be exchanged again.
//	N3 A replayed token revokes the whole family, rather than being merely rejected.
//	N4 An agent, tool, sandbox, plugin or MCP surface never holds session credentials.
//	N5 The zero Surface is untrusted, so an unrecognised surface gets the restrictive answer.
//	N6 An unscoped token is refused.
//	N7 Revocation is immediate and idempotent.

func manager(t *testing.T, p session.Policy) *session.Manager {
	t.Helper()
	m, err := session.NewManager(p)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// N1. Policy may shorten a session and may not extend one.
//
// A configurable maximum with no ceiling would let an operator set an eight-hour session and satisfy
// the letter of a setting while removing the property the requirement exists for.
func TestSecurityPolicyCannotExtendTheAccessTTL(t *testing.T) {
	if _, err := session.NewManager(session.Policy{AccessTTL: time.Hour}); err == nil {
		t.Fatal("a one-hour access TTL was accepted against a fifteen-minute maximum")
	}
	if _, err := session.NewManager(session.Policy{AccessTTL: -time.Minute}); err == nil {
		t.Fatal("a negative access TTL was accepted")
	}

	now := time.Now()
	// Default is the ceiling.
	m := manager(t, session.Policy{})
	access, _, err := m.Begin(session.SurfaceDesktop, []string{"repo:read"}, now)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if got := access.ExpiresAt.Sub(now); got != session.MaxAccessTTL {
		t.Fatalf("default TTL = %s, want %s", got, session.MaxAccessTTL)
	}

	// Shortening is honoured.
	m = manager(t, session.Policy{AccessTTL: time.Minute})
	access, _, err = m.Begin(session.SurfaceDesktop, []string{"repo:read"}, now)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if got := access.ExpiresAt.Sub(now); got != time.Minute {
		t.Fatalf("shortened TTL = %s, want 1m", got)
	}
	if access.Expired(now.Add(2*time.Minute)) != true {
		t.Fatal("a one-minute token was still live two minutes later")
	}
}

// N2. Rotation: the spent token cannot be exchanged again.
func TestSecurityASpentRefreshTokenCannotBeReused(t *testing.T) {
	now := time.Now()
	m := manager(t, session.Policy{})
	_, first, err := m.Begin(session.SurfaceCLI, []string{"repo:read"}, now)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	_, second, err := m.Exchange(first, now)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if second.Generation == first.Generation {
		t.Fatal("the exchange returned a token of the same generation; nothing rotated")
	}
	// The new one works.
	if _, _, err := m.Exchange(second, now); err != nil {
		t.Fatalf("the freshly issued token was refused: %v", err)
	}
}

// N3. A replayed token revokes the family.
//
// Rotation that merely invalidates the spent token handles the case where the attacker is late. It
// does nothing about the attacker getting there first — then the *client's* next exchange presents
// an already-rotated token, and a system that only rejects it has told the legitimate user their
// session ended and told nobody anything else.
//
// A rotated token coming back proves two parties hold the same secret. Neither is identifiable from
// the exchange, so the family goes.
func TestSecurityAReplayedRefreshTokenRevokesTheFamily(t *testing.T) {
	now := time.Now()
	m := manager(t, session.Policy{})
	_, stolen, err := m.Begin(session.SurfaceDesktop, []string{"repo:read"}, now)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// The attacker exchanges first and holds a live token.
	_, attacker, err := m.Exchange(stolen, now)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !m.Live(stolen.FamilyID) {
		t.Fatal("the family died on a legitimate first exchange")
	}

	// The real client presents the copy it still holds. That is the replay.
	if _, _, err := m.Exchange(stolen, now); err == nil {
		t.Fatal("a replayed refresh token was exchanged")
	} else if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Fatalf("err = %v, want CodePolicyDenied", err)
	}

	// And the attacker's live token dies with it: rejecting the replay alone would leave the thief
	// holding the only working credential.
	if m.Live(stolen.FamilyID) {
		t.Fatal("the family survived a replay")
	}
	if _, _, err := m.Exchange(attacker, now); err == nil {
		t.Fatal("the attacker's token still worked after the replay was detected")
	}
}

// N4, N5. §17.4: refresh tokens are never available to agents, tools, sandboxes, plugins or MCP
// servers — and an unrecognised surface is treated as one of them.
//
// An allowlist rather than a denylist, because the exclusion list names today's untrusted surfaces
// and tomorrow's would not be on it.
func TestSecurityUntrustedSurfacesNeverHoldSessionCredentials(t *testing.T) {
	now := time.Now()
	m := manager(t, session.Policy{})

	for _, s := range []session.Surface{
		session.SurfaceUnknown, "agent", "tool", "sandbox", "plugin", "mcp", "browser-host",
	} {
		if s.HoldsRefreshToken() {
			t.Errorf("surface %q reported itself able to hold a refresh token", s)
		}
		if _, _, err := m.Begin(s, []string{"repo:read"}, now); err == nil {
			t.Errorf("surface %q was issued session credentials", s)
		}
	}

	for _, s := range []session.Surface{
		session.SurfaceDesktop, session.SurfaceCLI, session.SurfaceWeb,
	} {
		if !s.HoldsRefreshToken() {
			t.Errorf("first-party surface %q was refused", s)
		}
	}
}

// N6. An unscoped token grants whatever the endpoint allows, which is the opposite of "scoped".
func TestAnUnscopedTokenIsRefused(t *testing.T) {
	m := manager(t, session.Policy{})
	if _, _, err := m.Begin(session.SurfaceWeb, nil, time.Now()); err == nil {
		t.Fatal("a session token with no scopes was issued")
	}
}

// N7. Revocation is immediate and idempotent.
func TestSecurityRevocationIsImmediateAndIdempotent(t *testing.T) {
	now := time.Now()
	m := manager(t, session.Policy{})
	_, refresh, err := m.Begin(session.SurfaceDesktop, []string{"repo:read"}, now)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	m.Revoke(refresh.FamilyID)
	m.Revoke(refresh.FamilyID) // must not panic or resurrect

	if m.Live(refresh.FamilyID) {
		t.Fatal("a revoked family reports itself live")
	}
	_, _, err = m.Exchange(refresh, now)
	if err == nil {
		t.Fatal("a revoked family was exchanged")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("err = %v; it must say the session was revoked", err)
	}

	// An unknown family is refused rather than treated as new.
	if _, _, err := m.Exchange(session.Refresh{FamilyID: "ses_nonexistent", Generation: 1}, now); err == nil {
		t.Fatal("an unrecognised family was exchanged")
	}
}
