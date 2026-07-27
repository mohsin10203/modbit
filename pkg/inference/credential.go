package inference

import (
	"log/slog"
	"time"
)

// Credential is a leased provider credential.
//
// Requirements: INV-2 — provider credentials must not enter the IDE, extension host, agent context,
// worker, sandbox, browser host, plugin, hook, or MCP server. They exist only inside the Model
// Gateway boundary and are handed to an adapter for the duration of one call.
//
// # Why the type exists rather than a plain string
//
// Go cannot stop a package from reading a value it was given, so the protection here is not access
// control — it is making *accidental* disclosure impossible. A raw string leaks the moment anyone
// writes %v, json.Marshal, or slog.Any on a struct that happens to contain it, and that is how
// credentials actually escape in practice. Credential implements Stringer, json.Marshaler, and
// slog.LogValuer so that every one of those paths yields a redaction marker instead.
//
// The secret is unexported and reachable only through Secret(), which is a call site a reviewer can
// grep for and a linter can flag.
type Credential struct {
	// ProviderID names the provider this credential authenticates to. An adapter must refuse a
	// credential minted for a different provider.
	ProviderID string
	// LeaseID identifies the lease for audit correlation.
	LeaseID string
	// ExpiresAt bounds the credential's lifetime. Leases are per call, not per process.
	ExpiresAt time.Time

	secret string
}

// NewCredential mints a credential. Only a credential broker inside the gateway boundary should
// call this.
func NewCredential(providerID, leaseID, secret string, expiresAt time.Time) Credential {
	return Credential{ProviderID: providerID, LeaseID: leaseID, ExpiresAt: expiresAt, secret: secret}
}

// Secret returns the credential material.
//
// Every call site is a place a provider credential crosses a boundary. Keep them inside adapter
// request construction; never store the result in a struct field, a closure that outlives the call,
// a log, or an error.
func (c Credential) Secret() string { return c.secret }

// IsZero reports whether the credential is unset.
func (c Credential) IsZero() bool { return c.secret == "" && c.ProviderID == "" }

// Expired reports whether the lease has elapsed at now.
func (c Credential) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
}

// redacted is the marker every accidental-disclosure path yields.
const redacted = "modbit.Credential(redacted)"

// String satisfies fmt.Stringer so %v and %s cannot print the secret.
func (c Credential) String() string { return redacted }

// GoString satisfies fmt.GoStringer so %#v cannot print the secret.
func (c Credential) GoString() string { return redacted }

// MarshalJSON ensures a credential embedded in a serialized struct becomes a marker, not material.
func (c Credential) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// LogValue satisfies slog.LogValuer so structured logging cannot emit the secret.
func (c Credential) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider_id", c.ProviderID),
		slog.String("lease_id", c.LeaseID),
		slog.String("secret", redacted),
	)
}
