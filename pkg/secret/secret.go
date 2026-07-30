// Package secret leases task secrets for a bounded purpose (SEC-10..SEC-17).
//
// Boundary: it decides whether a lease may be used, in what context, and how many times, and it
// keeps the value out of every path a value normally escapes by. It stores nothing durably, injects
// nothing into a process, and never writes to a log.
//
// Requirements: PRD §17.3 SEC-10, SEC-13, SEC-14, SEC-16, SEC-17.
//
// # A lease is a tuple, not a token
//
// SEC-13 binds an injected secret lease to "one run, step, tool, executable identity, worker, and
// environment". That is six coordinates, and the reason to check all six is that a token which works
// anywhere is a token whose theft is undetectable — it produces valid use from the wrong place, and
// nothing in the record distinguishes that from correct use.
//
// So `Use` takes the full context and compares it whole. A partial match is a mismatch: five
// coordinates agreeing means the sixth was substituted, which is the case worth catching rather
// than rounding off.
//
// # Why the value is unreachable rather than merely private
//
// SEC-14 excludes secret values from trace, prompt, logs, command display, shell history, process
// listings and artifacts. That is a list of places a string ends up when someone formats a struct,
// so the defence cannot be a rule about formatting — it has to be that formatting cannot reach it.
// The value lives in an unexported field behind a single accessor, and String, GoString and
// MarshalJSON are all implemented to return a redaction marker.
package secret

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// Binding is the context a lease is valid in (SEC-13).
//
// Every field participates in the comparison. A zero field is not a wildcard — see Validate — because
// a lease that matched "any tool" would be exactly the anywhere-token SEC-13 forbids.
type Binding struct {
	RunID  id.ID `json:"run_id"`
	StepID id.ID `json:"step_id"`
	// ToolID is the typed tool the secret was leased to.
	ToolID string `json:"tool_id"`
	// ExecutableIdentity is what will actually run — a digest or signed identity, not a path, since
	// a path is a name and names are reused.
	ExecutableIdentity string `json:"executable_identity"`
	WorkerID           string `json:"worker_id"`
	EnvironmentID      string `json:"environment_id"`
}

// Validate refuses a binding with any coordinate missing.
//
// SEC-13 lists six, and an absent one would widen the lease silently: a caller that forgot to set
// WorkerID would produce a lease usable from every worker, and nothing about the resulting use
// would look wrong.
func (b Binding) Validate() error {
	switch {
	case b.RunID.IsZero():
		return field("a lease binding names no run", "run_id")
	case b.StepID.IsZero():
		return field("a lease binding names no step", "step_id")
	case strings.TrimSpace(b.ToolID) == "":
		return field("a lease binding names no tool", "tool_id")
	case strings.TrimSpace(b.ExecutableIdentity) == "":
		return field("a lease binding names no executable identity", "executable_identity")
	case strings.TrimSpace(b.WorkerID) == "":
		return field("a lease binding names no worker", "worker_id")
	case strings.TrimSpace(b.EnvironmentID) == "":
		return field("a lease binding names no environment", "environment_id")
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// redacted is what every disclosure path yields.
const redacted = "modbit.Lease(redacted)"

// Lease is a task secret bound to one context for a bounded number of uses.
type Lease struct {
	ID      id.ID   `json:"id"`
	Binding Binding `json:"binding"`
	// Scope names what the secret is for, so an administrator reviewing SEC-9 sees purpose rather
	// than only existence.
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	// MaxUses bounds how many times the value may be read (SEC-10, SEC-13).
	MaxUses int `json:"max_uses"`
	// InheritToChildren is false by default: SEC-13 denies child-process inheritance unless it is
	// asked for, because a secret that survives into a child survives into whatever that child
	// spawns, and the boundary stops being describable.
	InheritToChildren bool `json:"inherit_to_children"`

	mu      sync.Mutex
	used    int
	revoked bool
	secret  string
}

// NewLease mints a lease. Only a broker inside the secret boundary should call this.
func NewLease(leaseID id.ID, b Binding, scope, value string, expiresAt time.Time, maxUses int) (*Lease, error) {
	if leaseID.IsZero() {
		return nil, field("a lease has no identifier", "id")
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(scope) == "" {
		return nil, field("a lease names no scope", "scope")
	}
	if value == "" {
		return nil, field("a lease carries no secret", "value")
	}
	if expiresAt.IsZero() {
		// SEC-13 requires leases to be short lived. An unbounded lease is the one that outlives the
		// run, the worker and the incident that justified it.
		return nil, field("a lease has no expiry; SEC-13 requires it to be short lived", "expires_at")
	}
	if maxUses <= 0 {
		return nil, field("a lease permits no uses; SEC-10 requires a use count", "max_uses")
	}
	return &Lease{
		ID: leaseID, Binding: b, Scope: scope, ExpiresAt: expiresAt, MaxUses: maxUses,
		secret: value,
	}, nil
}

// Use returns the secret if the caller's context matches the binding and the lease is live.
//
// The whole binding is compared. Five coordinates agreeing means the sixth was substituted, which is
// the theft case rather than a near miss.
func (l *Lease) Use(ctx Binding, now time.Time) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	switch {
	case l.revoked:
		return "", denied("the lease has been revoked")
	case !now.Before(l.ExpiresAt):
		return "", denied("the lease has expired")
	case l.used >= l.MaxUses:
		return "", denied("the lease has no uses remaining")
	case ctx != l.Binding:
		// The message names no coordinate. Reporting which one differed would let a caller holding a
		// stolen value discover the binding by probing one field at a time.
		return "", denied("the lease is not valid in this context")
	}
	l.used++
	return l.secret, nil
}

func denied(msg string) error {
	return modberr.New(modberr.CodePolicyDenied, msg).WithDetail("constraint", "secret_lease")
}

// Revoke ends the lease (SEC-16).
//
// Idempotent, because revocation arrives from several directions at once — cancellation, expiry,
// worker loss, policy change — and a second revoke failing would turn a safe duplicate into an
// error somebody suppresses.
func (l *Lease) Revoke() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.revoked = true
}

// Remaining reports uses left, without disclosing the value.
func (l *Lease) Remaining() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revoked {
		return 0
	}
	return l.MaxUses - l.used
}

// Live reports whether the lease could still be used at now.
func (l *Lease) Live(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.revoked && now.Before(l.ExpiresAt) && l.used < l.MaxUses
}

// String satisfies fmt.Stringer so %v and %s cannot print the secret (SEC-14).
func (l *Lease) String() string { return redacted }

// GoString does the same for %#v, which ignores Stringer.
func (l *Lease) GoString() string { return redacted }

// MarshalJSON keeps the value out of any structure that gets serialized.
//
// The struct's own tags would already omit an unexported field, so this is belt and braces — and it
// is worth having, because the failure it prevents is a future field being added without anyone
// rechecking what encoding/json will reach.
func (l *Lease) MarshalJSON() ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return json.Marshal(struct {
		ID        id.ID     `json:"id"`
		Binding   Binding   `json:"binding"`
		Scope     string    `json:"scope"`
		ExpiresAt time.Time `json:"expires_at"`
		MaxUses   int       `json:"max_uses"`
		Used      int       `json:"used"`
		Revoked   bool      `json:"revoked"`
	}{l.ID, l.Binding, l.Scope, l.ExpiresAt, l.MaxUses, l.used, l.revoked})
}

// InjectionContract is what a tool must satisfy to receive an injected secret (SEC-13, SEC-17).
type InjectionContract struct {
	// AdministratorApproved is SEC-12's gate: injection is permitted only for approved secret types
	// and tools.
	AdministratorApproved bool `json:"administrator_approved"`
	// SuppressesCommandEcho, ClearsOnExit and DeniesChildInheritance are the SEC-13 minimisations.
	SuppressesCommandEcho  bool `json:"suppresses_command_echo"`
	ClearsOnExit           bool `json:"clears_on_exit"`
	DeniesChildInheritance bool `json:"denies_child_inheritance"`
}

// MayInject reports whether a tool may receive a process-scoped injected secret.
//
// SEC-11 prefers brokered use, and SEC-17 says a tool that cannot meet the contract must be brokered
// or denied. So this answers "may inject", never "must inject" — and every unmet clause is named, so
// a tool author knows what to implement rather than being told no.
func MayInject(c InjectionContract) (bool, []string) {
	var unmet []string
	if !c.AdministratorApproved {
		unmet = append(unmet, "an administrator has not approved injection for this secret type and tool")
	}
	if !c.SuppressesCommandEcho {
		unmet = append(unmet, "the tool does not suppress command echo")
	}
	if !c.ClearsOnExit {
		unmet = append(unmet, "the tool does not clear the secret on exit")
	}
	if !c.DeniesChildInheritance {
		unmet = append(unmet, "the tool does not deny child-process inheritance")
	}
	return len(unmet) == 0, unmet
}

// Describe renders a lease for an audit line, with no value in it.
func (l *Lease) Describe() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return fmt.Sprintf("lease %s scope=%q run=%s tool=%s uses=%d/%d revoked=%v",
		l.ID, l.Scope, l.Binding.RunID, l.Binding.ToolID, l.used, l.MaxUses, l.revoked)
}
