// Package event implements Modbit's canonical event envelope.
//
// Boundary: envelope construction, validation, serialization, and per-run sequence allocation. It
// does not publish, persist, or subscribe — transport lives in the event-bus adapter, and
// durability lives in the transactional outbox.
//
// Requirements: api-and-events-v5.1.md §4–§5; rules.md INV-5 (every authoritative run transition
// emits the envelope), R-EVT-01 (append-only, monotonic per-run sequence), R-EVT-02 (envelope
// completeness), R-EVT-03 (payloads by reference).
//
// # Why payloads are references
//
// The envelope carries payload_ref and payload_hash, never a body. Run payloads routinely contain
// prompts, tool output, and diffs; keeping them in the object store behind a hash means the event
// log can be replicated, exported, and retained on a different schedule from the content it
// describes, and that a redaction applies in one place.
package event

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// Family groups related event types.
type Family string

// Type is a canonical event type from contracts/events/catalog.yaml.
type Type string

// Scope declares which identifiers an event type requires. Validation is driven from it.
type Scope string

const (
	// ScopeSystem covers control-plane lifecycle events that precede tenancy.
	ScopeSystem Scope = "system"
	// ScopeOrganization requires organization_id.
	ScopeOrganization Scope = "organization"
	// ScopeWorker requires organization_id and identifies a worker.
	ScopeWorker Scope = "worker"
	// ScopeSpace requires organization_id and space_id.
	ScopeSpace Scope = "space"
	// ScopeRun requires organization_id, space_id, run_id, and a positive sequence.
	ScopeRun Scope = "run"
)

// Spec is the catalog entry for an event type.
type Spec struct {
	Type    Type
	Version int
	Family  string
	Scope   Scope
	// Audit marks events that must reach the audit log in addition to the event stream.
	Audit bool
}

// ActorType identifies who or what caused an event.
type ActorType string

const (
	ActorUser    ActorType = "user"
	ActorService ActorType = "service"
	ActorAgent   ActorType = "agent"
	ActorWorker  ActorType = "worker"
	ActorSystem  ActorType = "system"
)

var validActorTypes = map[ActorType]bool{
	ActorUser: true, ActorService: true, ActorAgent: true, ActorWorker: true, ActorSystem: true,
}

// Actor is the event's originator.
type Actor struct {
	Type ActorType `json:"type"`
	ID   string    `json:"id"`
}

// payloadHashPattern matches the sha256:<64 lowercase hex> form used for payload_hash.
var payloadHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Envelope is the canonical Modbit event envelope (api-and-events-v5.1.md §4).
//
// Field order and JSON names are part of the wire contract. Adding a field is additive; renaming
// or removing one is a new event version.
type Envelope struct {
	EventID        id.ID  `json:"event_id"`
	EventType      Type   `json:"event_type"`
	EventVersion   int    `json:"event_version"`
	OrganizationID id.ID  `json:"organization_id,omitempty"`
	SpaceID        id.ID  `json:"space_id,omitempty"`
	RunID          id.ID  `json:"run_id,omitempty"`
	Sequence       uint64 `json:"sequence,omitempty"`
	Actor          Actor  `json:"actor"`
	// Timestamp is always UTC and serializes as RFC 3339 with nanosecond precision (R-ID-03).
	Timestamp time.Time `json:"timestamp"`
	// CorrelationID ties every event produced while servicing one originating command.
	CorrelationID id.ID `json:"correlation_id,omitempty"`
	// CausationID points at the single event that directly triggered this one.
	CausationID id.ID `json:"causation_id,omitempty"`
	// PayloadRef and PayloadHash reference an immutable object-store payload (R-EVT-03).
	PayloadRef  id.ID  `json:"payload_ref,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
	// PolicyDecisionID is required for anything policy evaluated (INV-7).
	PolicyDecisionID id.ID `json:"policy_decision_id,omitempty"`
	// SettingsSnapshotID is required for anything run bound (INV-6).
	SettingsSnapshotID id.ID `json:"settings_snapshot_id,omitempty"`
}

// Lookup returns the catalog spec for t.
func Lookup(t Type) (Spec, bool) {
	s, ok := specs[t]
	return s, ok
}

// Types returns every registered event type, sorted.
func Types() []Type {
	out := make([]Type, 0, len(specs))
	for t := range specs {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// AuditTypes returns the event types that must also reach the audit log.
func AuditTypes() []Type {
	var out []Type
	for t, s := range specs {
		if s.Audit {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Attributes are the optional envelope fields supplied at construction.
//
// A struct is used rather than variadic options because every field here is a contract field: a
// reader of a call site should see exactly which envelope fields were populated.
type Attributes struct {
	SpaceID            id.ID
	RunID              id.ID
	Sequence           uint64
	CorrelationID      id.ID
	CausationID        id.ID
	PayloadRef         id.ID
	PayloadHash        string
	PolicyDecisionID   id.ID
	SettingsSnapshotID id.ID
}

// Clock supplies the event timestamp. Production uses SystemClock; tests inject a fixed clock so
// that golden envelopes are stable (R-TST-03).
type Clock interface {
	Now() time.Time
}

// SystemClock reads the wall clock and normalizes to UTC.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// Builder constructs validated envelopes for one organization.
//
// It holds no run state, so a Builder is safe to share across goroutines; per-run monotonicity is
// the Sequencer's responsibility.
type Builder struct {
	organizationID id.ID
	clock          Clock
	generator      *id.Generator
}

// NewBuilder returns a Builder bound to organizationID.
//
// A nil clock means SystemClock; a nil generator means the process CSPRNG.
func NewBuilder(organizationID id.ID, clock Clock, generator *id.Generator) (*Builder, error) {
	if !organizationID.IsZero() && !organizationID.HasPrefix(id.Organization) {
		return nil, modberr.New(modberr.CodeInvalidArgument, "organization identifier has the wrong prefix").
			WithDetail("field", "organization_id")
	}
	if clock == nil {
		clock = SystemClock{}
	}
	if generator == nil {
		generator = id.NewGenerator(nil)
	}
	return &Builder{organizationID: organizationID, clock: clock, generator: generator}, nil
}

// New builds and validates an envelope. It fails rather than emitting an incomplete envelope: an
// unvalidated event in an append-only log cannot be corrected later.
func (b *Builder) New(t Type, actor Actor, attrs Attributes) (Envelope, error) {
	spec, ok := specs[t]
	if !ok {
		return Envelope{}, modberr.Newf(modberr.CodeInvalidArgument, "unknown event type %q", t).
			WithDetail("field", "event_type")
	}
	eventID, err := b.generator.New(id.TraceEvent)
	if err != nil {
		return Envelope{}, modberr.Wrap(err, modberr.CodeInternal, "allocate event identifier")
	}
	e := Envelope{
		EventID:            eventID,
		EventType:          t,
		EventVersion:       spec.Version,
		OrganizationID:     b.organizationID,
		SpaceID:            attrs.SpaceID,
		RunID:              attrs.RunID,
		Sequence:           attrs.Sequence,
		Actor:              actor,
		Timestamp:          b.clock.Now().UTC(),
		CorrelationID:      attrs.CorrelationID,
		CausationID:        attrs.CausationID,
		PayloadRef:         attrs.PayloadRef,
		PayloadHash:        attrs.PayloadHash,
		PolicyDecisionID:   attrs.PolicyDecisionID,
		SettingsSnapshotID: attrs.SettingsSnapshotID,
	}
	if err := e.Validate(); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

// Validate enforces envelope completeness for the event's catalog scope.
//
// Validation runs on construction and again on ingestion, because an envelope may arrive from a
// worker, a webhook replay, or a peer control-plane process.
func (e Envelope) Validate() error {
	spec, ok := specs[e.EventType]
	if !ok {
		return modberr.Newf(modberr.CodeInvalidArgument, "unknown event type %q", e.EventType).
			WithDetail("field", "event_type")
	}
	if e.EventVersion != spec.Version {
		return modberr.Newf(modberr.CodeUnsupportedVersion,
			"event %q version %d does not match the catalog", e.EventType, e.EventVersion).
			WithDetail("requested_version", fmt.Sprint(e.EventVersion)).
			WithDetail("supported_versions", fmt.Sprint(spec.Version))
	}
	if !e.EventID.HasPrefix(id.TraceEvent) {
		return invalidField("event_id")
	}
	if e.Timestamp.IsZero() {
		return invalidField("timestamp")
	}
	if e.Timestamp.Location() != time.UTC {
		return modberr.New(modberr.CodeInvalidArgument, "timestamp must be UTC").
			WithDetail("field", "timestamp").
			WithDetail("constraint", "utc")
	}
	if !validActorTypes[e.Actor.Type] {
		return invalidField("actor.type")
	}
	if strings.TrimSpace(e.Actor.ID) == "" {
		return invalidField("actor.id")
	}

	// Scope-driven identifier requirements. Anything tenant scoped must carry organization_id, or
	// the event cannot be authorized, filtered, or retained per tenant (R-TEN-01, INV-10).
	if spec.Scope != ScopeSystem && !e.OrganizationID.HasPrefix(id.Organization) {
		return invalidField("organization_id")
	}
	if spec.Scope == ScopeSpace || spec.Scope == ScopeRun {
		if !e.SpaceID.HasPrefix(id.Space) {
			return invalidField("space_id")
		}
	}
	if spec.Scope == ScopeRun {
		if !e.RunID.HasPrefix(id.Run) {
			return invalidField("run_id")
		}
		if e.Sequence == 0 {
			return modberr.New(modberr.CodeInvalidArgument, "run-scoped events require a positive sequence").
				WithDetail("field", "sequence").
				WithDetail("constraint", "positive")
		}
	}

	// Optional identifiers must still carry the right prefix when present, so that a settings
	// snapshot id can never appear where a policy decision id belongs.
	//
	// The checks are an ordered slice rather than a map: with a map, an envelope carrying two
	// malformed identifiers would report a different field on each run, making the failure
	// irreproducible in a test or an incident (R-TST-03).
	for _, check := range []struct {
		field  string
		value  id.ID
		prefix id.Prefix
	}{
		{"correlation_id", e.CorrelationID, id.Correlation},
		{"causation_id", e.CausationID, id.TraceEvent},
		{"payload_ref", e.PayloadRef, id.ObjectRef},
		{"policy_decision_id", e.PolicyDecisionID, id.PolicyDecision},
		{"settings_snapshot_id", e.SettingsSnapshotID, id.SettingsSnapshot},
	} {
		if !check.value.IsZero() && !check.value.HasPrefix(check.prefix) {
			return invalidField(check.field)
		}
	}

	// A reference without a hash is unverifiable, and a hash without a reference is unresolvable.
	// Both directions are rejected so that evidence integrity cannot degrade quietly.
	switch {
	case e.PayloadRef.IsZero() && e.PayloadHash != "":
		return modberr.New(modberr.CodeInvalidArgument, "payload_hash requires payload_ref").
			WithDetail("field", "payload_hash")
	case !e.PayloadRef.IsZero() && e.PayloadHash == "":
		return modberr.New(modberr.CodeInvalidArgument, "payload_ref requires payload_hash").
			WithDetail("field", "payload_ref")
	case e.PayloadHash != "" && !payloadHashPattern.MatchString(e.PayloadHash):
		return modberr.New(modberr.CodeInvalidArgument, "payload_hash must be sha256:<64 hex characters>").
			WithDetail("field", "payload_hash").
			WithDetail("constraint", "sha256_hex")
	}
	return nil
}

func invalidField(field string) error {
	return modberr.Newf(modberr.CodeInvalidArgument, "envelope field %q is missing or malformed", field).
		WithDetail("field", field)
}

// Spec returns the catalog entry for this envelope's type.
func (e Envelope) Spec() (Spec, bool) { return Lookup(e.EventType) }

// RequiresAudit reports whether this event must also reach the audit log.
func (e Envelope) RequiresAudit() bool {
	s, ok := specs[e.EventType]
	return ok && s.Audit
}

// MarshalJSON emits RFC 3339 timestamps in UTC (R-ID-03).
func (e Envelope) MarshalJSON() ([]byte, error) {
	type alias Envelope
	return json.Marshal(struct {
		alias
		Timestamp string `json:"timestamp"`
	}{
		alias:     alias(e),
		Timestamp: e.Timestamp.UTC().Format(time.RFC3339Nano),
	})
}

// UnmarshalJSON parses the wire form and normalizes the timestamp to UTC. It does not validate;
// call Validate explicitly so the caller decides how a malformed event is handled.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	type alias Envelope
	var raw struct {
		alias
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return modberr.Wrap(err, modberr.CodeInvalidArgument, "decode event envelope")
	}
	*e = Envelope(raw.alias)
	if raw.Timestamp != "" {
		ts, err := time.Parse(time.RFC3339Nano, raw.Timestamp)
		if err != nil {
			return modberr.Wrap(err, modberr.CodeInvalidArgument, "decode event timestamp").
				WithDetail("field", "timestamp")
		}
		e.Timestamp = ts.UTC()
	}
	return nil
}
