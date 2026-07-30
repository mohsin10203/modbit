// Package integration admits connected integrations and their inbound events (INT-1..INT-9).
//
// Boundary: it decides whether an integration may be advertised at a given tier, whether an inbound
// event may be processed, and whether an external mutation may be recorded. It verifies no
// signature itself, holds no credential, and calls no external API — a caller supplies a
// verification result and this decides what it means.
//
// Requirements: PRD §12.5 INT-1 (service identities, least-privilege scopes), INT-3 (external
// mutations are attributable), INT-4 (event delivery is idempotent), INT-6 (external content is
// untrusted), INT-7 (integration tiers), INT-8 (no native claim without native support), INT-9
// (native qualification coverage).
//
// # Native is earned, not declared
//
// INT-8 is unusual among the requirements: it forbids a *claim* rather than a behaviour. The reason
// it needs enforcing in code is that the claim and the evidence live in different places — a tier
// is a line in a config file and the qualification is a test run — and nothing stops the line being
// written first. So the tier is validated against INT-9's seven areas, and a Native claim without
// all seven is refused rather than quietly downgraded. A downgrade would render the integration
// correctly in the UI and leave the false claim in the config for the next reader.
//
// # Idempotency cannot be manufactured
//
// INT-4 requires idempotent event delivery, and the obvious way to provide it for a provider that
// sends no delivery identifier is to hash the payload. That is worse than not having it: two
// genuinely distinct events with identical payloads — the same comment posted twice, the same label
// applied and removed and applied — collapse into one, and the second is dropped silently. Dropping
// a real event is a worse failure than processing a duplicate, and it is invisible.
//
// So a provider that supplies no delivery identifier cannot claim idempotency, and therefore cannot
// be Native. The unsupported case is permitted and must be declared.
//
// # Why signatures are checked before the ledger
//
// An unverified event is refused before its delivery identifier is recorded. Recording first would
// let anyone who can reach the endpoint burn an identifier: send a forgery carrying the delivery id
// the provider is about to use, and the real event arrives afterwards and is dropped as a duplicate.
// The forgery does not need to be processed to do damage — it only needs to be remembered.
package integration

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Tier is INT-7's classification of an integration.
type Tier string

const (
	// TierUnclassified is the zero value and is never admissible. An integration nobody classified
	// would otherwise be presented with whatever the surface defaults to, which is the strongest
	// tier in every UI that lists them best-first.
	TierUnclassified Tier = ""
	// TierNative is the strongest claim and the one INT-8 protects.
	TierNative Tier = "native"
	// TierVerifiedMCP is an MCP integration Modbit has verified.
	TierVerifiedMCP Tier = "modbit_verified_mcp"
	// TierGenericMCP is generic MCP or webhook support.
	TierGenericMCP Tier = "generic_mcp_webhook"
	// TierCommunityPlugin is community-contributed.
	TierCommunityPlugin Tier = "community_plugin"
)

// Valid reports whether t is a declared tier.
func (t Tier) Valid() bool {
	switch t {
	case TierNative, TierVerifiedMCP, TierGenericMCP, TierCommunityPlugin:
		return true
	}
	return false
}

// NativeQualificationAreas are the seven areas INT-9 requires a native integration to have
// qualified. All seven, because the list is what "native" means — an integration qualified on
// authentication and pagination but not on permissions is a security claim nobody made.
var NativeQualificationAreas = []string{
	"authentication", "event_delivery", "rate_limits", "permissions",
	"pagination", "retries", "external_effect_idempotency",
}

// IdentityKind is how an integration authenticates (INT-1).
type IdentityKind string

const (
	// IdentityUnspecified is the zero value and is never admissible.
	IdentityUnspecified IdentityKind = ""
	// IdentityService is a service identity, which is what INT-1 requires.
	IdentityService IdentityKind = "service"
	// IdentityUser is a human's credentials, which INT-1 forbids: the integration outlives the
	// person's employment and carries whatever they could do rather than what it needs.
	IdentityUser IdentityKind = "user"
)

// Integration is a connected integration's configuration and qualification evidence.
type Integration struct {
	ID          string       `json:"id"`
	ClaimedTier Tier         `json:"claimed_tier"`
	Identity    IdentityKind `json:"identity"`
	// Scopes are the permissions the integration holds (INT-1).
	Scopes []string `json:"scopes"`
	// Qualified names the INT-9 areas with passing evidence. It is evidence, not intent: an area
	// listed here is one a qualification run covered.
	Qualified []string `json:"qualified,omitempty"`
	// SuppliesDeliveryID reports whether the provider sends a per-delivery identifier. A provider
	// that does not cannot be made idempotent — see the package comment.
	SuppliesDeliveryID bool `json:"supplies_delivery_id"`
}

// Validate enforces INT-1, INT-7, INT-8 and INT-9.
func (i Integration) Validate() error {
	switch {
	case strings.TrimSpace(i.ID) == "":
		return field("an integration has no id", "id")
	case !i.ClaimedTier.Valid():
		return field(fmt.Sprintf(
			"integration %s declares no tier; an unclassified integration is presented at whatever the "+
				"surface defaults to", i.ID), "claimed_tier")
	case i.Identity == IdentityUnspecified:
		return field(fmt.Sprintf("integration %s declares no identity kind", i.ID), "identity")
	case i.Identity != IdentityService:
		// INT-1. A user credential outlives the person's employment and carries everything they
		// could do rather than what the integration needs.
		return field(fmt.Sprintf(
			"integration %s authenticates as a %s identity; INT-1 requires a service identity",
			i.ID, i.Identity), "identity")
	case len(i.Scopes) == 0:
		return field(fmt.Sprintf(
			"integration %s holds no scopes; least privilege is a stated set, not an absent one", i.ID),
			"scopes")
	}
	for _, s := range i.Scopes {
		if unbounded(s) {
			// This catches the unbounded case, which is the one that recurs. It does not prove the
			// scope set is minimal — nothing here can — so the check is narrow and says so.
			return field(fmt.Sprintf(
				"integration %s holds the unbounded scope %q; INT-1 requires least privilege", i.ID, s),
				"scopes")
		}
	}

	for _, area := range i.Qualified {
		if !knownArea(area) {
			return field(fmt.Sprintf(
				"integration %s claims qualification in unrecognised area %q", i.ID, area), "qualified")
		}
	}
	// INT-4's precondition, checked before the tier so the refusal names the cause rather than the
	// symptom: an integration whose provider sends no delivery identifier cannot have qualified in
	// idempotency, whatever a qualification run recorded.
	if i.claims("external_effect_idempotency") && !i.SuppliesDeliveryID {
		return field(fmt.Sprintf(
			"integration %s claims idempotency qualification but its provider supplies no delivery "+
				"identifier; hashing the payload would collapse genuinely distinct identical events",
			i.ID), "qualified")
	}

	if i.ClaimedTier == TierNative {
		var missing []string
		for _, area := range NativeQualificationAreas {
			if !i.claims(area) {
				missing = append(missing, area)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			// INT-8. Refused rather than downgraded: a downgrade renders correctly in the UI and
			// leaves the false claim in the config for the next reader.
			return field(fmt.Sprintf(
				"integration %s claims native support without qualifying in: %s",
				i.ID, strings.Join(missing, ", ")), "claimed_tier")
		}
	}
	return nil
}

func (i Integration) claims(area string) bool {
	for _, a := range i.Qualified {
		if a == area {
			return true
		}
	}
	return false
}

func knownArea(area string) bool {
	for _, a := range NativeQualificationAreas {
		if a == area {
			return true
		}
	}
	return false
}

// unbounded reports whether a scope grants more than it names.
func unbounded(scope string) bool {
	s := strings.TrimSpace(scope)
	return s == "" || s == "*" || strings.HasSuffix(s, ":*") || strings.HasSuffix(s, "/*")
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

func denied(msg, constraint string) error {
	return modberr.New(modberr.CodePolicyDenied, msg).WithDetail("constraint", constraint)
}

// Signature is the caller's verification result for an inbound delivery. This package verifies
// nothing itself; it decides what a result means.
type Signature struct {
	// Present reports that the delivery carried a signature.
	Present bool `json:"present"`
	// Verified reports that the caller checked it and it held.
	Verified bool `json:"verified"`
}

// Event is an inbound delivery from an integration.
type Event struct {
	IntegrationID string `json:"integration_id"`
	// DeliveryID is the provider's per-delivery identifier, and the only sound idempotency key.
	DeliveryID string `json:"delivery_id"`
	Kind       string `json:"kind"`
	// Payload is the provider's content. It is untrusted (INT-6) and nothing in it changes that.
	Payload string `json:"payload"`
}

// Class is the provenance class of an event's content (INT-6).
//
// Always taint.Integration, and taken from the delivery rather than the payload: a payload that
// could describe its own trust level would be asked to, and then an attacker who can post a comment
// decides how their comment is treated.
func (Event) Class() taint.Class { return taint.Integration }

// Ledger records which deliveries have been processed (INT-4).
//
// Bounded, because an unbounded one is a memory leak that a busy repository fills. Eviction is
// oldest-first and eviction is visible: a caller that needs to know a key was forgotten can ask.
type Ledger struct {
	capacity int
	seen     map[string]bool
	order    []string
	evicted  int
}

// DefaultLedgerCapacity is how many deliveries a ledger remembers by default.
const DefaultLedgerCapacity = 4096

// NewLedger returns a ledger remembering the most recent capacity deliveries. A capacity of zero or
// less selects DefaultLedgerCapacity, because a zero-capacity ledger remembers nothing and would
// report every delivery as new — idempotency that silently does not apply.
func NewLedger(capacity int) *Ledger {
	if capacity <= 0 {
		capacity = DefaultLedgerCapacity
	}
	return &Ledger{capacity: capacity, seen: map[string]bool{}}
}

// key scopes a delivery identifier to its integration.
//
// Two providers pick their own identifier formats and both will eventually emit "1". A ledger keyed
// on the bare identifier would let one provider's delivery suppress another's, which presents as an
// event that simply never arrived.
func key(integrationID, deliveryID string) string {
	return integrationID + "\x00" + deliveryID
}

// Admit decides whether an event should be processed, and records it if so.
//
// Order matters. The signature is checked before anything is recorded: recording first would let
// anyone who can reach the endpoint send a forgery carrying the delivery identifier the provider is
// about to use, so that the real event arrives afterwards and is dropped as a duplicate. The
// forgery never has to be processed to do that — it only has to be remembered.
func (l *Ledger) Admit(i Integration, ev Event, sig Signature) (bool, error) {
	if err := i.Validate(); err != nil {
		return false, err
	}
	if ev.IntegrationID != i.ID {
		return false, field(fmt.Sprintf(
			"an event for %s was offered to integration %s", ev.IntegrationID, i.ID), "integration_id")
	}

	switch {
	case !sig.Present:
		return false, denied(fmt.Sprintf(
			"a delivery for %s carried no signature", i.ID), "webhook_signature")
	case !sig.Verified:
		// Distinguished from absent, because a present-but-unverified signature is worse: it looks
		// like assurance in a delivery log.
		return false, denied(fmt.Sprintf(
			"the signature on a delivery for %s did not verify", i.ID), "webhook_signature")
	}

	if strings.TrimSpace(ev.DeliveryID) == "" {
		// Refused rather than processed-without-dedup. Processing it is the tempting option and it
		// is how at-least-once quietly becomes at-least-once-and-sometimes-twice for external
		// mutations.
		return false, field(fmt.Sprintf(
			"a delivery for %s carries no delivery identifier, so it cannot be deduplicated", i.ID),
			"delivery_id")
	}

	k := key(i.ID, ev.DeliveryID)
	if l.seen[k] {
		return false, nil
	}
	l.remember(k)
	return true, nil
}

func (l *Ledger) remember(k string) {
	l.seen[k] = true
	l.order = append(l.order, k)
	for len(l.order) > l.capacity {
		oldest := l.order[0]
		l.order = l.order[1:]
		delete(l.seen, oldest)
		l.evicted++
	}
}

// Evicted is how many delivery identifiers the ledger has forgotten.
//
// Exposed because a ledger that has evicted anything is one whose idempotency window has been
// exceeded, and a redelivery of a forgotten event will be processed again. That is a fact an
// operator needs rather than one the ledger should keep to itself.
func (l *Ledger) Evicted() int { return l.evicted }

// Effect is a mutation an integration made outside Modbit (INT-3).
type Effect struct {
	IntegrationID string `json:"integration_id"`
	// Operation names what was done, so a record is readable without the provider's docs.
	Operation string `json:"operation"`
	// ExternalRef is the provider's identifier for the thing changed.
	ExternalRef string `json:"external_ref"`
	// ActorID is who Modbit acted for. INT-3's attributability is about this: a service identity
	// says which integration acted, and only this says on whose behalf.
	ActorID string `json:"actor_id"`
	// RunID ties the effect to the run that caused it.
	RunID string `json:"run_id"`
	// DeliveryID is the inbound delivery that triggered it, where there was one.
	DeliveryID string `json:"delivery_id,omitempty"`
}

// Validate enforces INT-3.
func (e Effect) Validate() error {
	switch {
	case strings.TrimSpace(e.IntegrationID) == "":
		return field("an external effect names no integration", "integration_id")
	case strings.TrimSpace(e.Operation) == "":
		return field("an external effect names no operation", "operation")
	case strings.TrimSpace(e.ExternalRef) == "":
		return field(fmt.Sprintf(
			"a %s effect names nothing it changed", e.Operation), "external_ref")
	case strings.TrimSpace(e.ActorID) == "":
		// The service identity says which integration acted. Without an actor the record says a
		// robot did it, which is true of every entry and distinguishes none of them.
		return field(fmt.Sprintf(
			"a %s effect names no actor; INT-3 requires every external mutation to be attributable",
			e.Operation), "actor_id")
	case strings.TrimSpace(e.RunID) == "":
		return field(fmt.Sprintf("a %s effect names no run", e.Operation), "run_id")
	}
	return nil
}
