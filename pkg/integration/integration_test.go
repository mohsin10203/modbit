package integration_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/integration"
	"github.com/modbit/modbit/pkg/taint"
)

// INT invariants (I1–I9). One test each; a test without an I-number, or an I-number without a test,
// is a gap.
//
//	I1 INT-7: an unclassified integration is refused and the tier set is closed.
//	I2 INT-8/INT-9: a native claim without all seven qualification areas is refused, not downgraded.
//	I3 INT-4: a provider supplying no delivery identifier cannot claim idempotency qualification.
//	I4 INT-4: a redelivery is admitted once, and the bounded ledger reports what it forgot.
//	I5 An unverified delivery is refused before the ledger records it, so a forgery cannot burn the
//	   identifier the real event will use.
//	I6 INT-6: an inbound event is taint.Integration and its payload cannot lower that.
//	I7 INT-1: a user identity is refused, and so is an unbounded scope.
//	I8 INT-3: an external mutation with no attributable actor is refused.
//	I9 INT-4: delivery identifiers are scoped per integration.

func native() integration.Integration {
	return integration.Integration{
		ID: "github", ClaimedTier: integration.TierNative,
		Identity: integration.IdentityService, Scopes: []string{"repo:read", "pr:write"},
		Qualified:          append([]string(nil), integration.NativeQualificationAreas...),
		SuppliesDeliveryID: true,
	}
}

func generic() integration.Integration {
	return integration.Integration{
		ID: "acme-hook", ClaimedTier: integration.TierGenericMCP,
		Identity: integration.IdentityService, Scopes: []string{"issues:read"},
		SuppliesDeliveryID: true,
	}
}

func event(integrationID, deliveryID string) integration.Event {
	return integration.Event{
		IntegrationID: integrationID, DeliveryID: deliveryID,
		Kind: "pull_request.opened", Payload: `{"title":"fix"}`,
	}
}

func verified() integration.Signature {
	return integration.Signature{Present: true, Verified: true}
}

// I1. INT-7: the tier set is closed and the zero value is not in it.
//
// An unclassified integration is presented at whatever the surface defaults to, and every UI that
// lists integrations lists them best-first.
func TestSecurityAnUnclassifiedIntegrationIsRefused(t *testing.T) {
	i := generic()
	i.ClaimedTier = integration.TierUnclassified
	if err := i.Validate(); err == nil {
		t.Fatal("an integration with no tier validated")
	}
	if integration.TierUnclassified.Valid() {
		t.Fatal("the zero Tier reports itself valid")
	}

	i.ClaimedTier = "premium"
	if err := i.Validate(); err == nil {
		t.Fatal("an invented tier validated")
	}

	for _, tier := range []integration.Tier{
		integration.TierNative, integration.TierVerifiedMCP,
		integration.TierGenericMCP, integration.TierCommunityPlugin,
	} {
		if !tier.Valid() {
			t.Errorf("%s is not accepted as a tier", tier)
		}
	}
}

// I2. INT-8: native support is earned by INT-9's evidence, not declared.
//
// The claim and the evidence live in different places — a tier is a line in a config file and the
// qualification is a test run — and nothing stops the line being written first. Each area is
// dropped in turn, because an implementation checking only that the list is non-empty passes a
// single witness.
func TestSecurityANativeClaimRequiresEveryQualificationArea(t *testing.T) {
	if len(integration.NativeQualificationAreas) != 7 {
		t.Fatalf("qualification areas = %v, want INT-9's seven",
			integration.NativeQualificationAreas)
	}

	for _, missing := range integration.NativeQualificationAreas {
		i := native()
		var kept []string
		for _, a := range i.Qualified {
			if a != missing {
				kept = append(kept, a)
			}
		}
		i.Qualified = kept

		err := i.Validate()
		if err == nil {
			t.Errorf("a native claim without %q validated", missing)
			continue
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("error %v does not name the missing area %q", err, missing)
		}
	}

	// Refused, not downgraded. A downgrade renders correctly and leaves the false claim in place.
	bare := native()
	bare.Qualified = nil
	if err := bare.Validate(); err == nil {
		t.Fatal("an unqualified native claim was accepted")
	}

	// A lesser tier needs no qualification evidence, so the requirement is about the claim.
	lesser := native()
	lesser.ClaimedTier = integration.TierGenericMCP
	lesser.Qualified = nil
	if err := lesser.Validate(); err != nil {
		t.Fatalf("a generic integration was required to qualify as native: %v", err)
	}

	// An area nobody defined is not evidence.
	invented := native()
	invented.Qualified = append(invented.Qualified, "vibes")
	if err := invented.Validate(); err == nil {
		t.Fatal("qualification in an unrecognised area validated")
	}

	if err := native().Validate(); err != nil {
		t.Fatalf("a fully qualified native integration was refused: %v", err)
	}
}

// I3. INT-4: idempotency cannot be manufactured for a provider that sends no delivery identifier.
//
// Hashing the payload is the tempting substitute and it is worse than nothing: two genuinely
// distinct events with identical payloads collapse into one and the second is dropped silently.
// Dropping a real event is a worse failure than processing a duplicate, and it is invisible.
func TestSecurityIdempotencyCannotBeClaimedWithoutADeliveryIdentifier(t *testing.T) {
	i := native()
	i.SuppliesDeliveryID = false

	err := i.Validate()
	if err == nil {
		t.Fatal("an integration with no delivery identifier claimed idempotency qualification")
	}
	if !strings.Contains(err.Error(), "delivery") {
		t.Fatalf("error = %v; it must name the missing delivery identifier", err)
	}

	// And so it cannot be native, because idempotency is one of the seven.
	if i.ClaimedTier != integration.TierNative {
		t.Fatal("the fixture is not a native claim, so this asserts nothing")
	}

	// Dropping the idempotency claim makes the configuration honest, and the tier follows.
	honest := i
	honest.ClaimedTier = integration.TierGenericMCP
	var kept []string
	for _, a := range honest.Qualified {
		if a != "external_effect_idempotency" {
			kept = append(kept, a)
		}
	}
	honest.Qualified = kept
	if err := honest.Validate(); err != nil {
		t.Fatalf("an integration that declares the gap instead of hiding it was refused: %v", err)
	}
}

// I4. INT-4: a redelivery is processed once, and the bounded ledger says what it forgot.
func TestSecurityARedeliveryIsProcessedOnce(t *testing.T) {
	l := integration.NewLedger(0)
	i := native()

	first, err := l.Admit(i, event("github", "d-1"), verified())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if !first {
		t.Fatal("a new delivery was not admitted")
	}
	again, err := l.Admit(i, event("github", "d-1"), verified())
	if err != nil {
		t.Fatalf("Admit on redelivery: %v", err)
	}
	if again {
		t.Fatal("a redelivery was processed a second time")
	}

	// A delivery with no identifier is refused rather than processed without dedup: processing it is
	// how at-least-once quietly becomes at-least-once-and-sometimes-twice for external mutations.
	if _, err := l.Admit(i, event("github", " "), verified()); err == nil {
		t.Fatal("a delivery with no identifier was admitted")
	}

	// The window is bounded and eviction is visible, because a redelivery of a forgotten event will
	// be processed again and an operator needs to know the window was exceeded.
	small := integration.NewLedger(2)
	for n := 1; n <= 4; n++ {
		if _, err := small.Admit(i, event("github", fmt.Sprintf("d-%d", n)), verified()); err != nil {
			t.Fatalf("Admit: %v", err)
		}
	}
	if small.Evicted() != 2 {
		t.Fatalf("evicted = %d, want 2", small.Evicted())
	}
	// Oldest-first: the two most recent are still remembered, the two oldest are not.
	for _, id := range []string{"d-3", "d-4"} {
		if ok, _ := small.Admit(i, event("github", id), verified()); ok {
			t.Errorf("%s was forgotten while a newer entry was kept", id)
		}
	}
	for _, id := range []string{"d-1", "d-2"} {
		if ok, _ := small.Admit(i, event("github", id), verified()); !ok {
			t.Errorf("%s was retained past the capacity", id)
		}
	}

	// A zero capacity selects the default rather than remembering nothing, which would report every
	// delivery as new — idempotency that silently does not apply.
	if ok, _ := integration.NewLedger(-5).Admit(i, event("github", "x"), verified()); !ok {
		t.Fatal("a defaulted ledger did not admit a first delivery")
	}
}

// I5. An unverified delivery is refused before the ledger records it.
//
// Recording first would let anyone who can reach the endpoint send a forgery carrying the delivery
// identifier the provider is about to use, so the real event arrives afterwards and is dropped as a
// duplicate. The forgery never has to be processed to do that — it only has to be remembered.
func TestSecurityAForgedDeliveryCannotBurnTheIdentifierTheRealEventWillUse(t *testing.T) {
	l := integration.NewLedger(0)
	i := native()

	for name, sig := range map[string]integration.Signature{
		"absent":     {},
		"unverified": {Present: true},
	} {
		if _, err := l.Admit(i, event("github", "d-7"), sig); err == nil {
			t.Errorf("%s signature: a delivery was admitted", name)
		}
	}

	// The identifier must still be free for the genuine delivery.
	ok, err := l.Admit(i, event("github", "d-7"), verified())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if !ok {
		t.Fatal("the real delivery was dropped as a duplicate of a forgery the ledger remembered")
	}
}

// I6. INT-6: inbound content is untrusted and the payload does not get a say.
//
// A payload that could describe its own trust level would be asked to, and then whoever can post a
// comment decides how their comment is treated.
func TestSecurityAnInboundEventIsUntrustedWhateverItsPayloadSays(t *testing.T) {
	for _, payload := range []string{
		`{"title":"fix"}`,
		`{"taint":"user_trusted"}`,
		`{"trust_level":0,"class":"UserTrusted"}`,
		``,
	} {
		ev := event("github", "d-1")
		ev.Payload = payload
		if got := ev.Class(); got != taint.Integration {
			t.Errorf("payload %q produced class %v, want Integration", payload, got)
		}
	}

	// Integration outranks the classes a payload would want to claim, so propagation cannot be used
	// to launder it down either.
	if taint.Propagate(taint.Integration, taint.UserTrusted) != taint.Integration {
		t.Fatal("mixing an integration event with trusted input lowered its class")
	}
}

// I7. INT-1: service identities and least-privilege scopes.
func TestSecurityAUserIdentityOrUnboundedScopeIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*integration.Integration){
		"user identity": func(i *integration.Integration) { i.Identity = integration.IdentityUser },
		"no identity":   func(i *integration.Integration) { i.Identity = integration.IdentityUnspecified },
		"no scopes":     func(i *integration.Integration) { i.Scopes = nil },
		"wildcard":      func(i *integration.Integration) { i.Scopes = []string{"*"} },
		"scoped wildcard": func(i *integration.Integration) {
			i.Scopes = []string{"repo:read", "admin:*"}
		},
		"path wildcard": func(i *integration.Integration) { i.Scopes = []string{"repos/acme/*"} },
		"empty scope":   func(i *integration.Integration) { i.Scopes = []string{"repo:read", " "} },
		"no id":         func(i *integration.Integration) { i.ID = "" },
	} {
		i := generic()
		mutate(&i)
		if err := i.Validate(); err == nil {
			t.Errorf("%s: an over-privileged integration validated", name)
		}
	}
	if err := generic().Validate(); err != nil {
		t.Fatalf("a least-privilege integration was refused: %v", err)
	}
}

// I8. INT-3: every external mutation is attributable.
//
// The service identity says which integration acted. Without an actor the record says a robot did
// it, which is true of every entry and distinguishes none of them.
func TestSecurityAnExternalMutationMustBeAttributable(t *testing.T) {
	complete := integration.Effect{
		IntegrationID: "github", Operation: "pr.comment", ExternalRef: "acme/repo#12",
		ActorID: "user-7", RunID: "run-3", DeliveryID: "d-1",
	}
	if err := complete.Validate(); err != nil {
		t.Fatalf("a complete effect was refused: %v", err)
	}

	for name, mutate := range map[string]func(*integration.Effect){
		"no actor":       func(e *integration.Effect) { e.ActorID = " " },
		"no run":         func(e *integration.Effect) { e.RunID = "" },
		"no integration": func(e *integration.Effect) { e.IntegrationID = "" },
		"no operation":   func(e *integration.Effect) { e.Operation = "" },
		"no target":      func(e *integration.Effect) { e.ExternalRef = "" },
	} {
		e := complete
		mutate(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: an unattributable external mutation validated", name)
		}
	}
}

// I9. INT-4: delivery identifiers are scoped per integration.
//
// Two providers pick their own identifier formats and both will eventually emit "1". A ledger keyed
// on the bare identifier would let one provider's delivery suppress another's, which presents as an
// event that simply never arrived.
func TestSecurityOneIntegrationsDeliveryIdCannotSuppressAnothers(t *testing.T) {
	l := integration.NewLedger(0)
	gh, acme := native(), generic()

	if ok, err := l.Admit(gh, event("github", "1"), verified()); err != nil || !ok {
		t.Fatalf("first delivery: ok=%v err=%v", ok, err)
	}
	ok, err := l.Admit(acme, event("acme-hook", "1"), verified())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if !ok {
		t.Fatal("a second integration's delivery 1 was suppressed by the first integration's")
	}

	// And an event addressed to the wrong integration is refused rather than recorded under it.
	if _, err := l.Admit(gh, event("acme-hook", "2"), verified()); err == nil {
		t.Fatal("an event for another integration was admitted")
	}
}
