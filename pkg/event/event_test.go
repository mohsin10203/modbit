package event_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

var fixedTime = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

func newBuilder(t *testing.T, orgID id.ID) *event.Builder {
	t.Helper()
	b, err := event.NewBuilder(orgID, fixedClock{fixedTime}, nil)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b
}

func runAttrs() event.Attributes {
	return event.Attributes{
		SpaceID:  id.MustNew(id.Space),
		RunID:    id.MustNew(id.Run),
		Sequence: 1,
	}
}

var agentActor = event.Actor{Type: event.ActorAgent, ID: "prof_reviewer"}

func TestNewProducesACompleteEnvelope(t *testing.T) {
	t.Parallel()
	org := id.MustNew(id.Organization)
	e, err := newBuilder(t, org).New(event.TypeRunStepCompleted, agentActor, runAttrs())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !e.EventID.HasPrefix(id.TraceEvent) {
		t.Errorf("event id = %q, want an evt_ identifier", e.EventID)
	}
	if e.OrganizationID != org {
		t.Errorf("organization = %q, want %q", e.OrganizationID, org)
	}
	if e.EventVersion != 1 {
		t.Errorf("version = %d, want 1", e.EventVersion)
	}
	if !e.Timestamp.Equal(fixedTime) {
		t.Errorf("timestamp = %v, want %v", e.Timestamp, fixedTime)
	}
}

func TestUnknownEventTypeIsRejected(t *testing.T) {
	t.Parallel()
	_, err := newBuilder(t, id.MustNew(id.Organization)).New("run.invented.event", agentActor, runAttrs())
	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want MODBIT_INVALID_ARGUMENT", err)
	}
}

// R-TEN-01: a tenant-scoped event without organization_id cannot be authorized, filtered, or
// retained per tenant, so it must never enter the log.
func TestTenantScopedEventRequiresAnOrganization(t *testing.T) {
	t.Parallel()
	b, err := event.NewBuilder("", fixedClock{fixedTime}, nil)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	if _, err := b.New(event.TypeRunStepCompleted, agentActor, runAttrs()); err == nil {
		t.Fatal("expected an error for a run-scoped event with no organization")
	}
	// Worker-scoped events are tenant owned too: a worker belongs to an organization.
	if _, err := b.New(event.TypeWorkerHeartbeat, event.Actor{Type: event.ActorWorker, ID: "wrk_1"},
		event.Attributes{}); err == nil {
		t.Fatal("expected an error for a worker-scoped event with no organization")
	}
}

func TestScopeDrivenRequiredIdentifiers(t *testing.T) {
	t.Parallel()
	org := id.MustNew(id.Organization)
	b := newBuilder(t, org)

	tests := []struct {
		name    string
		typ     event.Type
		attrs   event.Attributes
		wantErr bool
	}{
		{"run scope complete", event.TypeRunCompleted, runAttrs(), false},
		{"run scope without space", event.TypeRunCompleted, event.Attributes{RunID: id.MustNew(id.Run), Sequence: 1}, true},
		{"run scope without run", event.TypeRunCompleted, event.Attributes{SpaceID: id.MustNew(id.Space), Sequence: 1}, true},
		{"run scope without sequence", event.TypeRunCompleted, event.Attributes{SpaceID: id.MustNew(id.Space), RunID: id.MustNew(id.Run)}, true},
		{"space scope complete", event.TypeContextIndexCompleted, event.Attributes{SpaceID: id.MustNew(id.Space)}, false},
		{"space scope without space", event.TypeContextIndexCompleted, event.Attributes{}, true},
		{"organization scope", event.TypeSettingsChanged, event.Attributes{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			actor := event.Actor{Type: event.ActorSystem, ID: "svc_orchestrator"}
			_, err := b.New(tc.typ, actor, tc.attrs)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %t", err, tc.wantErr)
			}
		})
	}
}

func TestActorIsValidated(t *testing.T) {
	t.Parallel()
	b := newBuilder(t, id.MustNew(id.Organization))

	if _, err := b.New(event.TypeRunCompleted, event.Actor{Type: "impostor", ID: "x"}, runAttrs()); err == nil {
		t.Error("expected an error for an unknown actor type")
	}
	if _, err := b.New(event.TypeRunCompleted, event.Actor{Type: event.ActorUser, ID: "  "}, runAttrs()); err == nil {
		t.Error("expected an error for a blank actor id")
	}
}

// Optional identifiers must still carry the right prefix, so a settings snapshot id cannot appear
// where a policy decision id belongs.
func TestOptionalIdentifiersArePrefixChecked(t *testing.T) {
	t.Parallel()
	b := newBuilder(t, id.MustNew(id.Organization))

	attrs := runAttrs()
	attrs.PolicyDecisionID = id.MustNew(id.SettingsSnapshot) // wrong entity
	if _, err := b.New(event.TypeToolAuthorized, agentActor, attrs); err == nil {
		t.Error("expected an error when policy_decision_id carries the wrong prefix")
	}

	good := runAttrs()
	good.PolicyDecisionID = id.MustNew(id.PolicyDecision)
	good.SettingsSnapshotID = id.MustNew(id.SettingsSnapshot)
	good.CorrelationID = id.MustNew(id.Correlation)
	good.CausationID = id.MustNew(id.TraceEvent)
	if _, err := b.New(event.TypeToolAuthorized, agentActor, good); err != nil {
		t.Errorf("well-formed optional identifiers were rejected: %v", err)
	}
}

// R-EVT-03: a reference without a hash is unverifiable and a hash without a reference is
// unresolvable. Both directions must fail rather than degrade evidence integrity quietly.
func TestPayloadReferenceAndHashMustAgree(t *testing.T) {
	t.Parallel()
	b := newBuilder(t, id.MustNew(id.Organization))
	validHash := "sha256:" + strings.Repeat("a", 64)

	refOnly := runAttrs()
	refOnly.PayloadRef = id.MustNew(id.ObjectRef)
	if _, err := b.New(event.TypeRunStepCompleted, agentActor, refOnly); err == nil {
		t.Error("expected an error for a payload reference with no hash")
	}

	hashOnly := runAttrs()
	hashOnly.PayloadHash = validHash
	if _, err := b.New(event.TypeRunStepCompleted, agentActor, hashOnly); err == nil {
		t.Error("expected an error for a payload hash with no reference")
	}

	badHash := runAttrs()
	badHash.PayloadRef = id.MustNew(id.ObjectRef)
	badHash.PayloadHash = "md5:deadbeef"
	if _, err := b.New(event.TypeRunStepCompleted, agentActor, badHash); err == nil {
		t.Error("expected an error for a non-sha256 payload hash")
	}

	good := runAttrs()
	good.PayloadRef = id.MustNew(id.ObjectRef)
	good.PayloadHash = validHash
	if _, err := b.New(event.TypeRunStepCompleted, agentActor, good); err != nil {
		t.Errorf("a matched reference and hash were rejected: %v", err)
	}
}

func TestJSONRoundTripPreservesTheEnvelope(t *testing.T) {
	t.Parallel()
	attrs := runAttrs()
	attrs.CorrelationID = id.MustNew(id.Correlation)
	attrs.PolicyDecisionID = id.MustNew(id.PolicyDecision)

	original, err := newBuilder(t, id.MustNew(id.Organization)).New(event.TypeToolAuthorized, agentActor, attrs)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"timestamp":"2026-07-26T12:00:00Z"`) {
		t.Errorf("timestamp is not RFC 3339 UTC: %s", encoded)
	}

	var restored event.Envelope
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatalf("round-tripped envelope failed validation: %v", err)
	}
	if restored.EventID != original.EventID || restored.Sequence != original.Sequence {
		t.Errorf("round trip lost fields: %+v", restored)
	}
	if !restored.Timestamp.Equal(original.Timestamp) {
		t.Errorf("timestamp = %v, want %v", restored.Timestamp, original.Timestamp)
	}
}

func TestAuditFlagMatchesTheCatalog(t *testing.T) {
	t.Parallel()
	b := newBuilder(t, id.MustNew(id.Organization))

	authorized, err := b.New(event.TypeToolAuthorized, agentActor, runAttrs())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !authorized.RequiresAudit() {
		t.Error("tool.authorized must reach the audit log")
	}

	progress, err := b.New(event.TypeRunStepProgress, agentActor, runAttrs())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if progress.RequiresAudit() {
		t.Error("run.step.progress should not be an audit event")
	}
	if len(event.AuditTypes()) == 0 {
		t.Error("the catalog defines no audit events")
	}
}

func TestCatalogIsPopulated(t *testing.T) {
	t.Parallel()
	types := event.Types()
	if len(types) < 100 {
		t.Errorf("catalog has %d event types, want the full v5.1 catalog", len(types))
	}
	for _, required := range []event.Type{
		event.TypeRunCompleted,
		event.TypeApprovalRequested,
		event.TypeTaintEscalationApplied,
		event.TypeVerificationAdequacyBlocked,
		event.TypeEvidenceExportCompleted,
	} {
		if _, ok := event.Lookup(required); !ok {
			t.Errorf("catalog is missing %q", required)
		}
	}
}

// R-EVT-01: per-run sequence is strictly monotonic, and runs do not share a counter.
func TestSequencerIsMonotonicPerRun(t *testing.T) {
	t.Parallel()
	s := event.NewMemorySequencer()
	ctx := context.Background()
	runA, runB := id.MustNew(id.Run), id.MustNew(id.Run)

	for want := uint64(1); want <= 3; want++ {
		got, err := s.Next(ctx, runA)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if got != want {
			t.Fatalf("sequence = %d, want %d", got, want)
		}
	}
	first, err := s.Next(ctx, runB)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if first != 1 {
		t.Errorf("a second run started at %d, want 1", first)
	}
	current, err := s.Current(ctx, runA)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if current != 3 {
		t.Errorf("Current = %d, want 3", current)
	}
}

func TestSequencerIsSafeUnderConcurrentAllocation(t *testing.T) {
	t.Parallel()
	s := event.NewMemorySequencer()
	run := id.MustNew(id.Run)
	const goroutines, perGoroutine = 8, 200

	var mu sync.Mutex
	seen := make(map[uint64]struct{}, goroutines*perGoroutine)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				n, err := s.Next(context.Background(), run)
				if err != nil {
					t.Errorf("Next: %v", err)
					return
				}
				mu.Lock()
				seen[n] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != goroutines*perGoroutine {
		t.Fatalf("allocated %d distinct sequences, want %d", len(seen), goroutines*perGoroutine)
	}
}

func TestSequencerResumeRefusesToGoBackwards(t *testing.T) {
	t.Parallel()
	s := event.NewMemorySequencer()
	run := id.MustNew(id.Run)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := s.Next(ctx, run); err != nil {
			t.Fatalf("Next: %v", err)
		}
	}
	if err := s.Resume(run, 2); !modberr.Is(err, modberr.CodeSequenceConflict) {
		t.Fatalf("error = %v, want MODBIT_SEQUENCE_CONFLICT", err)
	}
	if err := s.Resume(run, 42); err != nil {
		t.Fatalf("Resume forward: %v", err)
	}
	next, err := s.Next(ctx, run)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if next != 43 {
		t.Errorf("sequence after resume = %d, want 43", next)
	}
}

func TestSequencerHonoursContextCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := event.NewMemorySequencer().Next(ctx, id.MustNew(id.Run)); !modberr.Is(err, modberr.CodeCancelled) {
		t.Fatalf("error = %v, want MODBIT_CANCELLED", err)
	}
}

// Validation must report the same field every time. With map iteration, an envelope carrying two
// malformed identifiers reported a different field on each run, making the failure irreproducible.
func TestValidationFieldOrderIsDeterministic(t *testing.T) {
	t.Parallel()
	e, err := newBuilder(t, id.MustNew(id.Organization)).New(event.TypeToolAuthorized, agentActor, runAttrs())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Three identifiers with the wrong entity prefix at once.
	e.CorrelationID = id.MustNew(id.Run)
	e.PayloadRef = id.MustNew(id.Run)
	e.PolicyDecisionID = id.MustNew(id.Run)

	first := e.Validate()
	if first == nil {
		t.Fatal("expected a validation error")
	}
	for i := 0; i < 50; i++ {
		if got := e.Validate(); got.Error() != first.Error() {
			t.Fatalf("validation is nondeterministic: %q then %q", first, got)
		}
	}
	if !strings.Contains(first.Error(), "correlation_id") {
		t.Errorf("error = %q, want the first declared field (correlation_id)", first)
	}
}
