package worker_test

import (
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/worker"
)

// WRK invariants (D1–D9). One test each; a test without a D-number, or a D-number without a test,
// is a gap.
//
//	D1 WRK-1: both directions of the handshake are required, and refused distinctly.
//	D2 WRK-3/INV-10: the server's ownership record wins over the worker's claim.
//	D3 WRK-2: a worker advertises capabilities and never assigns itself a policy label.
//	D4 WRK-4: a stale worker is ineligible, and the zero heartbeat is stale rather than current.
//	D5 WRK-5: draining is distinct from unhealthy and takes the worker out of scheduling.
//	D6 WRK-6: every eligibility condition must hold, and the zero Eligibility schedules nothing.
//	D7 WRK-7: the version floor is enforced at registration and at scheduling.
//	D8 WRK-8: attestation is required only when the deployment says so, and then absolutely.
//	D9 An unrecognised health report is refused rather than silently taking the worker out.

var now = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

func registration() worker.Registration {
	return worker.Registration{
		WorkerID: "w-1", OrganizationID: "org-a",
		Capabilities: []string{"docker", "linux/amd64"}, Version: 7,
	}
}

func mutual() worker.AuthOutcome {
	return worker.AuthOutcome{ServerVerifiedWorker: true, WorkerVerifiedServer: true}
}

func policy() worker.Policy {
	return worker.Policy{MinVersion: 5, HeartbeatTimeout: 90 * time.Second}
}

func registered(t *testing.T) worker.Worker {
	t.Helper()
	w, err := worker.Register(registration(), mutual(), "org-a", policy(), now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return w
}

func demand() worker.Demand {
	return worker.Demand{OrganizationID: "org-a", Capabilities: []string{"docker"}}
}

// D1. WRK-1: mutual means both directions.
//
// A single boolean would let a one-sided handshake register: the worker verified the server and
// nobody verified the worker. And the other direction matters too — a worker that did not
// authenticate the server may be talking to something else entirely, and registering it means that
// something else now has a worker.
func TestSecurityBothDirectionsOfTheHandshakeAreRequired(t *testing.T) {
	for name, auth := range map[string]worker.AuthOutcome{
		"neither":               {},
		"server did not verify": {WorkerVerifiedServer: true},
		"worker did not verify": {ServerVerifiedWorker: true},
	} {
		if auth.Mutual() {
			t.Errorf("%s: reported as mutual", name)
		}
		if _, err := worker.Register(registration(), auth, "org-a", policy(), now); err == nil {
			t.Errorf("%s: a one-sided handshake registered a worker", name)
		}
	}
	if !mutual().Mutual() {
		t.Fatal("a two-sided handshake did not report itself mutual")
	}

	// The two failures are distinguishable, because they mean different things to whoever reads
	// the log.
	_, serverSide := worker.Register(registration(),
		worker.AuthOutcome{WorkerVerifiedServer: true}, "org-a", policy(), now)
	_, workerSide := worker.Register(registration(),
		worker.AuthOutcome{ServerVerifiedWorker: true}, "org-a", policy(), now)
	if serverSide.Error() == workerSide.Error() {
		t.Fatal("the two one-sided failures are reported identically")
	}
}

// D2. WRK-3 and INV-10: the record wins over the claim.
//
// Asking the worker which organization it belongs to and believing the answer is how a worker ends
// up running another organization's jobs.
func TestSecurityTheServersOwnershipRecordBeatsTheWorkersClaim(t *testing.T) {
	lying := registration()
	lying.OrganizationID = "org-b"
	if _, err := worker.Register(lying, mutual(), "org-a", policy(), now); err == nil {
		t.Fatal("a worker registered into an organization it does not belong to")
	}

	// A worker with no ownership record at all is refused rather than defaulted.
	if _, err := worker.Register(registration(), mutual(), " ", policy(), now); err == nil {
		t.Fatal("a worker with no organization on record registered")
	}
	// The case the mismatch check cannot catch: an empty claim and an empty record compare equal,
	// so without its own check a worker belonging to no organization registers into the pool.
	orphan := registration()
	orphan.OrganizationID = ""
	if _, err := worker.Register(orphan, mutual(), "", policy(), now); err == nil {
		t.Fatal("a worker belonging to no organization registered")
	}

	// The registered worker carries the record's organization, not the claim's.
	//
	// A mutant that assigns the *claim* to the record survives this and is provably equivalent: the
	// mismatch check above guarantees the two strings are equal by the time the record is built.
	// The assignment is written from the record anyway, because that equality is a property of the
	// current control flow rather than of the field.
	w := registered(t)
	if w.OrganizationID != "org-a" {
		t.Fatalf("organization = %q, want the server's record", w.OrganizationID)
	}

	// And scheduling refuses across the boundary.
	other := demand()
	other.OrganizationID = "org-b"
	if got := worker.Eligible(w, other, policy(), now); got.Eligible {
		t.Fatal("a worker took another organization's work")
	}
	// Work naming no organization is not work anybody may take.
	unscoped := demand()
	unscoped.OrganizationID = ""
	if got := worker.Eligible(w, unscoped, policy(), now); got.Eligible {
		t.Fatal("a worker took work belonging to no organization")
	}
}

// D3. WRK-2: a worker advertises capabilities and does not assign itself labels.
//
// A capability is a claim about what the machine can do and the worker is the only thing that
// knows. A policy label is a claim about what it may be trusted with, and the worker is the last
// thing that should be asked. In one bag, a compromised worker advertises the label that gates the
// work it wants.
func TestSecurityAWorkerCannotLabelItselfIntoEligibility(t *testing.T) {
	// A registration cannot carry labels at all — the type has no field for it — and what it does
	// carry does not become one.
	sneaky := registration()
	sneaky.Capabilities = []string{"docker", "pci-approved", "production-secrets"}
	w, err := worker.Register(sneaky, mutual(), "org-a", policy(), now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(w.Labels) != 0 {
		t.Fatalf("labels = %v; a registration must not set any", w.Labels)
	}

	gated := demand()
	gated.Labels = []string{"pci-approved"}
	if got := worker.Eligible(w, gated, policy(), now); got.Eligible {
		t.Fatal("a worker advertised its way past a policy label")
	}

	// The same label, assigned by the server, does satisfy it — so the gate works and it is the
	// source that matters.
	w.Labels = []string{"pci-approved"}
	if got := worker.Eligible(w, gated, policy(), now); !got.Eligible {
		t.Fatalf("a server-assigned label did not satisfy the demand: %s", got.Reason)
	}

	// Capabilities still work as capabilities.
	needsGPU := demand()
	needsGPU.Capabilities = []string{"gpu"}
	if got := worker.Eligible(w, needsGPU, policy(), now); got.Eligible {
		t.Fatal("a worker took work needing a capability it never advertised")
	}
}

// D4. WRK-4: a worker that has stopped reporting is not available.
//
// The zero LastHeartbeat is stale rather than current: a record with no heartbeat never reported,
// and reading the zero time as now would make an unfilled field look like a live worker.
func TestSecurityAStaleWorkerIsIneligibleAndTheZeroHeartbeatIsStale(t *testing.T) {
	w := registered(t)
	if w.Stale(policy(), now) {
		t.Fatal("a worker that just registered is stale")
	}
	if !w.Stale(policy(), now.Add(91*time.Second)) {
		t.Fatal("a worker unheard from past the timeout is not stale")
	}
	// The boundary itself is not stale; one tick past it is.
	if w.Stale(policy(), now.Add(90*time.Second)) {
		t.Fatal("a worker exactly at the timeout is stale")
	}

	var never worker.Worker
	never.ID, never.OrganizationID, never.Health = "w-2", "org-a", worker.HealthHealthy
	if !never.Stale(policy(), now) {
		t.Fatal("a worker with no heartbeat at all reported itself fresh")
	}
	// Against a real clock, subtracting the zero time gives an enormous age and a worker that never
	// reported comes out stale by arithmetic alone. The explicit check earns its place at the one
	// point where the arithmetic agrees: a zero clock. Without it, "nobody has reported and nobody
	// has looked at the time" reads as a live worker.
	if !never.Stale(policy(), time.Time{}) {
		t.Fatal("a worker with no heartbeat, measured against a zero clock, reported itself fresh")
	}

	if got := worker.Eligible(w, demand(), policy(), now.Add(2*time.Minute)); got.Eligible {
		t.Fatal("a stale worker was scheduled")
	}

	// A policy stating no timeout gets the default rather than an infinite one.
	unstated := worker.Policy{MinVersion: 5}
	if !w.Stale(unstated, now.Add(worker.DefaultHeartbeatTimeout+time.Second)) {
		t.Fatal("a policy with no stated timeout never considers a worker stale")
	}
	if w.Stale(unstated, now) {
		t.Fatal("a policy with no stated timeout considers every worker stale")
	}
}

// D5. WRK-5: draining is a planned state, not a health problem.
//
// Folding it into health loses the difference between "we are upgrading this" and "this has
// stopped answering" — the same to a scheduler, completely different to an operator at 3am.
func TestSecurityDrainingIsDistinctFromUnhealthy(t *testing.T) {
	w := registered(t).Drain()
	if !w.Draining {
		t.Fatal("Drain did not mark the worker")
	}
	if w.Health != worker.HealthHealthy {
		t.Fatalf("draining changed health to %q; a planned upgrade is not an outage", w.Health)
	}

	got := worker.Eligible(w, demand(), policy(), now)
	if got.Eligible {
		t.Fatal("a draining worker was given new work")
	}
	if !strings.Contains(got.Reason, "draining") {
		t.Fatalf("reason = %q; it must say the worker is draining", got.Reason)
	}

	// Drain is idempotent, because it arrives from an operator, an upgrade job and a health system.
	if !w.Drain().Draining {
		t.Fatal("draining twice un-drained the worker")
	}

	// An unhealthy worker refuses for its own reason, so the two are distinguishable in the log.
	sick, err := registered(t).Heartbeat(worker.HealthUnhealthy, now)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	sickReason := worker.Eligible(sick, demand(), policy(), now).Reason
	if sickReason == got.Reason {
		t.Fatal("a draining worker and an unhealthy one refuse identically")
	}
}

// D6. WRK-6: every condition must hold, and the zero decision schedules nothing.
func TestSecurityEveryEligibilityConditionMustHold(t *testing.T) {
	var zero worker.Eligibility
	if zero.Eligible {
		t.Fatal("the zero Eligibility schedules work")
	}

	base := registered(t)
	base.Labels = []string{"general"}
	d := demand()
	d.Labels = []string{"general"}
	if got := worker.Eligible(base, d, policy(), now); !got.Eligible {
		t.Fatalf("a fully qualified worker was refused: %s", got.Reason)
	}

	// Each condition broken on its own, so no one check can be standing in for the others.
	for name, mutate := range map[string]func(*worker.Worker){
		"empty record":   func(w *worker.Worker) { w.ID = "" },
		"wrong org":      func(w *worker.Worker) { w.OrganizationID = "org-b" },
		"old version":    func(w *worker.Worker) { w.Version = 1 },
		"draining":       func(w *worker.Worker) { w.Draining = true },
		"degraded":       func(w *worker.Worker) { w.Health = worker.HealthDegraded },
		"unknown health": func(w *worker.Worker) { w.Health = worker.HealthUnknown },
		"stale":          func(w *worker.Worker) { w.LastHeartbeat = now.Add(-time.Hour) },
		"no capability":  func(w *worker.Worker) { w.Capabilities = nil },
		"no label":       func(w *worker.Worker) { w.Labels = nil },
	} {
		w := base
		mutate(&w)
		got := worker.Eligible(w, d, policy(), now)
		if got.Eligible {
			t.Errorf("%s: an ineligible worker was scheduled", name)
		}
		if got.Reason == "" {
			t.Errorf("%s: a refusal carried no reason", name)
		}
	}
}

// D7. WRK-7: the version floor is enforced in both places.
//
// At registration as well as at scheduling, so an outdated worker does not sit in the pool looking
// available.
func TestSecurityTheVersionFloorIsEnforcedAtRegistrationAndScheduling(t *testing.T) {
	old := registration()
	old.Version = 4
	if _, err := worker.Register(old, mutual(), "org-a", policy(), now); err == nil {
		t.Fatal("a worker below the version floor registered")
	}

	// At the floor exactly is permitted; a version of zero is not a version.
	at := registration()
	at.Version = 5
	if _, err := worker.Register(at, mutual(), "org-a", policy(), now); err != nil {
		t.Fatalf("a worker at the floor was refused: %v", err)
	}
	none := registration()
	none.Version = 0
	if _, err := worker.Register(none, mutual(), "org-a", policy(), now); err == nil {
		t.Fatal("a worker reporting no version registered")
	}
	// And in a deployment that sets no floor, where the floor check cannot stand in for it. WRK-7
	// says versions are recorded and enforceable, and a version nobody recorded cannot be enforced
	// against later when a floor is introduced.
	noFloor := worker.Policy{HeartbeatTimeout: 90 * time.Second}
	if _, err := worker.Register(none, mutual(), "org-a", noFloor, now); err == nil {
		t.Fatal("a worker reporting no version registered where the deployment sets no floor")
	}

	// A floor raised after registration takes effect at scheduling.
	w := registered(t)
	raised := policy()
	raised.MinVersion = 9
	if got := worker.Eligible(w, demand(), raised, now); got.Eligible {
		t.Fatal("a worker below a newly raised floor was scheduled")
	}
}

// D8. WRK-8: attestation is required only when the deployment says so, and then absolutely.
//
// A positive statement rather than an inferred default: a deployment that requires attestation says
// so, and one that does not has said that too.
func TestSecurityAttestationIsRequiredOnlyWhenDeclaredAndThenAbsolutely(t *testing.T) {
	strict := policy()
	strict.RequireAttestation = true

	if _, err := worker.Register(registration(), mutual(), "org-a", strict, now); err == nil {
		t.Fatal("an unattested worker registered in a deployment requiring attestation")
	}

	attested := registration()
	attested.Attestation = "tpm-quote-ref"
	w, err := worker.Register(attested, mutual(), "org-a", strict, now)
	if err != nil {
		t.Fatalf("an attested worker was refused: %v", err)
	}
	if !w.Attested {
		t.Fatal("an attested worker was not recorded as attested")
	}

	// Whitespace is not an attestation.
	blank := registration()
	blank.Attestation = "   "
	if _, err := worker.Register(blank, mutual(), "org-a", strict, now); err == nil {
		t.Fatal("whitespace was accepted as an attestation document")
	}

	// A deployment not requiring it admits an unattested worker, so the flag means something.
	relaxed, err := worker.Register(registration(), mutual(), "org-a", policy(), now)
	if err != nil {
		t.Fatalf("an unattested worker was refused where attestation is not required: %v", err)
	}
	if relaxed.Attested {
		t.Fatal("a worker with no attestation was recorded as attested")
	}
	// And an unattested worker admitted under a relaxed policy is still refused once it tightens.
	if got := worker.Eligible(relaxed, demand(), strict, now); got.Eligible {
		t.Fatal("an unattested worker stayed eligible after the policy tightened")
	}
}

// D9. An unrecognised health report is refused rather than stored.
//
// An unrecognised state compares unequal to healthy and would take the worker out of service
// silently — presenting as a worker that stopped receiving work for no reason anybody can find.
func TestSecurityAnUnrecognisedHealthReportIsRefused(t *testing.T) {
	w := registered(t)

	for _, h := range []worker.Health{"", "ok", "fine", "HEALTHY"} {
		if _, err := w.Heartbeat(h, now); err == nil {
			t.Errorf("the health state %q was accepted", h)
		}
	}
	if _, err := w.Heartbeat(worker.HealthHealthy, time.Time{}); err == nil {
		t.Fatal("a heartbeat with no timestamp was accepted")
	}

	for _, h := range []worker.Health{
		worker.HealthHealthy, worker.HealthDegraded, worker.HealthUnhealthy,
	} {
		got, err := w.Heartbeat(h, now.Add(time.Minute))
		if err != nil {
			t.Errorf("the health state %q was refused: %v", h, err)
			continue
		}
		if got.Health != h {
			t.Errorf("health = %q, want %q", got.Health, h)
		}
		if !got.LastHeartbeat.Equal(now.Add(time.Minute)) {
			t.Errorf("the heartbeat timestamp was not recorded")
		}
	}

	// A refused heartbeat leaves the worker as it was rather than half-updated.
	before := w
	after, err := w.Heartbeat("nonsense", now.Add(time.Hour))
	if err == nil {
		t.Fatal("an unrecognised state was accepted")
	}
	if after.Health != before.Health || !after.LastHeartbeat.Equal(before.LastHeartbeat) {
		t.Fatal("a refused heartbeat still modified the worker")
	}
}
