// Package worker admits remote workers and decides scheduler eligibility (WRK-1..WRK-8).
//
// Boundary: it decides whether a worker may register and whether it may be given a particular piece
// of work. It performs no authentication itself, opens no connection, and schedules nothing — a
// caller supplies authentication outcomes and this decides what they permit.
//
// Requirements: PRD §16.3 WRK-1 (mutual authentication), WRK-2 (workers advertise capabilities and
// labels), WRK-3 (the server validates worker identity and organization ownership), WRK-4
// (heartbeats and health state), WRK-5 (draining for upgrades), WRK-6 (policy-based scheduler
// eligibility), WRK-7 (worker software versions recorded and enforceable), WRK-8 (worker
// attestation in enterprise deployments). INV-10 makes a worker running another organization's work
// a release blocker.
//
// # A worker does not label itself
//
// WRK-2 says workers advertise capabilities and labels, and the natural implementation puts both in
// one bag the worker sends at registration. That is the bug. A *capability* is a claim about what
// the machine can do — it has a GPU, it has Docker — and the worker is the only thing that knows.
// A *policy label* is a claim about what the machine is allowed to be trusted with — it is in the
// PCI enclave, it may hold production credentials — and the worker is the last thing that should
// be asked.
//
// Put them in one bag and a compromised worker advertises `pci-approved` and starts receiving the
// work that label gates. So capabilities come from the worker and labels come from the server
// record, and there is no path in this package by which a registration message sets a label.
//
// # Draining is not unhealthy
//
// WRK-5's drain is a planned state: stop giving it new work, let it finish what it has. Folding
// that into health loses the distinction between "we are upgrading this" and "this has stopped
// answering", which are the same to a scheduler and completely different to an operator at 3am.
package worker

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// AuthOutcome is the caller's result from the registration handshake (WRK-1).
//
// Both directions are recorded because WRK-1 says mutual, and a single boolean would let a
// one-sided handshake register: the worker verified the server, nobody verified the worker.
type AuthOutcome struct {
	// ServerVerifiedWorker is true when the server authenticated the worker's certificate.
	ServerVerifiedWorker bool `json:"server_verified_worker"`
	// WorkerVerifiedServer is true when the worker authenticated the server's.
	WorkerVerifiedServer bool `json:"worker_verified_server"`
}

// Mutual reports whether both directions authenticated.
func (a AuthOutcome) Mutual() bool { return a.ServerVerifiedWorker && a.WorkerVerifiedServer }

// Health is WRK-4's reported state.
type Health string

const (
	// HealthUnknown is the zero value and is never eligible. A worker whose health nobody recorded
	// is not a healthy worker, and the zero value is what a partially-constructed record has.
	HealthUnknown   Health = ""
	HealthHealthy   Health = "healthy"
	HealthDegraded  Health = "degraded"
	HealthUnhealthy Health = "unhealthy"
)

// Registration is what a worker sends. Everything in it is the worker's claim.
type Registration struct {
	WorkerID string `json:"worker_id"`
	// OrganizationID is the organization the worker claims to belong to. It is checked against the
	// server's record rather than believed (WRK-3).
	OrganizationID string `json:"organization_id"`
	// Capabilities are what the machine can do — a GPU, a container runtime, a platform. The worker
	// is the only thing that knows these, so they come from here.
	Capabilities []string `json:"capabilities"`
	// Version is the worker software version (WRK-7).
	Version int `json:"version"`
	// Attestation is the attestation document reference, empty when the worker produced none.
	Attestation string `json:"attestation,omitempty"`
}

// Worker is the server's record of a registered worker.
//
// Constructed by Register, so a Worker in hand is one that passed WRK-1 and WRK-3.
type Worker struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organization_id"`
	Capabilities   []string `json:"capabilities"`
	Version        int      `json:"version"`
	// Labels are policy labels the *server* assigned. They never come from a registration message;
	// see the package comment for what happens when they do.
	Labels []string `json:"labels,omitempty"`
	// Attested records that the caller verified an attestation document (WRK-8).
	Attested bool `json:"attested"`
	// Draining marks a worker being taken out of service for an upgrade (WRK-5). Distinct from
	// health, because "we are upgrading this" and "this has stopped answering" are the same to a
	// scheduler and completely different to an operator.
	Draining bool `json:"draining"`
	// Health and LastHeartbeat are WRK-4's state.
	Health        Health    `json:"health"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}

// Policy is the deployment's scheduler policy (WRK-6, WRK-7, WRK-8).
type Policy struct {
	// MinVersion is the enforced worker software floor (WRK-7).
	MinVersion int `json:"min_version"`
	// RequireAttestation is WRK-8. It is a positive statement rather than an inferred default: a
	// deployment that requires attestation says so, and one that does not has said that too.
	RequireAttestation bool `json:"require_attestation"`
	// HeartbeatTimeout is how long a worker may go unheard from before it is stale (WRK-4). Zero
	// selects DefaultHeartbeatTimeout, because a zero timeout makes every worker instantly stale
	// and an infinite one makes a dead worker eligible forever.
	HeartbeatTimeout time.Duration `json:"heartbeat_timeout"`
}

// DefaultHeartbeatTimeout is the staleness bound a policy gets when it states none.
const DefaultHeartbeatTimeout = 90 * time.Second

func (p Policy) heartbeatTimeout() time.Duration {
	if p.HeartbeatTimeout <= 0 {
		return DefaultHeartbeatTimeout
	}
	return p.HeartbeatTimeout
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

func denied(msg, constraint string) error {
	return modberr.New(modberr.CodePolicyDenied, msg).WithDetail("constraint", constraint)
}

// Register admits a worker (WRK-1, WRK-2, WRK-3, WRK-7, WRK-8).
//
// ownedOrganization is the organization the *server* has on record for this worker id. It is a
// parameter rather than a field on the registration because that is the entire point of WRK-3:
// asking the worker which organization it belongs to and believing the answer is how a worker ends
// up running another organization's jobs.
func Register(r Registration, auth AuthOutcome, ownedOrganization string, p Policy, now time.Time) (Worker, error) {
	switch {
	case strings.TrimSpace(r.WorkerID) == "":
		return Worker{}, field("a registration names no worker", "worker_id")
	case !auth.ServerVerifiedWorker:
		return Worker{}, denied(fmt.Sprintf(
			"worker %s was not authenticated by the server", r.WorkerID), "worker_auth")
	case !auth.WorkerVerifiedServer:
		// Refused distinctly. A worker that did not authenticate the server may be talking to
		// something else entirely, and registering it means that something else now has a worker.
		return Worker{}, denied(fmt.Sprintf(
			"worker %s did not authenticate the server; WRK-1 requires mutual authentication",
			r.WorkerID), "server_auth")
	case strings.TrimSpace(ownedOrganization) == "":
		return Worker{}, denied(fmt.Sprintf(
			"worker %s has no organization on record", r.WorkerID), "worker_ownership")
	case r.OrganizationID != ownedOrganization:
		// WRK-3 and INV-10. The claim and the record disagree, and the record wins.
		return Worker{}, denied(fmt.Sprintf(
			"worker %s claims organization %s and is owned by %s",
			r.WorkerID, r.OrganizationID, ownedOrganization), "worker_ownership")
	case r.Version < 1:
		return Worker{}, field(fmt.Sprintf(
			"worker %s reports no software version", r.WorkerID), "version")
	case r.Version < p.MinVersion:
		// WRK-7. Enforced at registration as well as at scheduling, so an outdated worker does not
		// sit in the pool looking available.
		return Worker{}, denied(fmt.Sprintf(
			"worker %s runs version %d and the deployment requires %d",
			r.WorkerID, r.Version, p.MinVersion), "worker_version")
	}

	attested := strings.TrimSpace(r.Attestation) != ""
	if p.RequireAttestation && !attested {
		return Worker{}, denied(fmt.Sprintf(
			"worker %s produced no attestation and this deployment requires one", r.WorkerID),
			"worker_attestation")
	}

	capabilities := append([]string(nil), r.Capabilities...)
	sort.Strings(capabilities)
	return Worker{
		ID:             r.WorkerID,
		OrganizationID: ownedOrganization,
		Capabilities:   capabilities,
		Version:        r.Version,
		// Labels are deliberately not populated from the registration. A worker that could label
		// itself would advertise whatever gate it wanted to pass.
		Labels:        nil,
		Attested:      attested,
		Health:        HealthHealthy,
		LastHeartbeat: now,
	}, nil
}

// Stale reports whether the worker has gone unheard from past the policy's bound (WRK-4).
//
// A zero LastHeartbeat is stale rather than "just now": a record with no heartbeat is one that
// never reported, and reading the zero time as current would make an unfilled field look like a
// live worker.
func (w Worker) Stale(p Policy, now time.Time) bool {
	if w.LastHeartbeat.IsZero() {
		return true
	}
	return now.Sub(w.LastHeartbeat) > p.heartbeatTimeout()
}

// Demand is what a piece of work needs from a worker.
type Demand struct {
	OrganizationID string `json:"organization_id"`
	// Capabilities the work requires. Every one must be advertised.
	Capabilities []string `json:"capabilities,omitempty"`
	// Labels the work requires. Every one must be assigned by the server.
	Labels []string `json:"labels,omitempty"`
}

// Eligibility is a scheduling decision.
type Eligibility struct {
	// Eligible is false in the zero value, so a decision nobody computed does not schedule work.
	Eligible bool `json:"eligible"`
	// Reason names why not, so an operator staring at an idle pool can find out.
	Reason string `json:"reason,omitempty"`
}

// Eligible decides whether a worker may take a piece of work (WRK-6).
//
// Every condition must hold. The order runs from the most fundamental to the most contextual, so a
// refusal names the reason a person would want first: belonging to the wrong organization is a
// different conversation from missing a capability.
func Eligible(w Worker, d Demand, p Policy, now time.Time) Eligibility {
	switch {
	case strings.TrimSpace(w.ID) == "":
		return Eligibility{Reason: "the worker record is empty"}
	case strings.TrimSpace(d.OrganizationID) == "" || w.OrganizationID != d.OrganizationID:
		// INV-10, first. Everything below it is a question about a worker that has already been
		// established as the right organization's.
		return Eligibility{Reason: fmt.Sprintf(
			"worker %s belongs to %s and the work is %s's",
			w.ID, w.OrganizationID, orgName(d.OrganizationID))}
	case w.Version < p.MinVersion:
		return Eligibility{Reason: fmt.Sprintf(
			"worker %s runs version %d and the deployment requires %d",
			w.ID, w.Version, p.MinVersion)}
	case p.RequireAttestation && !w.Attested:
		return Eligibility{Reason: fmt.Sprintf("worker %s is not attested", w.ID)}
	case w.Draining:
		// Named as draining rather than as unavailable, because an operator who drained it wants to
		// see that reflected and one who did not wants to know somebody did.
		return Eligibility{Reason: fmt.Sprintf("worker %s is draining", w.ID)}
	case w.Health != HealthHealthy:
		return Eligibility{Reason: fmt.Sprintf(
			"worker %s reports health %s", w.ID, healthName(w.Health))}
	case w.Stale(p, now):
		return Eligibility{Reason: fmt.Sprintf(
			"worker %s has not reported since %s", w.ID, w.LastHeartbeat.Format(time.RFC3339))}
	}

	for _, c := range d.Capabilities {
		if !contains(w.Capabilities, c) {
			return Eligibility{Reason: fmt.Sprintf(
				"worker %s does not advertise %s", w.ID, c)}
		}
	}
	for _, l := range d.Labels {
		if !contains(w.Labels, l) {
			// Checked against the server-assigned labels. A worker cannot satisfy this by saying so.
			return Eligibility{Reason: fmt.Sprintf(
				"worker %s does not carry the policy label %s", w.ID, l)}
		}
	}
	return Eligibility{Eligible: true}
}

func contains(in []string, v string) bool {
	for _, s := range in {
		if s == v {
			return true
		}
	}
	return false
}

func orgName(id string) string {
	if strings.TrimSpace(id) == "" {
		return "unspecified"
	}
	return id
}

func healthName(h Health) string {
	if h == HealthUnknown {
		return "unknown"
	}
	return string(h)
}

// Drain marks a worker for upgrade (WRK-5).
//
// Idempotent, and it does not touch health: a draining worker is still answering, and recording it
// as unhealthy would put a planned upgrade into the same bucket as an outage.
func (w Worker) Drain() Worker {
	w.Draining = true
	return w
}

// Heartbeat records a report (WRK-4).
//
// A heartbeat carrying an unrecognised health state is refused rather than stored, because an
// unrecognised state compares unequal to HealthHealthy and would take the worker out of service
// silently — the failure would present as a worker that stopped receiving work for no reason.
func (w Worker) Heartbeat(h Health, at time.Time) (Worker, error) {
	switch h {
	case HealthHealthy, HealthDegraded, HealthUnhealthy:
	default:
		return w, field(fmt.Sprintf(
			"worker %s reported the unrecognised health state %q", w.ID, h), "health")
	}
	if at.IsZero() {
		return w, field(fmt.Sprintf("worker %s sent a heartbeat with no timestamp", w.ID),
			"last_heartbeat")
	}
	w.Health = h
	w.LastHeartbeat = at
	return w, nil
}
