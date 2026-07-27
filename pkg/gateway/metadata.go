package gateway

import (
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/taint"
)

// Failover records one abandoned route attempt.
//
// §14.4 requires failover to preserve capability, policy, residency, retention, and budget
// equivalence. That holds by construction here: every candidate was produced by the same
// Constraints, so moving between them cannot widen the envelope. What must still be recorded is
// that it happened, and why.
type Failover struct {
	ProviderID string `json:"provider_id"`
	ModelID    string `json:"model_id"`
	// Reason is a stable error code or a gateway-side classification, never provider prose.
	Reason string `json:"reason"`
}

// ModelCall is the immutable metadata for one gateway invocation (SDD §10).
//
// # What is deliberately absent
//
// There is no prompt, no completion, and no tool output. Bodies are metadata-only by default
// (INV-4), and the way that promise survives contact with a real system is for the metadata type to
// have nowhere to put a body. Bodies that policy does permit are stored as artifacts and referenced
// from the run's event log, on their own retention schedule.
type ModelCall struct {
	ID             id.ID `json:"id"`
	OrganizationID id.ID `json:"organization_id"`
	RunID          id.ID `json:"run_id"`
	StepID         id.ID `json:"step_id"`

	// Alias is what was requested; ProviderID and ModelID are what served it.
	Alias      string `json:"alias"`
	ProviderID string `json:"provider_id"`
	ModelID    string `json:"model_id"`

	// DeclaredRevision is the revision in the capability record; ObservedRevision is what the
	// provider actually reported. Keeping both is what makes silent provider model changes
	// detectable (MOD-6) and gives OEV-1 canary gating something to compare.
	DeclaredRevision string `json:"declared_revision"`
	ObservedRevision string `json:"observed_revision"`

	Classification Classification `json:"classification"`
	// DLPFindings records which rules fired and where, never what matched.
	DLPFindings []Finding `json:"dlp_findings,omitempty"`

	// Losses are every declared translation gap, from policy clamps and from the adapter (ADP-3).
	Losses []inference.Loss `json:"losses,omitempty"`

	Usage inference.Usage `json:"usage"`
	// Cost is computed from provider-reported usage. EstimatedCost is the pre-call admission
	// estimate; keeping both lets estimate drift be measured instead of guessed.
	Cost          inference.Money `json:"cost"`
	EstimatedCost inference.Money `json:"estimated_cost"`

	FinishReason inference.FinishReason `json:"finish_reason"`
	// Taint is the highest-risk provenance class in the request context (TNT-5).
	Taint taint.Class `json:"taint"`

	Failovers []Failover `json:"failovers,omitempty"`

	PolicyDecisionID   id.ID `json:"policy_decision_id,omitempty"`
	SettingsSnapshotID id.ID `json:"settings_snapshot_id,omitempty"`

	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

// Latency returns the wall-clock duration of the call.
func (m ModelCall) Latency() time.Duration { return m.CompletedAt.Sub(m.StartedAt) }

// RevisionDrifted reports whether the provider served a revision other than the one the capability
// record declares.
//
// A drift is not an error — providers roll models forward — but it is the trigger for
// evaluation.revision.detected and, where policy requires canary passage, for holding the route
// (OEV-1, OEV-6).
func (m ModelCall) RevisionDrifted() bool {
	return m.ObservedRevision != "" && m.ObservedRevision != m.DeclaredRevision
}

// FailedOver reports whether the call abandoned at least one route before succeeding.
func (m ModelCall) FailedOver() bool { return len(m.Failovers) > 0 }
