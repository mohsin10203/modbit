package gateway

import (
	"context"

	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
)

// Canonical event emission (MOD-A01j).
//
// Requirements: INV-5 (every authoritative run transition emits the canonical envelope), R-EVT-04
// (state writes and event publication are atomic), MOD-6 and OEV-1 (silent provider model changes
// are detectable).
//
// # Why events are written with the metadata, not separately
//
// R-EVT-04 requires the state write and the event publication to be one atomic act. The gateway's
// state write *is* the ModelCall, so Recorder takes both and a production implementation inserts
// them in a single transaction alongside the outbox row. Emitting through a separate publisher
// would reintroduce exactly the failure R-EVT-04 exists to prevent: a recorded call with no event,
// or an event for a call that was never recorded.
//
// # Why only terminal events
//
// The catalog defines model.requested, model.routed, and model.stream.delta. None is emitted here.
//
// A delta event per token would put a durable, sequenced, tenant-scoped envelope in the event log
// for every few characters of output — orders of magnitude more events than run transitions, all of
// them content the log is forbidden to carry anyway (INV-4). Deltas are a live-observation concern,
// served by the streaming surface.
//
// model.requested and model.routed are not emitted because everything they would carry — alias,
// chosen provider and model, classification, declared losses, cost — is already in the ModelCall
// that the terminal event references. Emitting them before the outcome is known would also create
// orphans: a request event with no completion whenever a process dies mid-call, which a consumer
// cannot distinguish from a call still in flight.

// buildEvents assembles the canonical events for a finished call.
//
// The sequence is allocated by the caller and passed in, because run-scoped events need a strictly
// monotonic per-run sequence that only the run's sequence authority can issue (R-EVT-01).
func (g *Gateway) buildEvents(c Call, call ModelCall, cause error, seq func() (uint64, error)) ([]event.Envelope, error) {
	builder, err := event.NewBuilder(c.OrganizationID, g.clock, g.generator)
	if err != nil {
		return nil, err
	}
	actor := event.Actor{Type: event.ActorAgent, ID: c.Request.RunID.String()}

	var out []event.Envelope

	// A failover happened before the outcome, so it is reported first. It is an audit event: which
	// provider was abandoned, and why, is a governance question independent of whether the call
	// eventually succeeded.
	for range call.Failovers {
		n, err := seq()
		if err != nil {
			return nil, err
		}
		e, err := builder.New(event.TypeModelFailedOver, actor, g.runAttrs(c, call, n))
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}

	n, err := seq()
	if err != nil {
		return nil, err
	}
	terminal := event.TypeModelCompleted
	if cause != nil {
		terminal = event.TypeModelFailed
	}
	e, err := builder.New(terminal, actor, g.runAttrs(c, call, n))
	if err != nil {
		return nil, err
	}
	out = append(out, e)

	// OEV-1: the provider served a revision other than the one the capability record declares.
	// Organization scoped, because a revision roll affects every run routed to that model, not just
	// the one that happened to notice.
	if call.RevisionDrifted() {
		e, err := builder.New(event.TypeEvaluationRevisionDetected,
			event.Actor{Type: event.ActorSystem, ID: "svc_model_gateway"},
			event.Attributes{CorrelationID: c.CorrelationID})
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// runAttrs builds the envelope attributes shared by every run-scoped gateway event.
func (g *Gateway) runAttrs(c Call, call ModelCall, sequence uint64) event.Attributes {
	return event.Attributes{
		SpaceID:            c.SpaceID,
		RunID:              c.Request.RunID,
		Sequence:           sequence,
		CorrelationID:      c.CorrelationID,
		PolicyDecisionID:   call.PolicyDecisionID,
		SettingsSnapshotID: call.SettingsSnapshotID,
	}
}

// sequenceAllocator returns a function issuing per-run sequences, or an error when the gateway has
// no sequencer.
//
// Run-scoped events without a monotonic sequence would break replay ordering (R-EVT-01, R-EVT-07),
// so a gateway configured to emit events must be given a sequencer. The alternative — inventing a
// sequence locally — produces a log that cannot be reassembled.
func (g *Gateway) sequenceAllocator(ctx context.Context, runID id.ID) func() (uint64, error) {
	return func() (uint64, error) {
		if g.sequencer == nil {
			return 0, modberr.New(modberr.CodeInternal,
				"gateway is configured to emit run-scoped events but has no sequence authority")
		}
		return g.sequencer.Next(ctx, runID)
	}
}

// finishReasonFor maps a terminal cause onto the canonical finish reason recorded on metadata.
func finishReasonFor(resp *inference.Response, cause error) inference.FinishReason {
	switch {
	case resp != nil:
		return resp.FinishReason
	case modberr.Is(cause, modberr.CodeCancelled):
		return inference.FinishCancelled
	default:
		return inference.FinishError
	}
}
