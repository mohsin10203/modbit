package gateway

import (
	"context"
	"time"

	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
)

// Gateway streaming protocol (MOD-A01i).
//
// The non-streaming path can express "it worked" as a return value. A stream cannot: the caller
// consumes events over time, and every interesting failure — cancellation, a stalled consumer, a
// provider dropping mid-response — happens after the function has already returned. The protocol
// below is therefore stated as numbered invariants, each with a matching test in streaming_test.go.
//
//	S1  Preparation is synchronous. Policy validation, DLP, routing, budget admission, and the
//	    credential lease all complete before a channel exists. A refused call returns (nil, err) and
//	    never produces a stream, so no caller sets up a consumption loop for work that never began.
//	S2  No egress precedes DLP. A blocked or unclassifiable payload leases no credential and opens
//	    no provider stream.
//	S3  The channel is closed exactly once, on every exit path.
//	S4  Exactly one terminal event is delivered, and it always precedes close. A caller never has to
//	    infer termination from a closed channel.
//	S5  A terminal event carries either a Result or an Err, never both and never neither.
//	S6  Model-call metadata is recorded exactly once, on every termination — success, failure, and
//	    cancellation alike. A cancelled stream still consumed tokens and must still be attributed.
//	S7  Cancellation is prompt: the upstream stream is abandoned and the channel closes without
//	    waiting for the provider to finish.
//	S8  Backpressure is applied to the provider, not absorbed in memory. The gateway holds no
//	    unbounded buffer, so a slow consumer slows the upstream read rather than growing the heap.
//	S9  A consumer that stops reading entirely cannot leak the pump forever. After
//	    ConsumerStallTimeout the stream is abandoned, metadata is recorded, and the channel closes.
//	S10 The payload the provider receives is the redacted one, and declared losses reach the caller
//	    on the terminal Result exactly as they do on the non-streaming path.
//
// # Why failover stops at the first byte
//
// Establishment failures fail over across eligible candidates, exactly as Complete does. Once a
// provider stream is open the gateway is committed: a second provider cannot resume another's
// partial response, and re-running from the start would either duplicate deltas the caller already
// rendered or silently discard them. A mid-stream failure is therefore terminal, and the caller
// decides whether to retry the whole call.

// StreamEventKind is unused by callers switching on the union below, but is recorded on metadata
// and in traces where a symbolic name is more useful than a nil check.
type StreamEventKind string

const (
	StreamKindDelta     StreamEventKind = "delta"
	StreamKindCompleted StreamEventKind = "completed"
	StreamKindFailed    StreamEventKind = "failed"
)

// StreamEvent is one event on a gateway stream.
//
// Exactly one of Delta, Result, or Err is populated. Terminal reports which.
type StreamEvent struct {
	// Delta is an incremental provider event, normalized by the adapter.
	Delta *inference.StreamEvent
	// Result is the completed response and its immutable metadata. Set once, on success.
	Result *Result
	// Err is the terminal failure. Set once, on failure or cancellation.
	Err error
}

// Kind returns the event's discriminator.
func (e StreamEvent) Kind() StreamEventKind {
	switch {
	case e.Result != nil:
		return StreamKindCompleted
	case e.Err != nil:
		return StreamKindFailed
	default:
		return StreamKindDelta
	}
}

// Terminal reports whether this is the stream's final event (S4).
func (e StreamEvent) Terminal() bool { return e.Result != nil || e.Err != nil }

// defaultConsumerStallTimeout bounds how long the pump waits for a consumer that has stopped
// reading. It is generous: a human reviewing a diff mid-stream is a legitimate pause, and killing
// their stream would be worse than holding one goroutine.
const defaultConsumerStallTimeout = 60 * time.Second

// Stream runs the pipeline and returns a channel of events.
//
// Preparation is synchronous (S1): every refusal this function can detect is returned as an error
// with no channel allocated.
func (g *Gateway) Stream(ctx context.Context, c Call) (<-chan StreamEvent, error) {
	started := g.clock.Now()

	prepared, err := g.prepare(ctx, c)
	if err != nil {
		return nil, err
	}

	// Establishment failover. Once a provider stream is open the gateway is committed; see the
	// package note above.
	var (
		attempts  int
		lastErr   error
		failovers []Failover
	)
	for _, candidate := range prepared.candidates {
		// A capability mismatch is decided locally and performs no I/O, so it is filtered before
		// the attempt budget is charged. Spending an attempt on it would let two non-streaming
		// candidates exhaust the budget before any provider was contacted.
		if !candidate.Model.SupportsStreaming {
			failovers = append(failovers, Failover{
				ProviderID: candidate.Model.ProviderID, ModelID: candidate.Model.ModelID,
				Reason: "streaming_unsupported",
			})
			lastErr = modberr.New(modberr.CodeNoEligibleRoute, "model does not support streaming").
				WithDetail("required_capabilities", "streaming")
			continue
		}

		if attempts >= g.maxAttempts {
			break
		}
		attempts++

		cred, err := g.broker.Lease(ctx, candidate.Model.ProviderID)
		if err != nil {
			lastErr = modberr.Wrap(err, modberr.CodeUnauthenticated,
				"could not lease a provider credential").WithDetail("scheme", "provider_credential")
			failovers = append(failovers, Failover{
				ProviderID: candidate.Model.ProviderID, ModelID: candidate.Model.ModelID,
				Reason: "credential_lease_failed",
			})
			continue
		}
		if cred.Expired(g.clock.Now()) {
			lastErr = modberr.New(modberr.CodeUnauthenticated, "leased credential is already expired").
				WithDetail("scheme", "provider_credential")
			failovers = append(failovers, Failover{
				ProviderID: candidate.Model.ProviderID, ModelID: candidate.Model.ModelID,
				Reason: "credential_expired",
			})
			continue
		}

		upstream, err := candidate.Adapter.Stream(ctx, prepared.request, candidate.Model, cred)
		if err != nil {
			lastErr = err
			if !modberr.IsRetryable(err) {
				return nil, err
			}
			failovers = append(failovers, Failover{
				ProviderID: candidate.Model.ProviderID, ModelID: candidate.Model.ModelID,
				Reason: string(modberr.CodeOf(err)),
			})
			continue
		}

		// Unbuffered on purpose (S8): every event the consumer has not taken is one the pump has
		// not read from the provider, so backpressure reaches the upstream instead of accumulating
		// in a queue whose depth nobody chose.
		out := make(chan StreamEvent)
		go g.pump(ctx, c, prepared, candidate, upstream, out, failovers, started)
		return out, nil
	}

	if lastErr == nil {
		lastErr = modberr.New(modberr.CodeNoEligibleRoute, "no streaming route was attempted")
	}
	return nil, lastErr
}

// pump forwards upstream events and guarantees the terminal contract.
//
// It owns out and closes it exactly once (S3). Every return path passes through terminate, which is
// what makes "exactly one terminal event, always before close" true by construction rather than by
// review (S4, S5, S6).
func (g *Gateway) pump(ctx context.Context, c Call, p prepared, candidate inference.Candidate,
	upstream <-chan inference.StreamEvent, out chan<- StreamEvent, failovers []Failover, started time.Time) {

	defer close(out)

	stall := g.consumerStallTimeout
	if stall <= 0 {
		stall = defaultConsumerStallTimeout
	}

	// sendDelta abandons an in-flight delta when the context ends: once the caller has cancelled,
	// partial content is no longer wanted and forcing it through only delays the terminal event.
	sendDelta := func(e StreamEvent) bool {
		timer := time.NewTimer(stall)
		defer timer.Stop()
		select {
		case out <- e:
			return true
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		}
	}

	// sendTerminal deliberately does not select on ctx.Done().
	//
	// Cancelling the work must not cancel the notification that the work ended. Selecting on a
	// context that is already closed makes delivery a coin flip between two ready cases, so a
	// cancelled stream would sometimes close without a terminal event and the caller would be left
	// inferring termination from a closed channel — exactly what S4 exists to prevent. The stall
	// timer still bounds it, so a consumer that has genuinely stopped reading cannot pin the pump.
	sendTerminal := func(e StreamEvent) {
		timer := time.NewTimer(stall)
		defer timer.Stop()
		select {
		case out <- e:
		case <-timer.C:
		}
	}

	// terminate records metadata once and emits the single terminal event. The recording happens
	// even when the consumer has gone (S6): usage was incurred and must be attributed regardless of
	// whether anyone is left to hear about it.
	terminate := func(resp *inference.Response, cause error) {
		usage := inference.Usage{}
		if resp != nil {
			usage = resp.Usage
		}

		call := g.buildCall(c, p, candidate, finishReasonFor(resp, cause), usage,
			respLosses(resp, p), failovers, started, observedRevision(resp))

		var recordingErr error
		if g.recorder != nil {
			// WithoutCancel deliberately: the work is over and the usage was already incurred, so a
			// cancelled context must not also destroy the evidence that it happened (S6).
			recordingErr = g.record(context.WithoutCancel(ctx), c, call, cause)
		}

		if cause != nil {
			sendTerminal(StreamEvent{Err: cause})
			return
		}
		final := *resp
		final.Losses = call.Losses
		sendTerminal(StreamEvent{Result: &Result{Response: final, Call: call, RecordingErr: recordingErr}})
	}

	for {
		select {
		case <-ctx.Done():
			// S7: abandon the upstream rather than draining it. The provider observes the same
			// cancelled context and stops on its own.
			terminate(nil, cancellationCause(ctx))
			return

		case ev, open := <-upstream:
			if !open {
				terminate(nil, closedStreamCause(ctx, candidate.Model.ProviderID))
				return
			}

			switch ev.Kind {
			case inference.StreamError:
				terminate(nil, streamErrorCause(ctx, ev.Err))
				return

			case inference.StreamMessageStop:
				if ev.Final == nil {
					terminate(nil, modberr.New(modberr.CodeInternal,
						"adapter ended the stream without an assembled response"))
					return
				}
				if err := ev.Final.Validate(); err != nil {
					terminate(nil, modberr.Wrap(err, modberr.CodeInternal,
						"adapter returned a response that is not a valid canonical response"))
					return
				}
				terminate(ev.Final, nil)
				return

			default:
				delta := ev
				if !sendDelta(StreamEvent{Delta: &delta}) {
					// S9: the consumer stopped reading or the context ended. Record what was spent
					// and stop; holding the goroutine open would leak it for the process lifetime.
					terminate(nil, modberr.New(modberr.CodeCancelled,
						"stream abandoned: the consumer stopped reading").
						WithDetail("run_id", c.Request.RunID.String()))
					return
				}
			}
		}
	}
}

// The termination cause of an interrupted stream, decided in one place.
//
// # Why these are functions and not three inline branches
//
// The pump selects on the caller's context and on the upstream channel. When the caller cancels,
// the adapter observes the same context, stops, and closes upstream on its way out — so both cases
// become ready and Go picks between them pseudorandomly. Whichever it picked used to decide what
// the run was recorded as. On a macOS developer machine ctx.Done() won every time; on a Linux CI
// runner the closed channel won once, and a cancelled run was recorded as a provider that
// truncated its stream.
//
// Making cancellation win explicitly in every branch is what removes the coin flip, and having the
// branches share these functions is what keeps the next one from being written without the check.

// cancellationCause is the error for a stream the caller ended.
func cancellationCause(ctx context.Context) error {
	return modberr.Wrap(ctx.Err(), modberr.CodeCancelled, "stream cancelled")
}

// closedStreamCause explains an upstream that closed without a terminal event.
//
// A closed stream is only evidence about the provider if the provider was still meant to be
// streaming. Under cancellation the adapter closed the channel because it was told to stop, and
// filing that as a truncated stream writes a provider fault into the record for something the user
// did on purpose.
func closedStreamCause(ctx context.Context, providerID string) error {
	if ctx.Err() != nil {
		return cancellationCause(ctx)
	}
	// Reporting success here would let a truncated answer pass as a whole one.
	return modberr.New(modberr.CodeProviderUnavailable,
		"provider stream ended without a completion").
		WithDetail("provider_id", providerID).
		WithDetail("upstream_class", "truncated_stream")
}

// streamErrorCause explains an upstream that reported an error.
//
// Cancellation is checked first for the same reason: an adapter that surfaces its cancelled context
// as a stream error is reporting our own cancellation back to us, and taking it at face value
// blames the provider for it.
func streamErrorCause(ctx context.Context, upstreamErr error) error {
	if ctx.Err() != nil {
		return cancellationCause(ctx)
	}
	if upstreamErr != nil {
		return upstreamErr
	}
	return modberr.New(modberr.CodeProviderUnavailable, "provider reported a stream error")
}

func observedRevision(resp *inference.Response) string {
	if resp != nil && resp.ModelRevision != "" {
		return resp.ModelRevision
	}
	// A stream that never completed has no observed revision. Reporting the declared one would
	// manufacture evidence that the provider confirmed it.
	return ""
}

func respLosses(resp *inference.Response, p prepared) []inference.Loss {
	out := append([]inference.Loss{}, p.policyLosses...)
	if resp != nil {
		out = append(out, resp.Losses...)
	}
	return out
}
