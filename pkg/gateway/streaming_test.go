package gateway_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/event"
	"github.com/modbit/modbit/pkg/gateway"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/inference/fake"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/settings"
	"github.com/modbit/modbit/pkg/taint"
)

// Every test below names the streaming-protocol invariant it covers. The invariants are stated in
// streaming.go; a test here without a matching S-number, or an S-number without a test, is a gap.

func streamCall(req inference.Request, snap settings.Snapshot) gateway.Call {
	return gateway.Call{
		Request:          req,
		OrganizationID:   id.MustNew(id.Organization),
		SpaceID:          id.MustNew(id.Space),
		CorrelationID:    id.MustNew(id.Correlation),
		Settings:         snap,
		PolicyDecisionID: id.MustNew(id.PolicyDecision),
		Taint:            taint.UserTrusted,
	}
}

// drain collects a stream to completion, enforcing S3, S4, and S5 on every use.
func drain(t *testing.T, events <-chan gateway.StreamEvent) (deltas []inference.StreamEvent, terminal gateway.StreamEvent) {
	t.Helper()
	seenTerminal := 0
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e, open := <-events:
			if !open {
				if seenTerminal != 1 {
					t.Fatalf("S4 violated: %d terminal events before close, want exactly 1", seenTerminal)
				}
				return deltas, terminal
			}
			if e.Terminal() {
				seenTerminal++
				if e.Result != nil && e.Err != nil {
					t.Fatal("S5 violated: terminal event carries both a Result and an Err")
				}
				terminal = e
				continue
			}
			if e.Delta == nil {
				t.Fatal("S5 violated: a non-terminal event carries no delta")
			}
			deltas = append(deltas, *e.Delta)
		case <-deadline:
			t.Fatal("S3 violated: the stream channel was never closed")
		}
	}
}

// S1, S4, S5, S10.
func TestStreamDeliversDeltasThenExactlyOneTerminalResult(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	h.adapters[0].Reply = "the change looks correct"

	events, err := h.gw.Stream(context.Background(), streamCall(request("review this"), snapshot(t, nil)))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	deltas, terminal := drain(t, events)
	if len(deltas) == 0 {
		t.Fatal("no deltas were delivered")
	}
	if terminal.Result == nil {
		t.Fatalf("terminal event is not a Result: %v", terminal.Err)
	}
	if terminal.Kind() != gateway.StreamKindCompleted {
		t.Errorf("Kind = %q, want completed", terminal.Kind())
	}

	var assembled strings.Builder
	for _, d := range deltas {
		assembled.WriteString(d.Text)
	}
	if strings.TrimSpace(assembled.String()) != terminal.Result.Response.Text() {
		t.Errorf("assembled deltas %q disagree with the terminal response %q",
			assembled.String(), terminal.Result.Response.Text())
	}
}

// S1: every refusal preparation can detect returns (nil, err) with no channel allocated.
func TestStreamPreparationRefusalsAreSynchronous(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		opts     gateway.Options
		snapshot map[settings.Key]any
		req      inference.Request
		wantCode modberr.Code
	}{
		{
			name: "dlp unavailable", opts: gateway.Options{Inspector: failingInspector{}},
			req: request("hello"), wantCode: modberr.CodeDLPUnavailable,
		},
		{
			name: "dlp block", req: request("key AKIAIOSFODNN7EXAMPLE"),
			wantCode: modberr.CodeDLPBlocked,
		},
		{
			name: "alias outside policy", req: request("hello"),
			snapshot: map[settings.Key]any{settings.KeyModelAliasesAllowed: []any{"code.default"}},
			wantCode: modberr.CodePolicyDenied,
		},
		{
			name:     "budget exhausted",
			opts:     gateway.Options{Spend: spendReporter{spent: inference.Money{Micros: 4_999_999, Currency: "USD"}}},
			req:      request(strings.Repeat("token ", 500)),
			snapshot: map[settings.Key]any{settings.KeyModelCostCapPerRunMicros: 5_000_000},
			wantCode: modberr.CodeBudgetExhausted,
		},
		{
			name: "credential lease failure", opts: gateway.Options{Broker: &broker{err: errors.New("vault sealed")}},
			req: request("hello"), wantCode: modberr.CodeUnauthenticated,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, tc.opts)
			events, err := h.gw.Stream(context.Background(), streamCall(tc.req, snapshot(t, tc.snapshot)))
			if events != nil {
				t.Error("S1 violated: a refused call must not allocate a channel")
			}
			if !modberr.Is(err, tc.wantCode) {
				t.Fatalf("error = %v, want %s", err, tc.wantCode)
			}
		})
	}
}

// S2: no credential is leased and no provider stream is opened before DLP clears the payload.
func TestStreamPerformsNoEgressBeforeDLP(t *testing.T) {
	t.Parallel()

	blocked := newHarness(t, gateway.Options{})
	if _, err := blocked.gw.Stream(context.Background(),
		streamCall(request("deploy with AKIAIOSFODNN7EXAMPLE"), snapshot(t, nil))); err == nil {
		t.Fatal("expected the blocked payload to be refused")
	}
	if blocked.adapters[0].Calls() != 0 {
		t.Error("S2 violated: a provider stream was opened for a blocked payload")
	}
	if len(blocked.broker.requests) != 0 {
		t.Error("S2 violated: a credential was leased for a blocked payload")
	}

	unavailable := newHarness(t, gateway.Options{Inspector: failingInspector{}})
	if _, err := unavailable.gw.Stream(context.Background(),
		streamCall(request("hello"), snapshot(t, nil))); err == nil {
		t.Fatal("expected the call to fail closed")
	}
	if unavailable.adapters[0].Calls() != 0 || len(unavailable.broker.requests) != 0 {
		t.Error("S2 violated: egress occurred although DLP could not complete")
	}
}

// S6: usage is attributed on every termination, including cancellation. A cancelled stream still
// consumed tokens.
func TestStreamRecordsMetadataOnEveryTermination(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, gateway.Options{})
		events, err := h.gw.Stream(context.Background(), streamCall(request("hello"), snapshot(t, nil)))
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		_, terminal := drain(t, events)
		if len(h.recordedCalls()) != 1 {
			t.Fatalf("recorded %d calls, want exactly 1", len(h.recordedCalls()))
		}
		rec := h.recordedCalls()[0]
		if rec.Usage.Total() == 0 {
			t.Error("usage was not recorded")
		}
		if rec.FinishReason != inference.FinishEndTurn {
			t.Errorf("finish reason = %q", rec.FinishReason)
		}
		if terminal.Result.Call.ID != rec.ID {
			t.Error("the terminal Result must carry the same metadata that was recorded")
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, gateway.Options{})
		h.adapters[0].Reply = "one two three four five six seven eight"
		h.adapters[0].Latency = 40 * time.Millisecond

		ctx, cancel := context.WithCancel(context.Background())
		events, err := h.gw.Stream(ctx, streamCall(request("hello"), snapshot(t, nil)))
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		<-events // consume one delta so cancellation lands mid-stream
		cancel()

		_, terminal := drain(t, events)
		if terminal.Err == nil {
			t.Fatal("a cancelled stream must terminate with an error")
		}
		if !modberr.Is(terminal.Err, modberr.CodeCancelled) {
			t.Errorf("error = %v, want MODBIT_CANCELLED", terminal.Err)
		}
		if len(h.recordedCalls()) != 1 {
			t.Fatalf("S6 violated: recorded %d calls on cancellation, want 1", len(h.recordedCalls()))
		}
		if got := h.recordedCalls()[0].FinishReason; got != inference.FinishCancelled {
			t.Errorf("finish reason = %q, want cancelled", got)
		}
	})

	t.Run("provider error", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, gateway.Options{})
		h.adapters[0].Faults = fake.Faults{OmitFinalResponse: true}

		events, err := h.gw.Stream(context.Background(), streamCall(request("hello"), snapshot(t, nil)))
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		_, terminal := drain(t, events)
		if terminal.Err == nil {
			t.Fatal("a stream ending without an assembled response must fail")
		}
		if len(h.recordedCalls()) != 1 {
			t.Errorf("S6 violated: recorded %d calls on failure, want 1", len(h.recordedCalls()))
		}
	})
}

// S7: cancellation abandons the upstream rather than draining it.
func TestStreamCancellationIsPrompt(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	h.adapters[0].Reply = strings.Repeat("word ", 40)
	h.adapters[0].Latency = 100 * time.Millisecond // draining would take ~4s

	ctx, cancel := context.WithCancel(context.Background())
	events, err := h.gw.Stream(ctx, streamCall(request("hello"), snapshot(t, nil)))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	<-events
	cancel()

	start := time.Now()
	drain(t, events)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("S7 violated: the stream took %v to stop after cancellation", elapsed)
	}
}

// S8: the gateway holds no buffer, so an unread consumer stalls the provider instead of growing the
// heap. The adapter's own channel is unbuffered too, so it blocks after at most a couple of sends.
func TestStreamAppliesBackpressureToTheProvider(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{ConsumerStallTimeout: 5 * time.Second})
	h.adapters[0].Reply = strings.Repeat("word ", 200)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := h.gw.Stream(ctx, streamCall(request("hello"), snapshot(t, nil)))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Take one event, then stop reading and let the pipeline settle.
	<-events
	time.Sleep(150 * time.Millisecond)

	sent := h.adapters[0].SentEvents()
	// message_start plus a small number in flight across two unbuffered hops. A buffering gateway
	// would have drained all 200 words by now.
	if sent > 8 {
		t.Errorf("S8 violated: provider emitted %d events while the consumer was not reading; "+
			"the gateway is buffering", sent)
	}

	cancel()
	drain(t, events)
}

// S9: a consumer that stops reading entirely cannot hold the pump goroutine forever.
func TestStreamAbandonsAStalledConsumer(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{ConsumerStallTimeout: 150 * time.Millisecond})
	h.adapters[0].Reply = strings.Repeat("word ", 50)

	events, err := h.gw.Stream(context.Background(), streamCall(request("hello"), snapshot(t, nil)))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	<-events // then stop reading

	// The pump must give up and close on its own. Draining after the stall proves the channel was
	// closed rather than the goroutine parked forever.
	time.Sleep(400 * time.Millisecond)

	closed := false
	for !closed {
		select {
		case _, open := <-events:
			if !open {
				closed = true
			}
		case <-time.After(2 * time.Second):
			t.Fatal("S9 violated: the pump did not abandon a stalled consumer")
		}
	}
	if len(h.recordedCalls()) != 1 {
		t.Errorf("S6/S9 violated: recorded %d calls for an abandoned stream, want 1", len(h.recordedCalls()))
	}
}

// S10: redaction and policy losses behave identically on both surfaces.
func TestStreamRedactsAndDeclaresLossesLikeComplete(t *testing.T) {
	t.Parallel()

	t.Run("redaction reaches the provider", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, gateway.Options{})
		req := request("use postgres://admin:hunter2secret@db.internal/app")

		events, err := h.gw.Stream(context.Background(), streamCall(req, snapshot(t, nil)))
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		drain(t, events)

		sent := h.adapters[0].LastRequest()
		if sent == nil {
			t.Fatal("the adapter recorded no request")
		}
		if strings.Contains(sent.Messages[0].Parts[0].Text, "hunter2secret") {
			t.Fatal("S10 violated: the original secret reached the provider")
		}
	})

	t.Run("policy losses reach the terminal result", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, gateway.Options{})
		snap := snapshot(t, map[settings.Key]any{settings.KeyModelMaxReasoningEffort: "low"})
		req := request("think hard")
		req.Reasoning = inference.ReasoningHigh

		events, err := h.gw.Stream(context.Background(), streamCall(req, snap))
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		_, terminal := drain(t, events)
		if terminal.Result == nil {
			t.Fatalf("terminal = %v", terminal.Err)
		}
		var found bool
		for _, l := range terminal.Result.Response.Losses {
			if l.Feature == "reasoning.policy_ceiling" {
				found = true
			}
		}
		if !found {
			t.Errorf("S10 violated: losses = %+v, want the policy ceiling declared", terminal.Result.Response.Losses)
		}
	})
}

// A provider stream that closes without a terminal event produced a truncated answer. Reporting it
// as success would let an incomplete response pass as a whole one.
func TestStreamTreatsATruncatedProviderStreamAsFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	h.adapters[0].Faults = fake.Faults{TruncateStream: true}

	events, err := h.gw.Stream(context.Background(), streamCall(request("hello"), snapshot(t, nil)))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	_, terminal := drain(t, events)
	if terminal.Err == nil {
		t.Fatal("a truncated stream must not be reported as success")
	}
	if !modberr.Is(terminal.Err, modberr.CodeProviderUnavailable) {
		t.Errorf("error = %v, want MODBIT_PROVIDER_UNAVAILABLE", terminal.Err)
	}
}

// Establishment failures fail over; a mid-stream failure does not, because no second provider can
// resume another's partial response.
func TestStreamFailsOverOnEstablishmentOnly(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{MaxRouteAttempts: 3},
		testModel("acme", "acme-large"), testModel("other", "other-model"))
	h.adapters[0].Faults = fake.Faults{
		FailWith: modberr.New(modberr.CodeProviderUnavailable, "upstream is down"),
	}

	events, err := h.gw.Stream(context.Background(), streamCall(request("hello"), snapshot(t, nil)))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	_, terminal := drain(t, events)
	if terminal.Result == nil {
		t.Fatalf("expected failover to the surviving provider: %v", terminal.Err)
	}
	if terminal.Result.Call.ProviderID != "other" {
		t.Errorf("routed to %q, want the surviving provider", terminal.Result.Call.ProviderID)
	}
	if !terminal.Result.Call.FailedOver() {
		t.Error("the abandoned attempt must be recorded")
	}
}

// A model that cannot stream is skipped at establishment rather than discovered mid-call.
func TestStreamSkipsNonStreamingModels(t *testing.T) {
	t.Parallel()
	noStream := testModel("acme", "acme-large")
	noStream.SupportsStreaming = false
	h := newHarness(t, gateway.Options{}, noStream)

	if _, err := h.gw.Stream(context.Background(),
		streamCall(request("hello"), snapshot(t, nil))); !modberr.Is(err, modberr.CodeNoEligibleRoute) {
		t.Fatalf("error = %v, want MODBIT_NO_ELIGIBLE_ROUTE", err)
	}
}

// The terminal metadata must carry no prompt or completion body, exactly as on the Complete path.
func TestStreamMetadataCarriesNoBody(t *testing.T) {
	t.Parallel()
	h := newHarness(t, gateway.Options{})
	const marker = "STREAM-BODY-MARKER-7c21"

	events, err := h.gw.Stream(context.Background(), streamCall(request("analyse "+marker), snapshot(t, nil)))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	drain(t, events)

	encoded, err := marshalCall(h.recordedCalls()[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(encoded, marker) || strings.Contains(encoded, testSecret) {
		t.Fatalf("streaming metadata contains a body or credential: %s", encoded)
	}
}

// A stream's evidence must be structurally identical to a completion's, including its events.
func TestStreamEmitsTheSameTerminalEventsAsComplete(t *testing.T) {
	t.Parallel()

	t.Run("success emits model.completed", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, gateway.Options{})
		events, err := h.gw.Stream(context.Background(), streamCall(request("hello"), snapshot(t, nil)))
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		drain(t, events)

		emitted := h.recordedEvents()
		if len(emitted) != 1 || emitted[0].EventType != event.TypeModelCompleted {
			t.Fatalf("emitted = %+v, want exactly model.completed", emitted)
		}
		if err := emitted[0].Validate(); err != nil {
			t.Errorf("envelope is not valid: %v", err)
		}
	})

	t.Run("cancellation emits model.failed", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, gateway.Options{})
		h.adapters[0].Reply = "one two three four five six"
		h.adapters[0].Latency = 40 * time.Millisecond

		ctx, cancel := context.WithCancel(context.Background())
		events, err := h.gw.Stream(ctx, streamCall(request("hello"), snapshot(t, nil)))
		if err != nil {
			t.Fatalf("Stream: %v", err)
		}
		<-events
		cancel()
		drain(t, events)

		emitted := h.recordedEvents()
		if len(emitted) != 1 || emitted[0].EventType != event.TypeModelFailed {
			t.Fatalf("emitted = %+v, want exactly model.failed", emitted)
		}
	})
}
