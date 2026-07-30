package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// S11: an interrupted stream is attributed to whoever interrupted it.
//
// The pump selects on the caller's context and on the upstream channel. Under cancellation the
// adapter observes the same context, stops, and closes upstream on its way out, so both cases are
// ready and Go picks between them pseudorandomly — and the pick used to decide what the run was
// recorded as. It passed on macOS every time and failed once on a Linux CI runner, recording a
// user's cancellation as a provider that truncated its stream.
//
// The race cannot be pinned by repetition, because the outcome is a coin flip only when both cases
// are ready and no test can force that reliably. So the attribution is a pure function of the
// context and the upstream signal, and this asserts the function directly: every branch must reach
// the same verdict, which is what makes the select's choice stop mattering.
func TestSecurityAnInterruptedStreamIsAttributedToWhoeverInterruptedIt(t *testing.T) {
	live := context.Background()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	upstreamErr := modberr.New(modberr.CodeProviderUnavailable, "the provider fell over")

	cases := []struct {
		name string
		got  error
		want modberr.Code
	}{
		// A closed stream is evidence about the provider only if the provider was still meant to be
		// streaming.
		{"closed stream, live context", closedStreamCause(live, "vendor"), modberr.CodeProviderUnavailable},
		{"closed stream, cancelled context", closedStreamCause(cancelled, "vendor"), modberr.CodeCancelled},
		// An adapter surfacing its cancelled context as a stream error is reporting our own
		// cancellation back to us; taking it at face value blames the provider for it.
		{"stream error, live context", streamErrorCause(live, upstreamErr), modberr.CodeProviderUnavailable},
		{"stream error, cancelled context", streamErrorCause(cancelled, upstreamErr), modberr.CodeCancelled},
		// An adapter that signals an error without supplying one is still a provider fault.
		{"errorless stream error, live context", streamErrorCause(live, nil), modberr.CodeProviderUnavailable},
		{"errorless stream error, cancelled context", streamErrorCause(cancelled, nil), modberr.CodeCancelled},
		// The branch that observed the cancellation directly agrees with the other two.
		{"context branch", cancellationCause(cancelled), modberr.CodeCancelled},
	}

	for _, c := range cases {
		if c.got == nil {
			t.Errorf("%s: an interrupted stream produced no cause", c.name)
			continue
		}
		if !modberr.Is(c.got, c.want) {
			t.Errorf("%s: cause = %v, want %s", c.name, c.got, c.want)
		}
	}

	// Under cancellation no provider fault is recorded at all — not merely a different code. The
	// truncated-stream detail is what a provider-health reading would later count, and a cancelled
	// run must contribute nothing to it.
	//
	// A mutant that returns the cancellation *carrying* upstream_class survives this, and it is
	// equivalent rather than a gap: CodeCancelled's schema admits only run_id and cancelled_by, so
	// WithDetail files upstream_class under unregistered_detail_keys and the provider-fault detail
	// cannot be attached to a cancellation at all. The assertion below is the second line of that
	// defence, not the only one.
	if detail := upstreamClass(closedStreamCause(cancelled, "vendor")); detail != "" {
		t.Errorf("a cancelled stream carried upstream_class=%q; that is a provider fault record", detail)
	}
	if detail := upstreamClass(closedStreamCause(live, "vendor")); detail != "truncated_stream" {
		t.Errorf("a genuinely truncated stream carried upstream_class=%q, want truncated_stream", detail)
	}

	// The cancellation cause keeps context.Canceled reachable, so a caller can still tell a
	// cancellation from a deadline.
	if !errors.Is(cancellationCause(cancelled), context.Canceled) {
		t.Error("the cancellation cause no longer wraps context.Canceled")
	}
	deadlined, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer stop()
	if !errors.Is(cancellationCause(deadlined), context.DeadlineExceeded) {
		t.Error("a deadline was reported as a cancellation without its cause")
	}
}

// upstreamClass reads the provider-fault detail a cause carries, or "" if it carries none.
func upstreamClass(err error) string {
	var e *modberr.Error
	if !errors.As(err, &e) {
		return ""
	}
	return e.Details()["upstream_class"]
}
