//go:build linux

package inotify_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/index/inotify"
)

// A burst that outruns the source becomes a rescan, never silence.
//
// CTX-2, CTX-A01c4. This is the property that makes the backend safe to trust: a watcher that
// quietly drops changes leaves the index confidently wrong, which is worse than one that stops.
//
// The kernel queue is what overflows, and it can be provoked rather than merely argued about. The
// reader goroutine parks in `send` as soon as nothing is consuming — an unbuffered channel with no
// receiver — and while it is parked it is not draining the inotify descriptor. The kernel then fills
// `fs.inotify.max_queued_events` (16384 by default) and sets IN_Q_OVERFLOW.
//
// That is not an artificial consumer either. A reindexer busy walking a tree is exactly what stops
// reading, and exactly when a burst is most likely.
func TestABurstThatOutrunsTheSourceBecomesARescan(t *testing.T) {
	queued := queuedEventLimit(t)
	if queued > 65536 {
		t.Skipf("fs.inotify.max_queued_events is %d; provoking it would cost more than the test is worth", queued)
	}

	root := t.TempDir()
	source, err := inotify.New(root)
	if err != nil {
		t.Fatalf("inotify.New: %v", err)
	}
	defer source.Close() //nolint:errcheck // the conformance suite owns Close's contract

	// Deliberately nothing reads source.Changes() during the burst. Each create yields at least
	// IN_CREATE and IN_CLOSE_WRITE, so this comfortably exceeds the queue.
	writes := queued
	for i := 0; i < writes; i++ {
		path := filepath.Join(root, fmt.Sprintf("burst%d.go", i))
		if err := os.WriteFile(path, []byte("package burst\n"), 0o644); err != nil {
			t.Fatalf("WriteFile %d: %v", i, err)
		}
	}

	deadline := time.After(20 * time.Second)
	for {
		select {
		case batch, open := <-source.Changes():
			if !open {
				t.Fatal("the source closed before reporting the loss")
			}
			if !batch.Rescan {
				continue
			}
			if batch.Reason != index.RescanQueueOverflow {
				t.Fatalf("rescan reason = %q, want %q", batch.Reason, index.RescanQueueOverflow)
			}
			// A rescan batch must carry no changes: the two are exclusive, because a consumer that
			// applied both would apply a delta to a state it is about to rebuild (D6).
			if len(batch.Changes) != 0 {
				t.Fatalf("an overflow batch carried %d changes; loss and delta are exclusive", len(batch.Changes))
			}
			return
		case <-deadline:
			t.Fatal("a burst larger than the kernel queue produced no overflow rescan; " +
				"the loss was dropped rather than reported")
		}
	}
}

func queuedEventLimit(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/sys/fs/inotify/max_queued_events")
	if err != nil {
		t.Skipf("cannot read the kernel queue limit: %v", err)
	}
	var limit int
	if _, err := fmt.Sscanf(string(raw), "%d", &limit); err != nil || limit <= 0 {
		t.Skipf("unreadable kernel queue limit %q", string(raw))
	}
	return limit
}
