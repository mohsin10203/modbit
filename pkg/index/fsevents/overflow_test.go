//go:build darwin && cgo

package fsevents_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/index/fsevents"
)

// A burst that outruns the source becomes a rescan, never silence.
//
// ADR-0104 recorded the overflow mapping as the least-proven part of this backend, on the grounds
// that a kernel queue overflow cannot be provoked on demand. That was half right: the *kernel's*
// `MustScanSubDirs` still cannot be forced, but the source's own bounded queue can, and both arrive
// at the same place — a `RescanQueueOverflow` batch. This covers the path the conformance suite
// leaves Skipped for this source, and it is the property that matters most:
//
// A watcher that quietly drops changes leaves the index confidently wrong, which is worse than one
// that stops. The contract says loss must be reported, and this is where that is enforced.
//
// The consumer deliberately does not read while the burst runs. That is not artificial — it is
// exactly what happens when the reindexer is busy walking a tree, which is precisely when a burst
// is most likely.
func TestABurstThatOutrunsTheSourceBecomesARescan(t *testing.T) {
	root := t.TempDir()
	source, err := fsevents.New(root, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("fsevents.New: %v", err)
	}
	defer source.Close()
	time.Sleep(200 * time.Millisecond) // let the stream attach before the burst

	// Half again the source's internal queue depth (4096). The sender parks on its first batch
	// because nothing is reading, so the queue fills behind it and the surplus has nowhere to go.
	// Verified stable over ten consecutive runs under the race detector; the margin is deliberately
	// modest because the burst is the slow part of this test and a larger one buys no confidence.
	const burst = 6000
	for i := range burst {
		path := filepath.Join(root, fmt.Sprintf("burst%d.go", i))
		if err := os.WriteFile(path, []byte("package burst\n"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	deadline := time.After(30 * time.Second)
	deltas := 0
	for {
		select {
		case batch, open := <-source.Changes():
			if !open {
				t.Fatalf("the source closed after %d deltas without reporting the loss", deltas)
			}
			if !batch.Rescan {
				deltas++
				continue
			}
			if batch.Reason != index.RescanQueueOverflow {
				t.Fatalf("rescan reason = %q, want %q", batch.Reason, index.RescanQueueOverflow)
			}
			// D6's property, asserted here for the source that cannot reach it through the suite:
			// a consumer must be able to tell "walk the tree" from "apply this delta", and a batch
			// carrying both answers neither question.
			if len(batch.Changes) != 0 {
				t.Fatalf("the overflow rescan also carried %d changes; the two are exclusive",
					len(batch.Changes))
			}
			return
		case <-deadline:
			t.Fatalf("%d writes produced %d deltas and no overflow rescan; "+
				"a burst larger than the queue must report the loss, not drop it", burst, deltas)
		}
	}
}
