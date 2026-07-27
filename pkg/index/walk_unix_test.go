//go:build unix

package index_test

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/index"
)

// Opening a FIFO blocks until a writer appears. Any contributor can commit one, so an indexer that
// opened whatever it found would hang on a path chosen by someone else. The walk decides a file's
// kind from the directory entry, before anything is opened.
func TestSecurityWalkDoesNotOpenIrregularFiles(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{"src/main.go": "package main"})
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	w, err := index.NewWalker(root, classifier(t, config(), nil), index.WalkOptions{})
	if err != nil {
		t.Fatalf("NewWalker: %v", err)
	}

	type result struct {
		entries []index.Entry
		err     error
	}
	done := make(chan result, 1)
	go func() {
		var entries []index.Entry
		_, err := w.Walk(context.Background(), func(e index.Entry) error {
			entries = append(entries, e)
			return nil
		})
		done <- result{entries, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Walk: %v", got.err)
		}
		byName := byPath(got.entries)
		e, ok := byName["pipe"]
		if !ok {
			t.Fatal("the FIFO was not reported at all")
		}
		if e.Disposition != index.DispositionExclude || e.Reason != index.ReasonNotRegular {
			t.Errorf("pipe = %s/%s, want exclude/not_regular", e.Disposition, e.Reason)
		}
		if !byName["src/main.go"].Indexable() {
			t.Error("the rest of the tree should still be indexed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the walk blocked, which means it opened the FIFO")
	}
}
