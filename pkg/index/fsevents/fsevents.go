//go:build darwin && cgo

// Package fsevents implements index.ChangeSource on macOS using FSEvents.
//
// Boundary: it reports what changed beneath one tree. It does not classify, index, or read file
// contents — that is the Reindexer's work, reached through the ChangeSource port.
//
// Requirements: CTX-2 (file changes must become searchable within the freshness SLO). It lives in
// its own package so that `pkg/index` stays free of cgo and keeps the import boundary its own
// guard test enforces.
//
// # Why FSEvents rather than kqueue
//
// kqueue — which is what portable Go watcher libraries use on macOS — needs an open descriptor per
// watched *file*. `kern.maxfilesperproc` is 10240 on this platform, so that design tops out around
// ten thousand files, which is the boundary between PRD §8A.3's Small and Standard repository
// classes. A watcher that fails at the size where the product's own scale targets begin is not a
// watcher.
//
// FSEvents takes one stream for a whole tree at any depth and costs no per-file descriptor.
// Measured on macOS 26.5: a write anywhere in a nested tree notified in a median of 49 ms against a
// 50 ms stream latency, versus CTX-2's 10-second budget.
package fsevents

/*
#cgo LDFLAGS: -framework CoreServices
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// DefaultLatency is how long FSEvents may batch before delivering.
//
// It trades notification delay against callback volume. At 50 ms a single edit still arrives well
// inside CTX-2's budget while a bulk change — a branch switch, a build — is coalesced into far
// fewer callbacks than the file count.
const DefaultLatency = 50 * time.Millisecond

// queueDepth bounds the buffer between the FSEvents callback and the Go sender.
//
// Overflow is not dropped silently: it converts to a rescan, which is exactly what the kernel's own
// overflow flags mean. A source that quietly lost changes would leave the index confidently wrong,
// which is the failure the ChangeSource contract exists to make impossible.
const queueDepth = 4096

// FSEvents flag bits. Declared here rather than read through cgo at each use so the mapping from
// kernel flag to Modbit meaning is readable in one place.
const (
	flagMustScanSubDirs = 0x00000001
	flagUserDropped     = 0x00000002
	flagKernelDropped   = 0x00000004
	flagRootChanged     = 0x00000020
	flagItemRemoved     = 0x00000200
	flagItemRenamed     = 0x00000800
)

// Source is a macOS ChangeSource.
type Source struct {
	root    string
	changes chan index.ChangeBatch
	stop    chan struct{}
	closeOn sync.Once

	// queue carries events from the dispatch-queue callback to the sender goroutine. The callback
	// must not block: FSEvents delivers on a serial queue, so a slow callback delays every later
	// notification.
	queue chan event
	// overflow records that the queue was full, so the loss becomes a rescan rather than silence.
	overflow chan struct{}

	stream C.FSEventStreamRef
	handle uintptr
}

type event struct {
	path  string
	flags int
}

var _ index.ChangeSource = (*Source)(nil)

// registry maps a handle to its Source. cgo forbids holding a Go pointer in C, so the stream
// carries an integer and the callback looks the source up here.
var registry = struct {
	sync.Mutex
	next    uintptr
	sources map[uintptr]*Source
}{sources: map[uintptr]*Source{}}

// New starts watching root and returns a ChangeSource.
//
// latency of zero selects DefaultLatency.
func New(root string, latency time.Duration) (*Source, error) {
	if latency <= 0 {
		latency = DefaultLatency
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "cannot watch a path that cannot be read").
			WithDetail("field", "root")
	}
	if !info.IsDir() {
		return nil, modberr.New(modberr.CodeInvalidArgument, "a change source watches a directory").
			WithDetail("field", "root")
	}
	// FSEvents reports *resolved* paths: a stream over /var/folders/x delivers /private/var/folders/x.
	// Resolving the root here is what lets the delivered path be made relative to it. Skipping this
	// is the same defect that made the sandbox profile's subpath rules miss (B-14) — macOS resolves
	// symlinks before it matches, and code that compares unresolved paths silently matches nothing.
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "cannot resolve the watched root").
			WithDetail("field", "root")
	}

	s := &Source{
		root:     resolved,
		changes:  make(chan index.ChangeBatch),
		stop:     make(chan struct{}),
		queue:    make(chan event, queueDepth),
		overflow: make(chan struct{}, 1),
	}

	registry.Lock()
	registry.next++
	s.handle = registry.next
	registry.sources[s.handle] = s
	registry.Unlock()

	cRoot := C.CString(resolved)
	defer C.free(unsafe.Pointer(cRoot))
	s.stream = C.modbit_fsevents_start(cRoot, C.double(latency.Seconds()), C.uintptr_t(s.handle))
	if s.stream == nil {
		s.unregister()
		return nil, modberr.New(modberr.CodeInternal, "the platform change stream could not be started")
	}

	go s.run()
	return s, nil
}

func (s *Source) unregister() {
	registry.Lock()
	delete(registry.sources, s.handle)
	registry.Unlock()
}

// deliver is called from the FSEvents callback. It never blocks.
func (s *Source) deliver(path string, flags int) {
	select {
	case s.queue <- event{path: path, flags: flags}:
	default:
		// The buffer is full. Record it once; the sender turns it into a rescan.
		select {
		case s.overflow <- struct{}{}:
		default:
		}
	}
}

// run translates queued events into batches.
func (s *Source) run() {
	defer close(s.changes)
	for {
		select {
		case <-s.stop:
			return
		case <-s.overflow:
			if !s.send(index.ChangeBatch{Rescan: true, Reason: index.RescanQueueOverflow}) {
				return
			}
		case e := <-s.queue:
			batch, ok := s.translate(e)
			if !ok {
				continue
			}
			if !s.send(batch) {
				return
			}
		}
	}
}

// send delivers a batch, abandoning it if the source is closing.
//
// The stop case is what makes Close return without a reader (D4): a sender parked on an unbuffered
// channel with nobody receiving would otherwise hold shutdown open indefinitely.
func (s *Source) send(batch index.ChangeBatch) bool {
	select {
	case s.changes <- batch:
		return true
	case <-s.stop:
		return false
	}
}

// translate converts one FSEvents notification into a batch.
//
// It returns ok=false for an event that carries nothing a consumer can act on, rather than sending
// an empty delta — a batch with no changes and no rescan reason tells the watcher to do nothing and
// costs it a wakeup.
func (s *Source) translate(e event) (index.ChangeBatch, bool) {
	// The kernel's own loss signals. MustScanSubDirs is FSEvents saying it could not keep up and the
	// subtree must be walked; dropped events mean the same from the user-space or kernel queue.
	if e.flags&(flagMustScanSubDirs|flagUserDropped|flagKernelDropped) != 0 {
		return index.ChangeBatch{Rescan: true, Reason: index.RescanQueueOverflow}, true
	}
	// The watched directory itself moved or was replaced. Nothing about the previous tree can be
	// trusted, and the paths that follow would be relative to a root that no longer means the same
	// thing.
	if e.flags&flagRootChanged != 0 {
		return index.ChangeBatch{Rescan: true, Reason: index.RescanSourceRestart}, true
	}

	rel, ok := s.relative(e.path)
	if !ok {
		return index.ChangeBatch{}, false
	}

	// The flags are cumulative for a path within a batching window: a file created and then deleted
	// arrives with both bits set, and a rename sets neither reliably on both ends. So the filesystem
	// decides, and the flags only hint. Trusting them instead is how a deleted file stays in the
	// index looking like a live result.
	kind := index.ChangeModified
	if _, err := os.Lstat(e.path); err != nil {
		if !os.IsNotExist(err) {
			// Unreadable but present — a permission change, most likely. It cannot be indexed, and
			// treating it as removed is the honest outcome: it is no longer retrievable content.
			return index.ChangeBatch{Changes: []index.Change{{
				Path: rel, Kind: index.ChangeRemoved, At: time.Now(),
			}}}, true
		}
		kind = index.ChangeRemoved
	} else if e.flags&(flagItemRemoved|flagItemRenamed) != 0 {
		// The path exists, so a rename landed here rather than leaving. Modified is correct.
		kind = index.ChangeModified
	}

	return index.ChangeBatch{Changes: []index.Change{{
		Path: rel, Kind: kind, At: time.Now(),
	}}}, true
}

// relative makes an absolute FSEvents path repository relative.
//
// A path outside the watched root is discarded rather than passed on. FSEvents should not deliver
// one, but a path that escaped the root would become a Change the reindexer resolves against the
// repository — which is how a watcher turns into a way to read files outside it.
func (s *Source) relative(abs string) (string, bool) {
	rel, err := filepath.Rel(s.root, abs)
	if err != nil {
		return "", false
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// Changes implements index.ChangeSource.
func (s *Source) Changes() <-chan index.ChangeBatch { return s.changes }

// Close implements index.ChangeSource.
func (s *Source) Close() error {
	s.closeOn.Do(func() {
		close(s.stop)
		C.modbit_fsevents_stop(s.stream)
		s.stream = nil
		s.unregister()
	})
	return nil
}

//export goFSEventsDeliver
func goFSEventsDeliver(handle C.uintptr_t, path *C.char, flags C.int) {
	registry.Lock()
	s := registry.sources[uintptr(handle)]
	registry.Unlock()
	if s == nil {
		// The source closed between the kernel queuing this event and the callback running. There is
		// nothing to deliver it to, and no error to report to anyone.
		return
	}
	s.deliver(C.GoString(path), int(flags))
}
