//go:build linux

// Package inotify implements index.ChangeSource on Linux using inotify.
//
// Boundary: it reports what changed beneath one tree. It does not classify, index, or read file
// contents — that is the Reindexer's work, reached through the ChangeSource port.
//
// Requirements: CTX-2 (file changes must become searchable within the freshness SLO). It lives in
// its own package for symmetry with `pkg/index/fsevents`, so `pkg/index` keeps the import boundary
// its own guard test enforces.
//
// # Why the standard library rather than a watcher module
//
// `syscall` carries the whole inotify interface on Linux — `InotifyInit1`, `InotifyAddWatch`,
// `InotifyRmWatch`, and the event struct. There is nothing a third-party module adds here except its
// own portability layer, which is the layer this repository replaced with `ChangeSource`. So `go.mod`
// is unchanged at one dependency, and ADR-0104's note that fsnotify was "adoptable here" turns out
// not to be needed.
//
// # What inotify costs that FSEvents does not
//
// inotify is **not recursive**. One watch covers one directory, so the tree is walked at startup and
// every directory created afterwards adds a watch. That makes watch descriptors a budget: the kernel
// caps them per user at `fs.inotify.max_user_watches`, commonly 8192 on desktop distributions and
// often 524288 on developer machines that have raised it. Exhaustion is reported, never absorbed —
// see the two ENOSPC paths below, which differ because only one of them can still fall back.
package inotify

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/modberr"
)

// eventMask is what the source asks the kernel for.
//
// `IN_CLOSE_WRITE` rather than `IN_MODIFY` alone: a writer that flushes repeatedly produces one
// event per flush under IN_MODIFY, and the interesting moment for an index is when the file is
// closed. Both are requested because an editor that writes through a rename never closes the
// original path, and IN_MOVED_TO is what carries that case.
const eventMask = syscall.IN_CREATE |
	syscall.IN_DELETE |
	syscall.IN_MODIFY |
	syscall.IN_CLOSE_WRITE |
	syscall.IN_MOVED_FROM |
	syscall.IN_MOVED_TO |
	syscall.IN_DELETE_SELF |
	syscall.IN_MOVE_SELF

// readBuffer holds one read's worth of events. NAME_MAX is 255, so the largest single event is 271
// bytes; this batches many without a syscall per event.
const readBuffer = 64 * 1024

// newDirectoryFileCap bounds how many files a newly created directory may contribute as individual
// changes before the source gives up and asks for a rescan.
//
// A directory that appears after startup was populated before its watch existed, so its contents
// have to be discovered by walking it. That walk is unbounded — `git checkout` of a large subtree is
// one create event — and turning a hundred thousand files into a hundred thousand changes would cost
// more than the rescan it is trying to avoid.
const newDirectoryFileCap = 1024

// Source is a Linux ChangeSource.
type Source struct {
	root    string
	file    *os.File
	changes chan index.ChangeBatch
	stop    chan struct{}
	closeOn sync.Once

	// mu guards watches. The reader goroutine adds and removes entries as directories come and go,
	// and Close reads it to release descriptors.
	mu      sync.Mutex
	watches map[int32]string
}

var _ index.ChangeSource = (*Source)(nil)

// New starts watching root and returns a ChangeSource.
//
// It returns MODBIT_CAPABILITY_UNAVAILABLE when the kernel's watch budget cannot cover the tree, so
// that a caller falls back to polling rather than running a watcher with holes in it. See
// `pkg/index/changesource`, which is what reads that distinction.
func New(root string) (*Source, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "cannot watch a path that cannot be read").
			WithDetail("field", "root")
	}
	if !info.IsDir() {
		return nil, modberr.New(modberr.CodeInvalidArgument, "a change source watches a directory").
			WithDetail("field", "root")
	}
	// Resolved for the same reason FSEvents resolves its root: `Change.Path` is repository relative,
	// and a root that does not match the paths being reported strips nothing.
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "cannot resolve the watched root").
			WithDetail("field", "root")
	}

	// IN_NONBLOCK is what makes the descriptor pollable, which is what lets os.File hand it to the
	// runtime poller. That in turn is what makes Close interrupt a blocked Read (D4, D8) — without
	// it the reader parks in the kernel and no amount of channel signalling reaches it.
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInternal, "the platform change stream could not be started")
	}

	s := &Source{
		root:    resolved,
		file:    os.NewFile(uintptr(fd), "inotify"),
		changes: make(chan index.ChangeBatch),
		stop:    make(chan struct{}),
		watches: map[int32]string{},
	}

	if err := s.watchTree(resolved); err != nil {
		_ = s.file.Close()
		return nil, err
	}

	go s.run()
	return s, nil
}

// watchTree adds a watch for dir and every directory beneath it.
//
// Symlinked directories are not followed. The walker that feeds the index refuses to follow them
// (CTX-4), and a watcher that did would report changes for paths outside the repository — which is
// how a change source becomes a way to observe files the index will never hold.
func (s *Source) watchTree(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory that vanished mid-walk is not an error: it is a change, and the watch on its
			// parent will report it. A permission error is skipped for the same reason the walker skips
			// one — an unreadable subtree is not indexable either.
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil
			}
			return modberr.Wrap(err, modberr.CodeInternal, "the watched tree could not be walked")
		}
		if !d.IsDir() {
			return nil
		}
		return s.addWatch(path)
	})
}

func (s *Source) addWatch(dir string) error {
	wd, err := syscall.InotifyAddWatch(int(s.file.Fd()), dir, eventMask)
	if err != nil {
		if errors.Is(err, syscall.ENOSPC) {
			// The kernel's per-user watch limit. At construction this is recoverable by the caller —
			// polling is worse but complete — so it is reported as an unavailable capability rather
			// than a fault, and `changesource` degrades instead of failing the watch entirely.
			return modberr.Wrap(err, modberr.CodeCapabilityUnavailable,
				"the kernel watch limit cannot cover this tree (fs.inotify.max_user_watches)")
		}
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil
		}
		return modberr.Wrap(err, modberr.CodeInternal, "a directory could not be watched")
	}
	s.mu.Lock()
	s.watches[int32(wd)] = dir
	s.mu.Unlock()
	return nil
}

func (s *Source) pathFor(wd int32) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, ok := s.watches[wd]
	return dir, ok
}

func (s *Source) forget(wd int32) {
	s.mu.Lock()
	delete(s.watches, wd)
	s.mu.Unlock()
}

// run reads events until the source is closed.
func (s *Source) run() {
	defer close(s.changes)
	buf := make([]byte, readBuffer)
	for {
		n, err := s.file.Read(buf)
		if err != nil {
			// Close interrupted the read, or the descriptor died. Either way there is nothing further
			// to report, and the deferred close of s.changes is what tells the consumer (D2).
			return
		}
		for _, batch := range s.translate(buf[:n]) {
			if !s.send(batch) {
				return
			}
		}
	}
}

// send delivers a batch, abandoning it if the source is closing.
func (s *Source) send(batch index.ChangeBatch) bool {
	select {
	case s.changes <- batch:
		return true
	case <-s.stop:
		return false
	}
}

// translate converts one read's raw events into batches.
func (s *Source) translate(raw []byte) []index.ChangeBatch {
	var batches []index.ChangeBatch
	var changes []index.Change
	observed := time.Now()

	for offset := 0; offset+syscall.SizeofInotifyEvent <= len(raw); {
		event := (*syscall.InotifyEvent)(unsafe.Pointer(&raw[offset]))
		nameLen := int(event.Len)
		next := offset + syscall.SizeofInotifyEvent + nameLen
		if next > len(raw) {
			break
		}
		name := ""
		if nameLen > 0 {
			name = strings.TrimRight(string(raw[offset+syscall.SizeofInotifyEvent:next]), "\x00")
		}
		offset = next

		// The kernel dropped events. This is the condition the whole recovery path exists for, and it
		// supersedes anything else in this read: the source cannot say what it missed.
		if event.Mask&syscall.IN_Q_OVERFLOW != 0 {
			return []index.ChangeBatch{{Rescan: true, Reason: index.RescanQueueOverflow}}
		}

		dir, known := s.pathFor(event.Wd)
		if !known {
			// A watch removed between the kernel queuing this event and the read. Nothing can be said
			// about a path that cannot be reconstructed, and inventing one would be worse.
			continue
		}

		// The watched directory itself went away. IN_IGNORED follows and the descriptor is already
		// invalid, so the entry is dropped either way.
		if event.Mask&(syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF) != 0 {
			s.forget(event.Wd)
			if dir == s.root {
				// The root moved out from under the stream. Nothing below it can be trusted, and the
				// paths that follow would be relative to a root that no longer means the same thing.
				return []index.ChangeBatch{{Rescan: true, Reason: index.RescanSourceRestart}}
			}
			continue
		}
		if event.Mask&syscall.IN_IGNORED != 0 {
			s.forget(event.Wd)
			continue
		}

		abs := dir
		if name != "" {
			abs = filepath.Join(dir, name)
		}

		// A new directory was populated before its watch existed, so its contents have to be
		// discovered rather than waited for.
		if event.Mask&syscall.IN_ISDIR != 0 && event.Mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0 {
			discovered, overflowed := s.adoptDirectory(abs, observed)
			if overflowed {
				return []index.ChangeBatch{{Rescan: true, Reason: index.RescanQueueOverflow}}
			}
			changes = append(changes, discovered...)
			continue
		}
		if event.Mask&syscall.IN_ISDIR != 0 {
			// A removed directory needs no change of its own: the files beneath it arrive as their
			// own events, and the index holds files rather than directories.
			continue
		}

		rel, ok := s.relative(abs)
		if !ok {
			continue
		}
		changes = append(changes, index.Change{Path: rel, Kind: s.kind(abs), At: observed})
	}

	if len(changes) > 0 {
		batches = append(batches, index.ChangeBatch{Changes: changes})
	}
	return batches
}

// kind decides whether a path was modified or removed.
//
// The filesystem is the authority and the mask is not consulted at all. FSEvents needs the mask as a
// hint because it coalesces flags per path within a batching window; inotify does not, and once the
// path has been stat'ed every mask branch gives the same answer — a rename that landed here exists, a
// rename that left does not, and a create-then-delete inside one read is simply gone. Reading the
// mask as well would look like corroboration while adding none, which is worse than not reading it.
//
// Trusting the mask instead of the filesystem is how a deleted file stays in the index looking like
// a live result.
func (s *Source) kind(abs string) index.ChangeKind {
	if _, err := os.Lstat(abs); err != nil {
		// Gone, or present but unreadable after a permission change. Either way it is no longer
		// retrievable content, and reporting it as removed is the honest outcome.
		return index.ChangeRemoved
	}
	return index.ChangeModified
}

// adoptDirectory watches a newly created directory and reports the files already inside it.
//
// It returns overflowed=true when the subtree is larger than newDirectoryFileCap, in which case the
// caller asks for a rescan instead: past that size a walk is the cheaper answer anyway, and claiming
// a partial list would be worse than admitting the source cannot enumerate it.
func (s *Source) adoptDirectory(dir string, observed time.Time) (changes []index.Change, overflowed bool) {
	if err := s.watchTree(dir); err != nil {
		// Including ENOSPC: mid-run there is nobody left to fall back to, so the loss becomes a
		// rescan rather than an error nobody is positioned to handle.
		return nil, true
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		if len(changes) >= newDirectoryFileCap {
			return filepath.SkipAll
		}
		rel, ok := s.relative(path)
		if !ok {
			return nil
		}
		changes = append(changes, index.Change{Path: rel, Kind: index.ChangeModified, At: observed})
		return nil
	})
	if err != nil || len(changes) >= newDirectoryFileCap {
		return nil, true
	}
	return changes, false
}

// relative makes an absolute path repository relative.
//
// A path outside the watched root is discarded rather than passed on — that is how a watcher would
// otherwise turn into a way to reach files outside the tree it was given.
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
//
// Closing the file interrupts the reader's blocked Read through the runtime poller, which is what
// releases the goroutine (D9) rather than abandoning it.
func (s *Source) Close() error {
	s.closeOn.Do(func() {
		close(s.stop)
		_ = s.file.Close()
		s.mu.Lock()
		s.watches = map[int32]string{}
		s.mu.Unlock()
	})
	return nil
}
