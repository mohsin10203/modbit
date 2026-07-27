package index

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// Freshness budget (CTX-2; PRD §7 "Index freshness p95 <10 seconds for local file changes").
//
// The two constants split that budget. A save burst from an editor — write, rename, chmod — arrives
// as several notifications inside a few milliseconds, and reindexing each one separately would cost
// several rescans to reach the state the last one describes. Debounce collapses the burst.
//
// MaxDelay is the part that matters for the SLO. A debounce alone never fires while edits keep
// arriving, so a developer typing continuously in a large file would hold the index at the last
// quiet moment indefinitely — a starvation that presents as "search is stale" and is invisible from
// inside the debounce. The cap bounds the wait regardless of activity, and it is set well under the
// SLO so the rescan and the index write still fit inside it.
const (
	DefaultDebounce = 250 * time.Millisecond
	DefaultMaxDelay = 3 * time.Second
)

// ChangeKind is what a filesystem notification reports.
type ChangeKind string

const (
	// ChangeModified covers creation and writes. The two are not distinguished because the
	// reindexer re-derives a path's classification either way; treating them separately would
	// invite a caller to guess wrong and skip work that must happen.
	ChangeModified ChangeKind = "modified"
	// ChangeRemoved reports a path that no longer exists.
	ChangeRemoved ChangeKind = "removed"
)

// Change is one observed filesystem change.
type Change struct {
	// Path is repository relative.
	Path string
	Kind ChangeKind
	// At is when the change was observed. It is the clock the freshness SLO is measured against, so
	// it is supplied by the caller rather than read here (R-TST-03).
	At time.Time
}

// ChangeSet is the index update one flush produces.
//
// Removals are applied before upserts by any consumer that cares about ordering: a path can appear
// in both when a rename replaces a file with a directory.
type ChangeSet struct {
	// Upserts carry every path whose content or classification changed. Excluded paths never
	// appear here — an excluded path is a removal, never an update.
	Upserts []Entry
	// Removals name paths the index must no longer return. A path is removed when it was deleted,
	// when it became excluded, or when a directory above it became excluded.
	Removals []string
	// FullRescan reports that the set was derived from a walk of the whole tree, so a consumer may
	// treat anything it holds outside the set as absent.
	FullRescan bool
	// RescanReason explains why a full walk happened, empty on an ordinary delta. The flag alone
	// tells a consumer how to apply the set; the reason tells an operator whether the machine is
	// dropping notifications, whether no native watcher is available, or whether this is simply the
	// initial index. Those call for different responses, so they are not collapsed into one bit.
	RescanReason string
}

// Empty reports whether the set would change nothing.
func (c ChangeSet) Empty() bool { return len(c.Upserts) == 0 && len(c.Removals) == 0 }

// FlushPolicy decides when pending changes are due to be applied.
type FlushPolicy struct {
	Debounce time.Duration
	MaxDelay time.Duration
}

// DefaultFlushPolicy returns the policy that meets the freshness SLO.
func DefaultFlushPolicy() FlushPolicy {
	return FlushPolicy{Debounce: DefaultDebounce, MaxDelay: DefaultMaxDelay}
}

// DueAt returns the time at which pending changes must be applied, given when the oldest and the
// newest of them were observed.
//
// The result is the earlier of "the newest change plus the debounce" and "the oldest change plus
// the cap". Taking the earlier is what stops a steady stream of edits from postponing the flush
// forever.
func (p FlushPolicy) DueAt(oldest, newest time.Time) time.Time {
	debounced := newest.Add(p.Debounce)
	capped := oldest.Add(p.MaxDelay)
	if capped.Before(debounced) {
		return capped
	}
	return debounced
}

// fileState is what the reindexer remembers about a path it has already seen.
//
// It is deliberately smaller than an Entry: a reindexer for a large monorepo holds one of these per
// path, and the fields it drops — reason, detail, provenance — are re-derived on every scan anyway.
type fileState struct {
	size        int64
	modTime     time.Time
	disposition Disposition
	isDir       bool
}

func (s fileState) matches(e Entry) bool {
	return s.disposition == e.Disposition && s.size == e.Size && s.modTime.Equal(e.ModTime)
}

// Reindexer turns filesystem changes into index updates (CTX-1, CTX-2).
//
// It holds what the tree contained at the last scan and rescans only the directories a change could
// have affected. The scope rules are the whole design:
//
//   - An edited file affects its own directory's listing and nothing else, so its directory is
//     rescanned without descending.
//   - A changed ignore file affects every path beneath it, so its directory is rescanned in full.
//     This is the case that matters for CTX-4: adding `secrets/` to `.modbitignore` must retract
//     content that is already indexed, not merely stop future indexing of it.
//   - A changed directory is rescanned in full, because a notification about a directory says
//     nothing about what appeared inside it.
//
// A Reindexer is safe for concurrent use. Observe never blocks on a scan, so a watcher feeding it
// cannot be stalled by a flush and let the operating system's own queue overflow.
type Reindexer struct {
	walker *Walker
	policy FlushPolicy

	// worktree is nil for a tree that is not under version control, which is a supported case: a
	// directory with no checkout is indexed without revision awareness rather than refused.
	worktree *Worktree

	mu      sync.Mutex
	state   map[string]fileState
	pending map[string]Change
	// oldest is when the oldest pending change was observed, for the freshness SLO.
	oldest, newest time.Time
	scanned        bool
	// revision is the tree state the current index corresponds to (CTX-3).
	revision Revision
}

// BindWorktree makes the reindexer revision-aware (CTX-3).
//
// Once bound, an incremental flush verifies that the checkout is still the one the index was built
// from and refuses to apply deltas across a branch switch. Nothing else changes: a tree with no
// checkout indexes exactly as before.
func (r *Reindexer) BindWorktree(w *Worktree) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.worktree = w
	// The binding invalidates any state gathered before it, since that state was never checked
	// against a revision.
	r.scanned = false
}

// Revision reports the tree state the current index corresponds to.
func (r *Reindexer) Revision() Revision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revision
}

// NewReindexer returns a Reindexer over a tree. The zero FlushPolicy selects the defaults.
func NewReindexer(walker *Walker, policy FlushPolicy) (*Reindexer, error) {
	if walker == nil {
		return nil, modberr.New(modberr.CodeInvalidArgument, "reindexer requires a walker").
			WithDetail("field", "walker")
	}
	if policy.Debounce <= 0 {
		policy.Debounce = DefaultDebounce
	}
	if policy.MaxDelay <= 0 {
		policy.MaxDelay = DefaultMaxDelay
	}
	if policy.MaxDelay < policy.Debounce {
		return nil, modberr.New(modberr.CodeInvalidArgument,
			"flush max delay must not be shorter than the debounce").
			WithDetail("field", "policy.MaxDelay")
	}
	return &Reindexer{
		walker:  walker,
		policy:  policy,
		state:   make(map[string]fileState),
		pending: make(map[string]Change),
	}, nil
}

// Observe records changes without applying them.
//
// Repeated changes to one path collapse: the index only ever reflects a path's current state, so
// remembering that it changed twice would buy nothing. The observation time of the first one is
// kept, because that is when the index started being stale.
func (r *Reindexer) Observe(changes ...Change) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range changes {
		c.Path = normalizePath(c.Path)
		if c.Path == "" {
			continue
		}
		if c.At.IsZero() {
			c.At = time.Now()
		}
		if prev, ok := r.pending[c.Path]; ok {
			c.At = prev.At
		}
		r.pending[c.Path] = c
		if r.oldest.IsZero() || c.At.Before(r.oldest) {
			r.oldest = c.At
		}
		if c.At.After(r.newest) {
			r.newest = c.At
		}
	}
}

// Pending reports how many changes await application and when the oldest was observed.
//
// A zero time means nothing is pending. The status surface subtracts it from now to show index
// freshness, which is the number CTX-2 is asserted against.
func (r *Reindexer) Pending() (count int, oldest time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending), r.oldest
}

// DueAt reports when the pending changes must be flushed, or the zero time when none are pending.
func (r *Reindexer) DueAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 {
		return time.Time{}
	}
	return r.policy.DueAt(r.oldest, r.newest)
}

// Rescan walks the whole tree and returns everything that differs from the last known state.
//
// It is both the initial index and the recovery path. An operating-system watcher drops
// notifications when its queue overflows, and a reindexer that kept applying deltas after a drop
// would diverge from the tree with nothing to reveal it — so an overflow must resolve to this, and
// the resulting ChangeSet says FullRescan so the degradation is not silent (SDD §15).
func (r *Reindexer) Rescan(ctx context.Context) (ChangeSet, Report, error) {
	// Read before the walk, not after: a revision captured afterwards would name a tree state that
	// the scan may not have seen, and the next flush would compare against it and find no
	// divergence to report.
	revision, err := r.currentRevision()
	if err != nil {
		return ChangeSet{}, Report{}, err
	}

	observed := make(map[string]Entry)
	report, err := r.walker.Walk(ctx, func(e Entry) error {
		observed[e.Path] = e
		return nil
	})
	if err != nil {
		return ChangeSet{}, report, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	set := r.reconcile(observed, func(known string) bool { return true })
	set.FullRescan = true
	r.scanned = true
	r.revision = revision
	// A full walk supersedes every pending change: it observed the tree as it is now.
	clear(r.pending)
	r.oldest, r.newest = time.Time{}, time.Time{}
	return set, report, nil
}

// Flush applies every pending change and returns the resulting index update.
//
// The scans run without the lock held, so changes observed while a flush is in progress stay
// pending and are picked up by the next one. That can leave the index one flush behind a change
// that lands mid-scan, which the freshness budget accounts for; blocking the watcher instead would
// risk losing notifications entirely.
func (r *Reindexer) Flush(ctx context.Context) (ChangeSet, Report, error) {
	r.mu.Lock()
	if !r.scanned {
		r.mu.Unlock()
		// Applying deltas to a state that was never established would record a tree consisting of
		// whatever happened to change, and report it as an index.
		return ChangeSet{}, Report{}, modberr.New(modberr.CodeRunStateInvalid,
			"reindexer requires an initial Rescan before changes can be applied")
	}
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return ChangeSet{}, Report{}, nil
	}
	indexed := r.revision
	changes := make([]Change, 0, len(r.pending))
	for _, c := range r.pending {
		changes = append(changes, c)
	}
	clear(r.pending)
	r.oldest, r.newest = time.Time{}, time.Time{}
	r.mu.Unlock()

	// CTX-3, and the zero-contamination budget in PRD §7. A checkout rewrites the working tree in
	// bulk, far faster than a notification queue drains, so the changes this flush holds cannot be
	// assumed to describe it. Applying them would merge one branch's content into the other's
	// index, and nothing downstream could tell the difference afterwards.
	current, err := r.currentRevision()
	if err != nil {
		r.Observe(changes...)
		return ChangeSet{}, Report{}, err
	}
	if !current.Equal(indexed) {
		r.Observe(changes...)
		return ChangeSet{}, Report{}, modberr.New(modberr.CodeSnapshotDiverged,
			"the checkout changed since the index was built; a full rescan is required").
			WithDetails(map[string]string{
				"expected_revision": indexed.Commit,
				"actual_revision":   current.Commit,
				"resource_type":     "index_worktree",
			})
	}

	scopes := r.scopes(changes)
	observed := make(map[string]Entry)
	var report Report
	for _, s := range scopes {
		var (
			rep Report
			err error
		)
		collect := func(e Entry) error {
			observed[e.Path] = e
			return nil
		}
		if s.recursive {
			rep, err = r.walker.WalkSubtree(ctx, s.dir, collect)
		} else {
			rep, err = r.walker.WalkDirectory(ctx, s.dir, collect)
		}
		if err != nil {
			// The changes are already drained. Putting them back keeps the next flush correct
			// rather than losing the scopes this one failed to cover.
			r.Observe(changes...)
			return ChangeSet{}, report, err
		}
		report.merge(rep)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reconcile(observed, inScopes(scopes)), report, nil
}

// currentRevision reads the checkout's revision, or the zero Revision when the tree is not under
// version control.
func (r *Reindexer) currentRevision() (Revision, error) {
	r.mu.Lock()
	w := r.worktree
	r.mu.Unlock()
	if w == nil {
		return Revision{}, nil
	}
	return w.Revision()
}

// scope is one directory a flush must rescan.
type scope struct {
	dir       string
	recursive bool
}

// scopes reduces changes to the directories that must be rescanned.
//
// A scope contained in another recursive scope is dropped: rescanning `a` in full already covers
// `a/b`, and scanning it twice would produce the same entries at twice the cost.
func (r *Reindexer) scopes(changes []Change) []scope {
	byDir := make(map[string]bool, len(changes))
	for _, c := range changes {
		dir, recursive := r.scopeOf(c)
		if was, ok := byDir[dir]; !ok || (recursive && !was) {
			byDir[dir] = recursive
		}
	}

	out := make([]scope, 0, len(byDir))
	for dir, recursive := range byDir {
		out = append(out, scope{dir: dir, recursive: recursive})
	}
	// Shallowest first, so the containment check below only ever looks backwards, and so a flush
	// scans in a stable order.
	sort.Slice(out, func(i, j int) bool {
		if a, b := strings.Count(out[i].dir, "/"), strings.Count(out[j].dir, "/"); a != b {
			return a < b
		}
		return out[i].dir < out[j].dir
	})

	kept := out[:0]
	for _, s := range out {
		if !coveredBy(kept, s.dir) {
			kept = append(kept, s)
		}
	}
	return kept
}

// scopeOf returns the directory a single change requires rescanning, and whether it must recurse.
func (r *Reindexer) scopeOf(c Change) (dir string, recursive bool) {
	name := path.Base(c.Path)
	for _, ig := range IgnoreFiles {
		if name == ig.Name {
			// The rules beneath this file changed, so every verdict beneath it is suspect.
			return parentDir(c.Path), true
		}
	}
	// A removed path cannot be stat'd, so the state is the only record of what it was — and it only
	// records directories that were *excluded*, since an included one is never reported on its own.
	// So "not known" cannot be distinguished from "was a directory", and the parent is rescanned in
	// full unless the state positively says the path was a file.
	//
	// The alternative — assuming it was a directory and retracting everything beneath its path —
	// would empty part of the index on a spurious removal notification for a directory that still
	// exists. Retraction here is always driven by what a scan observed, never by what a
	// notification claimed.
	if c.Kind == ChangeRemoved {
		known, ok := r.state[c.Path]
		return parentDir(c.Path), !ok || known.isDir
	}
	// A directory is rescanned in full. A notification naming a directory says nothing about what
	// appeared inside it, and a shallow scan of its parent skips subdirectories entirely — so
	// treating a newly created directory as an ordinary file would leave everything in it
	// unindexed until something else forced a rescan.
	if r.isDirOnDisk(c.Path) {
		return c.Path, true
	}
	return parentDir(c.Path), false
}

// isDirOnDisk reports whether a path is currently a directory.
//
// Lstat, not Stat: a symlink to a directory is not a directory here, because the walk does not
// resolve links and rescanning through one would index a tree that is not in this repository.
func (r *Reindexer) isDirOnDisk(rel string) bool {
	info, err := os.Lstat(filepath.Join(r.walker.root, filepath.FromSlash(rel)))
	return err == nil && info.IsDir()
}

func parentDir(p string) string {
	dir := path.Dir(p)
	if dir == "." {
		return ""
	}
	return dir
}

func coveredBy(scopes []scope, dir string) bool {
	for _, s := range scopes {
		if !s.recursive {
			continue
		}
		if s.dir == "" || dir == s.dir || strings.HasPrefix(dir, s.dir+"/") {
			return true
		}
	}
	return false
}

// inScopes returns a predicate reporting whether a known path fell inside this flush's scans, and
// so whether its absence from the observations means it is gone.
//
// A path outside every scanned scope was simply not looked at. Treating it as deleted is how an
// incremental reindex silently empties an index.
func inScopes(scopes []scope) func(string) bool {
	return func(known string) bool {
		for _, s := range scopes {
			if s.recursive {
				if s.dir == "" || known == s.dir || strings.HasPrefix(known, s.dir+"/") {
					return true
				}
				continue
			}
			// A shallow scan listed only this directory's own entries, and skipped subdirectories
			// entirely, so it says nothing about a subdirectory's fate.
			if parentDir(known) == s.dir {
				return true
			}
		}
		return false
	}
}

// reconcile diffs observations against the remembered state and updates it.
//
// covered reports whether a known path was inside the scanned region; only those can be concluded
// missing.
func (r *Reindexer) reconcile(observed map[string]Entry, covered func(string) bool) ChangeSet {
	var set ChangeSet

	for p, e := range observed {
		prev, known := r.state[p]
		if e.Disposition == DispositionExclude {
			// An excluded path is never an upsert. When it was indexed before, the exclusion has to
			// reach back and retract it — that is what makes a new ignore rule take effect on
			// content already in the index rather than only on content indexed after it.
			if known && prev.disposition != DispositionExclude {
				set.Removals = append(set.Removals, p)
			}
		} else if !known || !prev.matches(e) {
			set.Upserts = append(set.Upserts, e)
		}
		r.state[p] = fileState{
			size:        e.Size,
			modTime:     e.ModTime,
			disposition: e.Disposition,
			isDir:       e.IsDir,
		}
	}

	for p, prev := range r.state {
		if _, seen := observed[p]; seen || !covered(p) {
			continue
		}
		if prev.disposition != DispositionExclude {
			set.Removals = append(set.Removals, p)
		}
		delete(r.state, p)
	}

	// Deterministic output: two reindexers given the same changes must produce the same set, or a
	// recorded index update is not reproducible evidence.
	slices.SortFunc(set.Upserts, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	slices.Sort(set.Removals)
	return set
}

// merge folds one scan's report into an accumulated one.
func (r *Report) merge(other Report) {
	r.Stats.Directories += other.Stats.Directories
	r.Stats.Pruned += other.Stats.Pruned
	r.Stats.Files += other.Stats.Files
	r.Stats.Indexed += other.Stats.Indexed
	r.Stats.Referenced += other.Stats.Referenced
	r.Stats.Excluded += other.Stats.Excluded
	r.Stats.IgnoreFiles += other.Stats.IgnoreFiles
	r.Diagnostics = append(r.Diagnostics, other.Diagnostics...)
	r.Suppressed += other.Suppressed
}
