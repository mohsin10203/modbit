package index

import (
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// vcsMetadataDirs are directories that hold version-control state rather than source.
//
// They are pruned by name because they are not source in any language, they dwarf the tree they
// sit in, and `.git/config` routinely carries a remote URL with an embedded token. Indexing one
// would put a credential into a retrievable index, which INV-11 forbids.
var vcsMetadataDirs = []string{".git", ".hg", ".svn", ".bzr"}

// Walk limits. They bound the work a single tree can demand; none of them is a policy choice, so
// none is a setting. A tree that trips one is malformed or hostile, not merely large.
const (
	// defaultMaxDepth bounds recursion. Real source trees are far shallower; a tree deeper than
	// this is a symlink loop materialized by a checkout or a generator gone wrong.
	defaultMaxDepth = 64
	// maxIgnoreFileBytes bounds a single ignore file. Ignore files are hand written; one larger
	// than this is not something a person typed.
	maxIgnoreFileBytes = 1 << 20
	// defaultMaxDiagnostics bounds the report. A tree with a million unreadable files must not turn
	// a walk report into a memory problem; the count keeps the loss visible.
	defaultMaxDiagnostics = 1000
)

// Diagnostic reasons. A walk that could not do its job says so rather than returning a quietly
// smaller tree (R-ERR-05).
const (
	// DiagIgnoreFileUnreadable means an ignore file existed but could not be read.
	DiagIgnoreFileUnreadable = "ignore_file_unreadable"
	// DiagIgnoreFileTooLarge means an ignore file exceeded maxIgnoreFileBytes.
	DiagIgnoreFileTooLarge = "ignore_file_too_large"
	// DiagDirectoryUnreadable means a directory could not be listed.
	DiagDirectoryUnreadable = "directory_unreadable"
	// DiagFileUnreadable means a file's prefix could not be read for classification.
	DiagFileUnreadable = "file_unreadable"
	// DiagDepthExceeded means a subtree was pruned at defaultMaxDepth.
	DiagDepthExceeded = "depth_exceeded"
)

// Entry is one classified path produced by a walk.
//
// Size and ModTime accompany the decision because the walk has already paid for the stat. An
// incremental reindex compares exactly these two fields, and making it stat every path a second
// time would double the syscall cost of the operation the freshness SLO is measured on.
type Entry struct {
	Decision
	Size    int64
	ModTime time.Time
}

// Diagnostic records something a walk could not do.
//
// Detail names the condition, never the content of the file involved: a diagnostic is written to
// logs and shown in the context health view, and an ignore file can contain paths a user considers
// sensitive (R-ERR-02).
type Diagnostic struct {
	// Path is repository relative, "" for the root itself.
	Path string
	// Reason is one of the Diag* codes.
	Reason string
	// Detail is a short, stable explanation.
	Detail string
}

// Stats counts what a walk saw.
type Stats struct {
	Directories int
	// Pruned counts directories whose subtrees were not visited at all.
	Pruned      int
	Files       int
	Indexed     int
	Referenced  int
	Excluded    int
	IgnoreFiles int
}

// Report is the outcome of a walk.
type Report struct {
	Stats Stats
	// Diagnostics is capped at MaxDiagnostics; Suppressed counts those dropped.
	Diagnostics []Diagnostic
	Suppressed  int
}

// Complete reports whether the walk saw the whole tree.
//
// A caller recording an index snapshot (CTX-8) must not describe an incomplete walk as a full
// index of the revision, and a caller deciding whether a retrieval is degraded needs this as a
// single answer rather than a diagnostic scan.
func (r Report) Complete() bool { return len(r.Diagnostics) == 0 && r.Suppressed == 0 }

// WalkOptions tunes a walk. The zero value selects the defaults.
type WalkOptions struct {
	// MaxDepth bounds directory recursion below the root.
	MaxDepth int
	// MaxDiagnostics bounds the retained diagnostics.
	MaxDiagnostics int
}

// Walker performs hierarchical ignore discovery over a source tree (PRD §20A.10).
//
// It reads `.gitignore`, `.modbitignore`, and `.modbitindexingignore` in each directory it enters
// and applies them to that directory's subtree only, which is the semantic users already have from
// git. It never resolves a symbolic link, never opens an irregular file, and never descends into a
// directory it has decided to exclude — the last of these is what makes CTX-4 hold in practice,
// since content excluded before the descent is content that was never read.
type Walker struct {
	root       string
	classifier *Classifier
	opts       WalkOptions
}

// NewWalker returns a Walker rooted at an existing directory.
//
// The root is resolved through any symbolic links once, here, so that every path the walk produces
// is relative to a fixed real directory. Resolving it per entry instead would let a link swapped
// mid-walk move the root underneath the traversal.
func NewWalker(root string, classifier *Classifier, opts WalkOptions) (*Walker, error) {
	if classifier == nil {
		return nil, modberr.New(modberr.CodeInvalidArgument, "walker requires a classifier").
			WithDetail("field", "classifier")
	}
	if root == "" {
		return nil, modberr.New(modberr.CodeInvalidArgument, "walker requires a root directory").
			WithDetail("field", "root")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "walk root cannot be resolved").
			WithDetail("field", "root")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "walk root cannot be read").
			WithDetail("field", "root")
	}
	if !info.IsDir() {
		return nil, modberr.New(modberr.CodeInvalidArgument, "walk root is not a directory").
			WithDetail("field", "root")
	}

	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	if opts.MaxDiagnostics <= 0 {
		opts.MaxDiagnostics = defaultMaxDiagnostics
	}
	return &Walker{root: resolved, classifier: classifier, opts: opts}, nil
}

// Walk traverses the tree, calling visit once per classified path.
//
// Entries arrive in a deterministic order — directory entries sorted by name, depth first — so two
// walks of the same tree produce the same sequence and an index built from one is reproducible
// from the other.
//
// Directories are reported only when excluded, which collapses a pruned subtree into the single
// line that explains it instead of the millions of paths it contains. Returning an error from
// visit stops the walk and surfaces that error unchanged.
func (w *Walker) Walk(ctx context.Context, visit func(Entry) error) (Report, error) {
	if visit == nil {
		return Report{}, modberr.New(modberr.CodeInvalidArgument, "walk requires a visit function").
			WithDetail("field", "visit")
	}
	rep := &Report{}
	err := w.walkDir(ctx, frame{abs: w.root, classifier: w.classifier}, rep, visit)
	return *rep, err
}

// frame is one directory's traversal state.
type frame struct {
	// abs is the absolute path on disk; rel is repository relative, "" at the root.
	abs string
	rel string
	// depth is 0 at the root.
	depth int
	// classifier resolves this directory's inherited ignore rules. It is shared with the parent
	// whenever this directory contributed no patterns of its own, which is the common case.
	classifier *Classifier
	// patterns are every inherited pattern, in application order.
	patterns []Pattern
}

func (w *Walker) walkDir(ctx context.Context, fr frame, rep *Report, visit func(Entry) error) error {
	// Checked per directory rather than per entry: a cancelled walk should stop promptly without
	// paying for a context read on every file in a monorepo (R-GO-01).
	if err := ctx.Err(); err != nil {
		return modberr.Wrap(err, modberr.CodeCancelled, "index walk cancelled")
	}

	entries, err := os.ReadDir(fr.abs)
	if err != nil {
		// An unlistable directory is pruned, not fatal: one unreadable subtree must not deny the
		// user an index of the rest of the repository.
		w.diagnose(rep, fr.rel, DiagDirectoryUnreadable, "directory could not be listed")
		rep.Stats.Pruned++
		return nil
	}
	rep.Stats.Directories++

	// Ignore files are read before any child is judged. A directory's own rules govern its
	// children, so reading them later would mean pruning decisions had already been made without
	// them.
	classifier, patterns, ok := w.loadIgnoreFiles(fr, entries, rep)
	if !ok {
		rep.Stats.Pruned++
		return nil
	}
	child := frame{depth: fr.depth + 1, classifier: classifier, patterns: patterns}

	for _, entry := range entries {
		child.rel = path.Join(fr.rel, entry.Name())
		child.abs = filepath.Join(fr.abs, entry.Name())

		if entry.IsDir() {
			if err := w.walkSubdir(ctx, child, entry.Name(), rep, visit); err != nil {
				return err
			}
			continue
		}
		if err := w.walkFile(child, entry, rep, visit); err != nil {
			return err
		}
	}
	return nil
}

// walkSubdir classifies a directory and descends into it unless it is excluded.
func (w *Walker) walkSubdir(ctx context.Context, fr frame, name string, rep *Report, visit func(Entry) error) error {
	if slices.Contains(vcsMetadataDirs, name) {
		rep.Stats.Pruned++
		rep.Stats.Excluded++
		return visit(Entry{Decision: Decision{
			Path:        fr.rel,
			Disposition: DispositionExclude,
			Reason:      ReasonVCSMetadata,
			Detail:      name,
			Provenance:  taint.RepositoryUntrusted,
		}})
	}

	d := fr.classifier.Classify(File{Path: fr.rel, IsDir: true})
	if d.Disposition == DispositionExclude {
		rep.Stats.Pruned++
		rep.Stats.Excluded++
		return visit(Entry{Decision: d})
	}
	if fr.depth > w.opts.MaxDepth {
		w.diagnose(rep, fr.rel, DiagDepthExceeded, "subtree exceeds the maximum indexing depth")
		rep.Stats.Pruned++
		return nil
	}
	// A directory held at DispositionReference by `.modbitindexingignore` is still traversed: that
	// file withholds content from the indexes, it does not hide the tree.
	return w.walkDir(ctx, fr, rep, visit)
}

// walkFile classifies a single non-directory entry.
func (w *Walker) walkFile(fr frame, entry os.DirEntry, rep *Report, visit func(Entry) error) error {
	rep.Stats.Files++

	// Kind is judged before the path rules, from the directory entry itself, so no decision here
	// depends on opening anything.
	//
	// A symbolic link is recorded and never resolved. Following one would let a link committed to
	// the repository pull arbitrary filesystem content in under a repository-relative path — a path
	// the protected list was never written to cover, because it describes the repository's own
	// layout and not the machine's. Excluding rather than referencing the link keeps a later stage
	// from resolving the path on the index's authority.
	if entry.Type()&os.ModeSymlink != 0 {
		return w.emit(rep, visit, Entry{Decision: Decision{
			Path:        fr.rel,
			Disposition: DispositionExclude,
			Reason:      ReasonSymlink,
			Provenance:  taint.RepositoryUntrusted,
		}})
	}
	if !entry.Type().IsRegular() {
		// Opening a FIFO blocks until a writer appears, which would hang the indexer on a path any
		// contributor can create.
		return w.emit(rep, visit, Entry{Decision: Decision{
			Path:        fr.rel,
			Disposition: DispositionExclude,
			Reason:      ReasonNotRegular,
			Provenance:  taint.RepositoryUntrusted,
		}})
	}

	info, err := entry.Info()
	if err != nil {
		w.diagnose(rep, fr.rel, DiagFileUnreadable, "file metadata could not be read")
		return nil
	}

	f := File{Path: fr.rel, Size: info.Size()}
	d, decided := fr.classifier.classifyPath(f)
	if !decided {
		// Only now is opening the file permitted. Everything that could forbid reading it —
		// `.modbitignore`, the protected list, the size limit — has already been consulted.
		contents, err := readPrefix(fr.abs, sniffBytes)
		if err != nil {
			w.diagnose(rep, fr.rel, DiagFileUnreadable, "file contents could not be read")
			return nil
		}
		d = fr.classifier.classifyContents(d, contents)
	}
	return w.emit(rep, visit, Entry{Decision: d, Size: info.Size(), ModTime: info.ModTime()})
}

func (w *Walker) emit(rep *Report, visit func(Entry) error, e Entry) error {
	switch e.Disposition {
	case DispositionIndex:
		rep.Stats.Indexed++
	case DispositionReference:
		rep.Stats.Referenced++
	case DispositionExclude:
		rep.Stats.Excluded++
	}
	return visit(e)
}

// loadIgnoreFiles reads this directory's ignore files and returns the classifier its children are
// judged by.
//
// ok=false means an ignore file exists but could not be honoured. The subtree is then pruned rather
// than indexed under the rules that happened to be readable: an ignore file Modbit cannot read is
// an instruction Modbit cannot follow, and CTX-4 requires excluding restricted content *before*
// indexing. Failing open here would index exactly the content the unreadable file was there to
// withhold.
func (w *Walker) loadIgnoreFiles(fr frame, entries []os.DirEntry, rep *Report) (*Classifier, []Pattern, bool) {
	present := make(map[string]os.DirEntry, len(IgnoreFiles))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			present[entry.Name()] = entry
		}
	}

	var discovered []Pattern
	for _, ig := range IgnoreFiles {
		entry, found := present[ig.Name]
		if !found {
			continue
		}
		// Reading `.gitignore` at all is pointless when policy says not to honour it, and not
		// reading it keeps the walk off a file the operator has declared irrelevant.
		if ig.Source == SourceGitignore && !w.classifier.config.RespectGitignore {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			w.diagnose(rep, path.Join(fr.rel, ig.Name), DiagIgnoreFileUnreadable,
				"ignore file metadata could not be read")
			return nil, nil, false
		}
		if info.Size() > maxIgnoreFileBytes {
			w.diagnose(rep, path.Join(fr.rel, ig.Name), DiagIgnoreFileTooLarge,
				"ignore file exceeds the maximum readable size")
			return nil, nil, false
		}
		contents, err := readPrefix(filepath.Join(fr.abs, ig.Name), maxIgnoreFileBytes)
		if err != nil {
			w.diagnose(rep, path.Join(fr.rel, ig.Name), DiagIgnoreFileUnreadable,
				"ignore file could not be read")
			return nil, nil, false
		}
		rep.Stats.IgnoreFiles++
		discovered = append(discovered, ParseFile(string(contents), fr.rel, ig.Source)...)
	}

	if len(discovered) == 0 {
		// The common case: nothing to layer, so the parent's classifier is reused as is. Rebuilding
		// it per directory would allocate a rule set for every directory in the tree.
		return fr.classifier, fr.patterns, true
	}
	// Cloning rather than appending in place keeps sibling directories independent: two siblings
	// share the parent's backing array, and an append could otherwise let one overwrite the other's
	// patterns.
	merged := append(slices.Clone(fr.patterns), discovered...)
	return fr.classifier.WithRules(NewRuleSet(merged)), merged, true
}

// readPrefix reads at most limit bytes from a regular file.
func readPrefix(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// diagnose records a diagnostic, bounded by MaxDiagnostics.
func (w *Walker) diagnose(rep *Report, path, reason, detail string) {
	if len(rep.Diagnostics) >= w.opts.MaxDiagnostics {
		rep.Suppressed++
		return
	}
	rep.Diagnostics = append(rep.Diagnostics, Diagnostic{Path: path, Reason: reason, Detail: detail})
}
