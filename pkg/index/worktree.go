package index

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Worktree reads the version-control state of a checkout (CTX-3).
//
// It parses git's plumbing files directly rather than running git. That is a security decision, not
// a dependency one: repository-controlled configuration can make git execute programs it names —
// hooks, `core.fsmonitor`, aliases, credential helpers — so invoking git inside a repository the
// user has merely opened would put CTX-12 ("indexing must not execute repository code") at the mercy
// of that repository's own config. Reading files keeps it structural.
//
// Everything here is read-only. Nothing in this file writes to the repository.
type Worktree struct {
	root string
	// gitDir holds per-worktree state: HEAD, and for a linked worktree its own directory under
	// `.git/worktrees/<name>`.
	gitDir string
	// commonDir holds shared state: `refs/`, `packed-refs`. A linked worktree has its own gitDir
	// but shares this, which is why the two are tracked separately.
	commonDir string
	linked    bool
}

// Revision identifies the tree state an index was built from.
//
// It is what makes an index branch-, revision-, and worktree-aware. An index recorded against one
// Revision must never answer a query made against another — PRD §7 budgets zero branch/worktree
// contamination incidents.
type Revision struct {
	// Worktree is the checkout's own identity: its resolved root path.
	Worktree string
	// Branch is the checked-out branch, empty when HEAD is detached or unborn.
	Branch string
	// Commit is the resolved object id, empty on an unborn branch (a repository with no commits).
	Commit string
	// Detached reports a HEAD pointing straight at an object rather than a branch.
	Detached bool
	// Linked reports a `git worktree add` checkout rather than the primary one.
	Linked bool
}

// Bounds on the plumbing files. These are small, structured files; anything larger is not the file
// git wrote, and reading it unbounded would let a repository choose how much memory to consume.
const (
	maxHeadFileBytes  = 4 << 10
	maxRefFileBytes   = 4 << 10
	maxPackedRefBytes = 64 << 20
	maxRefNameLength  = 255
	// maxSymrefDepth bounds symbolic-reference chasing. Git allows indirection; a cycle would
	// otherwise not terminate.
	maxSymrefDepth = 5
)

// ErrNotARepository reports that a directory is not a git checkout.
//
// It is an ordinary outcome, not a failure: Modbit indexes plain directories too, and a caller that
// cannot find version control indexes without revision awareness rather than refusing to index.
var ErrNotARepository = errors.New("not a git repository")

// OpenWorktree inspects the checkout containing root.
//
// It returns ErrNotARepository when root is not a checkout, which callers are expected to treat as
// a supported case.
func OpenWorktree(root string) (*Worktree, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "worktree root cannot be resolved").
			WithDetail("field", "root")
	}

	dotGit := filepath.Join(resolved, ".git")
	info, err := os.Lstat(dotGit)
	if err != nil {
		return nil, ErrNotARepository
	}

	w := &Worktree{root: resolved}
	switch {
	case info.IsDir():
		w.gitDir, w.commonDir = dotGit, dotGit
	case info.Mode().IsRegular():
		// A linked worktree records its git directory in a `.git` file. Git creates this file
		// locally; it cannot arrive through a clone, because git refuses to check out a path named
		// `.git`.
		gitDir, err := readGitDirFile(dotGit, resolved)
		if err != nil {
			return nil, err
		}
		w.gitDir, w.linked = gitDir, true
		w.commonDir = readCommonDir(gitDir)
	default:
		// A symlinked `.git` is not followed, for the same reason the walk does not follow links.
		return nil, ErrNotARepository
	}

	if info, err := os.Stat(w.gitDir); err != nil || !info.IsDir() {
		return nil, ErrNotARepository
	}
	return w, nil
}

// Linked reports whether this is a `git worktree add` checkout.
func (w *Worktree) Linked() bool { return w.linked }

// Revision reads the current branch and commit.
//
// A read that cannot be completed is an error rather than a zero Revision: an empty revision would
// compare equal to another empty one, and two different tree states that compare equal is exactly
// the contamination this type exists to prevent.
func (w *Worktree) Revision() (Revision, error) {
	rev := Revision{Worktree: w.root, Linked: w.linked}

	head, err := readTrimmed(filepath.Join(w.gitDir, "HEAD"), maxHeadFileBytes)
	if err != nil {
		return Revision{}, modberr.Wrap(err, modberr.CodeUnavailable, "HEAD could not be read")
	}

	target, isSymbolic := strings.CutPrefix(head, "ref: ")
	if !isSymbolic {
		if !isObjectID(head) {
			return Revision{}, modberr.New(modberr.CodeContractValidationFailed,
				"HEAD is neither a symbolic reference nor an object id")
		}
		rev.Detached, rev.Commit = true, head
		return rev, nil
	}

	target = strings.TrimSpace(target)
	if err := validateRefName(target); err != nil {
		return Revision{}, err
	}
	rev.Branch = strings.TrimPrefix(target, "refs/heads/")

	commit, err := w.resolveRef(target, 0)
	if err != nil {
		return Revision{}, err
	}
	// An empty commit is an unborn branch: `git init` with nothing committed yet. The branch is
	// real and indexable, so this is not an error.
	rev.Commit = commit
	return rev, nil
}

// resolveRef follows a reference to an object id, chasing symbolic references.
func (w *Worktree) resolveRef(ref string, depth int) (string, error) {
	if depth > maxSymrefDepth {
		return "", modberr.New(modberr.CodeContractValidationFailed,
			"reference indirection exceeded its depth limit")
	}

	// Loose refs live in the common directory: a linked worktree has its own HEAD but shares
	// branches with the repository it was created from.
	value, err := readTrimmed(filepath.Join(w.commonDir, filepath.FromSlash(ref)), maxRefFileBytes)
	if err == nil {
		if target, symbolic := strings.CutPrefix(value, "ref: "); symbolic {
			target = strings.TrimSpace(target)
			if err := validateRefName(target); err != nil {
				return "", err
			}
			return w.resolveRef(target, depth+1)
		}
		if !isObjectID(value) {
			return "", modberr.New(modberr.CodeContractValidationFailed,
				"reference does not contain an object id")
		}
		return value, nil
	}
	if !os.IsNotExist(err) {
		return "", modberr.Wrap(err, modberr.CodeUnavailable, "reference could not be read")
	}

	return w.resolvePacked(ref)
}

// resolvePacked looks a reference up in `packed-refs`.
//
// The file is streamed rather than read whole: it holds one line per reference and a repository
// with a large number of tags produces a large one.
func (w *Worktree) resolvePacked(ref string) (string, error) {
	f, err := os.Open(filepath.Join(w.commonDir, "packed-refs"))
	if err != nil {
		if os.IsNotExist(err) {
			// No loose ref and no packed refs: an unborn branch.
			return "", nil
		}
		return "", modberr.Wrap(err, modberr.CodeUnavailable, "packed-refs could not be read")
	}
	defer f.Close()

	scanner := bufio.NewScanner(io.LimitReader(f, maxPackedRefBytes))
	scanner.Buffer(make([]byte, 0, 4096), maxRefFileBytes)
	for scanner.Scan() {
		line := scanner.Text()
		// `#` is a header, `^` a peeled tag target; neither names the reference being resolved.
		if line == "" || line[0] == '#' || line[0] == '^' {
			continue
		}
		id, name, ok := strings.Cut(line, " ")
		if !ok || strings.TrimSpace(name) != ref || !isObjectID(id) {
			continue
		}
		return id, nil
	}
	if err := scanner.Err(); err != nil {
		return "", modberr.Wrap(err, modberr.CodeUnavailable, "packed-refs could not be scanned")
	}
	return "", nil
}

// Key returns the partition key an index built at this revision belongs to.
//
// The key covers the worktree and the branch, not the commit: committing does not move the index to
// a different partition, it advances the one it is in. A detached HEAD has no branch to identify
// it, so the commit stands in.
//
// It is a digest rather than the names themselves because a branch name is repository-authored, and
// therefore untrusted (R-SEC-01). Names like `../other-space` reach this function; a key that
// embedded them verbatim would let a branch name address a partition it does not own. Hashing makes
// that structurally impossible while staying injective.
func (r Revision) Key() string {
	identity := r.Branch
	if r.Detached || identity == "" {
		identity = "@" + r.Commit
	}
	h := sha256.New()
	// The separator cannot occur in either field, so no pair of different inputs can produce the
	// same digest input.
	h.Write([]byte(r.Worktree))
	h.Write([]byte{0})
	h.Write([]byte(identity))
	return hex.EncodeToString(h.Sum(nil))
}

// SamePartition reports whether two revisions address the same index partition.
func (r Revision) SamePartition(other Revision) bool { return r.Key() == other.Key() }

// Equal reports whether two revisions describe the same tree state.
func (r Revision) Equal(other Revision) bool {
	return r.Worktree == other.Worktree && r.Branch == other.Branch &&
		r.Commit == other.Commit && r.Detached == other.Detached && r.Linked == other.Linked
}

// Short renders the revision the way a citation displays it.
//
// The commit is preferred over the branch because a branch moves and a citation must stay readable
// against the state it was taken from. A tree with no checkout has neither, and says so rather than
// rendering empty — a citation ending in "@" reads as a truncation, which is the one thing evidence
// must not look like.
func (r Revision) Short() string {
	switch {
	case r.Commit != "":
		if len(r.Commit) > shortCommitLength {
			return r.Commit[:shortCommitLength]
		}
		return r.Commit
	case r.Branch != "":
		return r.Branch
	default:
		return "unversioned"
	}
}

// shortCommitLength is the abbreviation used in citations. Twelve rather than git's seven: seven
// collides at monorepo scale, and a citation that names the wrong commit is worse than a long one.
const shortCommitLength = 12

// readGitDirFile parses the `gitdir:` pointer a linked worktree's `.git` file contains.
func readGitDirFile(name, root string) (string, error) {
	contents, err := readTrimmed(name, maxHeadFileBytes)
	if err != nil {
		return "", modberr.Wrap(err, modberr.CodeUnavailable, "worktree .git file could not be read")
	}
	dir, ok := strings.CutPrefix(contents, "gitdir: ")
	if !ok {
		return "", ErrNotARepository
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", ErrNotARepository
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	return filepath.Clean(dir), nil
}

// readCommonDir resolves the shared git directory for a linked worktree, falling back to the
// worktree's own git directory when there is no `commondir` file.
func readCommonDir(gitDir string) string {
	contents, err := readTrimmed(filepath.Join(gitDir, "commondir"), maxRefFileBytes)
	if err != nil || contents == "" {
		return gitDir
	}
	if filepath.IsAbs(contents) {
		return filepath.Clean(contents)
	}
	return filepath.Clean(filepath.Join(gitDir, contents))
}

// readTrimmed reads at most limit bytes and trims surrounding whitespace.
func readTrimmed(name string, limit int64) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// isObjectID reports whether s is a git object id: SHA-1 or SHA-256, lowercase hex.
func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validateRefName rejects reference names that are not safe to carry.
//
// A branch name is chosen by whoever can push to the repository, and it flows from here into
// partition keys, status displays, logs, and index snapshot records. Git's own `check-ref-format`
// rules are enforced here rather than assumed, because the rules exist precisely to stop a name
// from being read as something other than a name.
func validateRefName(ref string) error {
	invalid := func(reason string) error {
		return modberr.New(modberr.CodeContractValidationFailed,
			"reference name is not valid: "+reason).WithDetail("field", "ref")
	}

	switch {
	case ref == "", len(ref) > maxRefNameLength:
		return invalid("empty or too long")
	case !strings.HasPrefix(ref, "refs/"):
		return invalid("not under refs/")
	case strings.Contains(ref, ".."):
		return invalid("contains ..")
	case strings.Contains(ref, "//"):
		return invalid("contains an empty component")
	case strings.HasSuffix(ref, "/"), strings.HasSuffix(ref, "."):
		return invalid("ends with a separator or dot")
	case strings.HasSuffix(ref, ".lock"):
		return invalid("ends with .lock")
	case strings.Contains(ref, "@{"):
		return invalid("contains @{")
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		// Control characters, DEL, and the characters git reserves for revision syntax.
		if c < 0x20 || c == 0x7f || strings.IndexByte(" ~^:?*[\\", c) >= 0 {
			return invalid("contains a reserved character")
		}
	}
	for _, component := range strings.Split(ref, "/") {
		if strings.HasPrefix(component, ".") {
			return invalid("has a component beginning with a dot")
		}
	}
	return nil
}
