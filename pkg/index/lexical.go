package index

import (
	"cmp"
	"math"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/modbit/modbit/pkg/modberr"
)

// Lexical invariants (L1–L8).
//
// This is CTX-5's lexical channel and RET-1's `bm25` term. It is a port with one in-process
// implementation: SDD §2 names Tantivy locally and an OpenSearch-compatible adapter on the server,
// and both are engine choices that belong in an ADR rather than in the first implementation. What
// must not wait for that decision is the contract — what a lexical channel may hold, what it may
// return, and which revision it answers for.
//
// Each invariant has one test named for it in lexical_test.go. A test without an L-number, or an
// L-number without a test, is a gap.
//
//	L1 A document indexed for one revision is never returned to a query on another.
//	L2 Only indexable content becomes a document; construction is the gate.
//	L3 A removed path never appears in a later result.
//	L4 Re-indexing a path replaces its documents rather than accumulating them.
//	L5 Ranking is deterministic: the same corpus and query always produce the same order.
//	L6 Identifiers match their parts, so camelCase and snake_case are searchable.
//	L7 Every match carries the path and span a citation needs.
//	L8 A query with no usable terms returns nothing, never everything.
//
// L8 is a property of the scoring loop rather than something guarded: with no terms there is nothing
// to accumulate a score against, so the result is empty whether or not the early return exists.
// Removing the guard does not fail its test, and the test is kept for the next implementation rather
// than this one — a match-all path added later is exactly the kind of change that looks reasonable
// in isolation and turns an unparseable query into a whole spent retrieval budget.

// Document is one indexed unit of text.
//
// A document is a span of a file rather than a whole file, because a retrieval budget is spent in
// spans and a citation names one (RET-6). dev-06 places one BM25 document per chunk for the same
// reason.
type Document struct {
	// Path is the repository-relative path the span belongs to.
	Path string
	// Span locates the text within the file, in both lines and bytes.
	Span Span
	// Text is the chunk's content. It is tokenized and discarded; the index stores no bodies.
	Text string
}

// Match is one lexical hit.
//
// It carries exactly what Cite needs and nothing else: a retrieval result that could not be turned
// into a citation would be content with no provenance, which RET-6 forbids reaching a model.
type Match struct {
	Path  string
	Span  Span
	Score float64
}

// LexicalIndex is the port for full-text retrieval.
//
// Implementations: MemoryIndex here, Tantivy locally, and an OpenSearch-compatible adapter on the
// server. Every method is revision-scoped because an index that answered across revisions would be
// the branch contamination PRD §7 budgets at zero, and making the revision a parameter means an
// implementation cannot forget it.
type LexicalIndex interface {
	// Upsert replaces every document previously held for each document's path.
	Upsert(revision Revision, docs ...Document) error
	// Remove drops every document held for each path.
	Remove(revision Revision, paths ...string) error
	// Search returns at most k matches, best first.
	Search(revision Revision, query string, k int) ([]Match, error)
}

// DefaultChunkLines is the line window a chunk covers when no symbol boundaries are available.
//
// dev-06 specifies symbol-aligned chunks of 200–800 tokens, which needs the parser CTX-A01e brings.
// Until then a line window is the honest approximation: it produces exact spans, which is what a
// citation requires, and it is replaceable without changing the index or the port.
const DefaultChunkLines = 60

// Chunk turns one classified file into indexable documents.
//
// Construction is the gate (L2), exactly as it is for Cite: a file the classifier did not mark
// indexable has no business in a full-text index, and refusing here means no implementation of the
// port has to re-check. A reference file is refused too — Modbit never read it, so there is no text
// to index and a document claiming otherwise would be fabricated.
func Chunk(entry Entry, content []byte) ([]Document, error) {
	if entry.IsDir {
		return nil, modberr.New(modberr.CodeInvalidArgument, "a directory has no text to index").
			WithDetail("field", "entry")
	}
	if !entry.Indexable() {
		// L2. The message names the disposition rather than the path's contents: a caller passing a
		// protected path has misunderstood what an index holds, and telling it why is safe, while
		// echoing the path would put it in whatever log catches this error.
		return nil, modberr.New(modberr.CodeInvalidArgument,
			"only content classified for indexing can be chunked").
			WithDetail("field", "entry").
			WithDetail("resource_type", string(entry.Disposition))
	}
	if len(content) == 0 {
		return nil, nil
	}

	var (
		docs      []Document
		lineStart = 1
		byteStart = 0
		lines     = 0
	)
	flush := func(byteEnd int, lineEnd int) {
		if byteEnd <= byteStart {
			return
		}
		text := string(content[byteStart:byteEnd])
		if strings.TrimSpace(text) == "" {
			return
		}
		docs = append(docs, Document{
			Path: entry.Path,
			Span: Span{
				StartLine: lineStart,
				EndLine:   lineEnd,
				StartByte: int64(byteStart),
				EndByte:   int64(byteEnd),
			},
			Text: text,
		})
	}

	line := 1
	for i, b := range content {
		if b != '\n' {
			continue
		}
		lines++
		line++
		if lines == DefaultChunkLines {
			flush(i+1, line-1)
			byteStart = i + 1
			lineStart = line
			lines = 0
		}
	}
	flush(len(content), line)
	return docs, nil
}

// ApplyChangeSet updates a lexical index from one reindex delta.
//
// Removals are applied before upserts, matching ChangeSet's documented ordering: a rename that
// replaces a file with a directory puts the same path in both, and applying them the other way round
// would delete the content just written.
//
// read supplies a path's current bytes. A path that cannot be read is skipped with its error
// returned rather than silently omitted — a document missing from a lexical index is a file the user
// cannot find by searching for text they know is in it, which is a degradation that must be visible
// (R-ERR-05).
func ApplyChangeSet(idx LexicalIndex, revision Revision, set ChangeSet, read func(path string) ([]byte, error)) error {
	if idx == nil {
		return modberr.New(modberr.CodeInvalidArgument, "applying a change set requires an index").
			WithDetail("field", "index")
	}
	if read == nil {
		return modberr.New(modberr.CodeInvalidArgument, "applying a change set requires a reader").
			WithDetail("field", "read")
	}

	if len(set.Removals) > 0 {
		if err := idx.Remove(revision, set.Removals...); err != nil {
			return err
		}
	}

	unreadable := 0
	for _, entry := range set.Upserts {
		if entry.IsDir || !entry.Indexable() {
			// A reference entry is legitimately in a ChangeSet — it is citable — but it has no text.
			// Dropping it here is not a silent loss: nothing was ever readable to lose.
			continue
		}
		content, err := read(entry.Path)
		if err != nil {
			// One unreadable file must not cost the rest of the batch. Aborting here would leave
			// every later file unindexed as well, turning one missing document into an arbitrary
			// number of them — and the caller could not tell which.
			unreadable++
			continue
		}
		docs, err := Chunk(entry, content)
		if err != nil {
			return err
		}
		if len(docs) == 0 {
			// A file that produced no documents must still drop whatever it held before, or an edit
			// that empties a file leaves its old text searchable.
			if err := idx.Remove(revision, entry.Path); err != nil {
				return err
			}
			continue
		}
		if err := idx.Upsert(revision, docs...); err != nil {
			return err
		}
	}

	if unreadable > 0 {
		// A document missing from a lexical index is a file the user cannot find by searching for
		// text they know is in it. The index is as complete as it could be made, and the shortfall
		// is reported rather than swallowed (R-ERR-05, SDD §15). The count is carried; the paths are
		// not, because a path is itself information (decision 78).
		return modberr.New(modberr.CodeContextDegraded,
			"some files could not be read and are missing from the lexical index").
			WithDetail("degraded_channels", "lexical")
	}
	return nil
}

// BM25 parameters. These are the standard values and are deliberately not settings: they are a
// ranking-model detail with no operator-meaningful interpretation, and exposing them would invite
// tuning that RET-10's benchmark, not a preference, should drive.
const (
	bm25K1 = 1.2
	bm25B  = 0.75
)

// MemoryIndex is an in-process BM25 implementation of LexicalIndex.
//
// It is the reference implementation the port is proved against, and the one a desktop install uses
// before a native engine is chosen. It holds tokens and postings, never document bodies: the text a
// caller passes is tokenized and discarded, so the index cannot become a second copy of the
// repository sitting outside the classifier's reach.
type MemoryIndex struct {
	mu sync.RWMutex
	// partitions are keyed by Revision.Key(), which is a digest covering worktree and branch. L1
	// rests on this: a query can only reach the partition its revision hashes to.
	partitions map[string]*partition
}

type partition struct {
	// docs holds each document's location and length, keyed by an internal ordinal.
	docs []docEntry
	// byPath maps a path to the ordinals it owns, so a re-index or removal can retract exactly
	// what that path contributed.
	byPath map[string][]int
	// postings maps a term to the ordinals containing it and the count in each.
	postings map[string]map[int]int
	// free lists ordinals vacated by removals, so a long-lived index does not grow without bound.
	free      []int
	totalLen  int
	liveCount int
}

type docEntry struct {
	path   string
	span   Span
	length int
	live   bool
}

// NewMemoryIndex returns an empty in-process lexical index.
func NewMemoryIndex() *MemoryIndex {
	return &MemoryIndex{partitions: make(map[string]*partition)}
}

var _ LexicalIndex = (*MemoryIndex)(nil)

func (m *MemoryIndex) partitionFor(revision Revision, create bool) *partition {
	key := revision.Key()
	p := m.partitions[key]
	if p == nil && create {
		p = &partition{
			byPath:   make(map[string][]int),
			postings: make(map[string]map[int]int),
		}
		m.partitions[key] = p
	}
	return p
}

// Upsert implements LexicalIndex.
func (m *MemoryIndex) Upsert(revision Revision, docs ...Document) error {
	if len(docs) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.partitionFor(revision, true)

	// L4. Every path in this batch is cleared first, so re-indexing a file replaces its documents
	// rather than adding a second copy of every chunk that did not change.
	seen := make(map[string]bool, len(docs))
	for _, d := range docs {
		if !seen[d.Path] {
			p.retract(d.Path)
			seen[d.Path] = true
		}
	}
	for _, d := range docs {
		p.add(d)
	}
	return nil
}

// Remove implements LexicalIndex.
func (m *MemoryIndex) Remove(revision Revision, paths ...string) error {
	if len(paths) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.partitionFor(revision, false)
	if p == nil {
		return nil
	}
	for _, path := range paths {
		p.retract(normalizePath(path))
	}
	return nil
}

func (p *partition) add(d Document) {
	terms := tokenize(d.Text)
	if len(terms) == 0 {
		return
	}
	ordinal := -1
	if n := len(p.free); n > 0 {
		ordinal = p.free[n-1]
		p.free = p.free[:n-1]
		p.docs[ordinal] = docEntry{}
	} else {
		ordinal = len(p.docs)
		p.docs = append(p.docs, docEntry{})
	}

	path := normalizePath(d.Path)
	p.docs[ordinal] = docEntry{path: path, span: d.Span, length: len(terms), live: true}
	p.byPath[path] = append(p.byPath[path], ordinal)
	p.totalLen += len(terms)
	p.liveCount++

	for _, term := range terms {
		posting := p.postings[term]
		if posting == nil {
			posting = make(map[int]int)
			p.postings[term] = posting
		}
		posting[ordinal]++
	}
}

// retract drops every document a path owns. L3 depends on it being complete: a posting left behind
// would keep returning a match for content the index no longer holds.
func (p *partition) retract(path string) {
	ordinals := p.byPath[path]
	if len(ordinals) == 0 {
		return
	}
	live := make(map[int]bool, len(ordinals))
	for _, ordinal := range ordinals {
		if !p.docs[ordinal].live {
			continue
		}
		live[ordinal] = true
		p.totalLen -= p.docs[ordinal].length
		p.liveCount--
		p.docs[ordinal] = docEntry{}
		p.free = append(p.free, ordinal)
	}
	delete(p.byPath, path)

	for term, posting := range p.postings {
		for ordinal := range live {
			delete(posting, ordinal)
		}
		if len(posting) == 0 {
			delete(p.postings, term)
		}
	}
}

// Search implements LexicalIndex.
func (m *MemoryIndex) Search(revision Revision, query string, k int) ([]Match, error) {
	if k <= 0 {
		return nil, modberr.New(modberr.CodeInvalidArgument, "search requires a positive result count").
			WithDetail("field", "k")
	}
	terms := tokenize(query)
	if len(terms) == 0 {
		// L8. An optimisation, not a gate: the scoring loop below already yields nothing without
		// terms. It is here so the empty case is obvious to read rather than inferred.
		return nil, nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	// L1. Revision.Key() is a digest over worktree and branch, so a query cannot reach a partition
	// its revision does not hash to. A missing partition is an empty result, not a fallback to
	// another one.
	p := m.partitionFor(revision, false)
	if p == nil || p.liveCount == 0 {
		return nil, nil
	}

	avgLen := float64(p.totalLen) / float64(p.liveCount)
	scores := make(map[int]float64)
	for _, term := range dedupeTerms(terms) {
		posting := p.postings[term]
		if len(posting) == 0 {
			continue
		}
		// Robertson/Sparck-Jones idf with the +1 guard, so a term present in every document scores
		// zero rather than negative.
		idf := math.Log(1 + (float64(p.liveCount)-float64(len(posting))+0.5)/(float64(len(posting))+0.5))
		for ordinal, freq := range posting {
			d := p.docs[ordinal]
			if !d.live {
				continue
			}
			tf := float64(freq)
			norm := tf * (bm25K1 + 1) / (tf + bm25K1*(1-bm25B+bm25B*float64(d.length)/avgLen))
			scores[ordinal] += idf * norm
		}
	}
	if len(scores) == 0 {
		return nil, nil
	}

	matches := make([]Match, 0, len(scores))
	for ordinal, score := range scores {
		d := p.docs[ordinal]
		matches = append(matches, Match{Path: d.path, Span: d.span, Score: score})
	}
	// L5. Map iteration is random, so an unbroken tie would reorder between runs and a recorded
	// retrieval would not be reproducible evidence (the same reason routing is deterministic —
	// MOD-A01 decision 6). Path then span start makes the order total.
	slices.SortFunc(matches, func(a, b Match) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return cmp.Compare(a.Span.StartByte, b.Span.StartByte)
	})
	if len(matches) > k {
		matches = matches[:k]
	}
	return matches, nil
}

func dedupeTerms(terms []string) []string {
	seen := make(map[string]bool, len(terms))
	out := terms[:0:0]
	for _, t := range terms {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// tokenize splits text into lowercase search terms, code-aware.
//
// L6. A plain word splitter is wrong for source code: `getUserName` would be one term, so searching
// for "user name" would miss the function that defines it, and searching for the identifier would
// miss `get_user_name` in the file next to it. Each identifier therefore contributes both its whole
// form and its parts, which is what makes the three spellings of one name find each other.
func tokenize(text string) []string {
	var (
		terms []string
		word  strings.Builder
	)
	emit := func() {
		if word.Len() == 0 {
			return
		}
		// Split before lowering: the case boundary in getUserName is the only thing marking where
		// one part ends, and lowercasing first destroys it.
		raw := word.String()
		word.Reset()
		whole := strings.ToLower(raw)
		terms = append(terms, whole)
		for _, part := range splitIdentifier(raw) {
			if part != whole {
				terms = append(terms, part)
			}
		}
	}
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			word.WriteRune(r)
			continue
		}
		emit()
	}
	emit()
	return terms
}

// splitIdentifier breaks an identifier into lowercase parts on underscores and case boundaries.
//
// It takes the original casing, because the boundary in getUserName *is* the casing. An acronym run
// is split before its last capital, so HTTPServer yields "http" and "server" rather than "httpserve"
// and "r" — acronyms are common enough in real identifiers that getting this wrong would mis-tokenize
// a large share of a typical codebase.
func splitIdentifier(raw string) []string {
	runes := []rune(raw)
	var (
		parts []string
		start int
	)
	cut := func(end int) {
		if end > start {
			parts = append(parts, strings.ToLower(string(runes[start:end])))
		}
		start = end
	}
	for i := 1; i < len(runes); i++ {
		switch {
		case runes[i] == '_':
			cut(i)
			start = i + 1
		case runes[i-1] == '_':
			// Handled by the branch above; the part starts here.
		case unicode.IsUpper(runes[i]) && !unicode.IsUpper(runes[i-1]):
			// getUser -> get | User
			cut(i)
		case unicode.IsUpper(runes[i-1]) && unicode.IsUpper(runes[i]) &&
			i+1 < len(runes) && unicode.IsLower(runes[i+1]):
			// HTTPServer -> HTTP | Server
			cut(i)
		}
	}
	cut(len(runes))
	if len(parts) < 2 {
		return nil
	}
	return parts
}
