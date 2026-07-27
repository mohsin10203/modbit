package index

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"slices"
	"sync"

	"github.com/modbit/modbit/pkg/modberr"
)

// Vector invariants (V1–V10).
//
// This is CTX-5's semantic channel and RET-1's `ann` term. Like the lexical channel it is a port
// with one in-process implementation: SDD §2 and dev-06 place pgvector with an HNSW index behind it,
// which is a datastore choice and therefore an ADR under R-ARCH-01.
//
// Each invariant has one test named for it in vector_test.go. A test without a V-number, or a
// V-number without a test, is a gap.
//
//	V1  A vector indexed for one revision is never returned to a query on another.
//	V2  Vectors from one embedding model are never compared against another's.
//	V3  Only indexable content is embedded; Chunk is the gate.
//	V4  A removed path never appears in a later result.
//	V5  Re-indexing a path replaces its vectors rather than accumulating them.
//	V6  Ranking is deterministic.
//	V7  Every match carries the path and span a citation needs.
//	V8  A vector of the wrong width or of zero magnitude is refused, never coerced.
//	V9  The index holds vectors and locations, never text.
//	V10 The index never contacts a provider; embedding is the gateway's job.
//
// V9 holds structurally here — Match has no field to put text in and vectorEntry keeps none — so its
// test cannot fail against this implementation. It is kept for the pgvector adapter the port exists
// to admit, where the row being selected from does hold the chunk and returning it would be one
// column away.
//
// V10 is enforced rather than asserted: TestSecurityIndexPackageCannotReachTheNetwork walks this
// package's transitive dependencies and fails on net/http, crypto/tls, os/exec, and the gateway and
// inference packages. A comment saying "do not import net/http" is a convention; that test is the
// same statement in a form that fails.

// Vector is an embedding. Values are float32 because that is what every embedding provider returns
// and what a vector store holds; widening them here would double the index's memory for precision
// nothing downstream uses.
type Vector []float32

// EmbeddedDocument is a chunk and the vector that represents it.
type EmbeddedDocument struct {
	Document
	Vector Vector
}

// VectorSpace identifies the partition a vector belongs to.
//
// It is a revision *and* an embedding model because both make vectors incomparable. The revision is
// CTX-3, the same zero-contamination rule the lexical channel obeys. The model is dev-06's
// "re-embedding on model change is a versioned rebuild" (SDD §17, UPG-6): two models place the same
// text at different coordinates, so a cosine between them is a number with no meaning — and, worse,
// a plausible-looking one. Threading both through every method is deliberate; an implementation
// cannot forget a parameter it is required to accept.
type VectorSpace struct {
	Revision Revision
	// Model identifies the embedding model *and* its revision, as the provider reports it. Two
	// deployments of "the same" model that report different revisions are different models here,
	// because MOD-A01 decision 18 exists precisely because providers roll models silently.
	Model string
}

// Key returns the stable partition key. Like Revision.Key it is a digest rather than a concatenation,
// so a model identifier chosen by a provider cannot be read as a partition path.
func (s VectorSpace) Key() string {
	h := sha256.New()
	h.Write([]byte(s.Revision.Key()))
	h.Write([]byte{0})
	h.Write([]byte(s.Model))
	return hex.EncodeToString(h.Sum(nil))
}

// Valid reports whether the space names both a revision and a model.
func (s VectorSpace) Valid() bool { return s.Model != "" }

// VectorIndex is the port for semantic retrieval.
//
// Implementations: MemoryVectorIndex here, and pgvector behind an adapter for anything larger.
type VectorIndex interface {
	// Upsert replaces every vector previously held for each document's path.
	Upsert(space VectorSpace, docs ...EmbeddedDocument) error
	// Remove drops every vector held for each path.
	Remove(space VectorSpace, paths ...string) error
	// Search returns at most k nearest documents, closest first.
	Search(space VectorSpace, query Vector, k int) ([]Match, error)
}

// Embedder turns text into vectors.
//
// V10. It is a port rather than a provider client because embedding a chunk is egress of repository
// content: dev-06 requires embedding calls to route through the Model Gateway like all inference, so
// they pass the credential boundary (INV-2), DLP inspection (INV-3), and cost metering. An index
// that held its own HTTP client would bypass all three, and it would do so for the one code path
// that reads every file in the repository.
//
// Nothing in this package imports net/http, and nothing here should.
type Embedder interface {
	// Model identifies the model and revision producing these vectors, for VectorSpace.
	Model() string
	// Embed returns one vector per text, in the order given.
	Embed(ctx context.Context, texts []string) ([]Vector, error)
}

// MemoryVectorIndex is an in-process brute-force implementation of VectorIndex.
//
// It scores every vector in a partition against the query. dev-06 specifies HNSW, which is what
// pgvector brings; exhaustive scan is the honest floor — correct at every size, fast enough for a
// single repository, and never pretending to be an approximate-nearest-neighbour structure it is
// not. Recall is 100% by construction, which also makes it the reference an approximate index is
// measured against (RET-10).
type MemoryVectorIndex struct {
	mu         sync.RWMutex
	partitions map[string]*vectorPartition
}

type vectorPartition struct {
	docs   []vectorEntry
	byPath map[string][]int
	free   []int
	// dims is fixed by the first vector admitted and enforced against every later one.
	dims int
}

type vectorEntry struct {
	path   string
	span   Span
	vector Vector
	live   bool
}

// NewMemoryVectorIndex returns an empty in-process semantic index.
func NewMemoryVectorIndex() *MemoryVectorIndex {
	return &MemoryVectorIndex{partitions: make(map[string]*vectorPartition)}
}

var _ VectorIndex = (*MemoryVectorIndex)(nil)

func (m *MemoryVectorIndex) partitionFor(space VectorSpace, create bool) *vectorPartition {
	key := space.Key()
	p := m.partitions[key]
	if p == nil && create {
		p = &vectorPartition{byPath: make(map[string][]int)}
		m.partitions[key] = p
	}
	return p
}

// Upsert implements VectorIndex.
func (m *MemoryVectorIndex) Upsert(space VectorSpace, docs ...EmbeddedDocument) error {
	if !space.Valid() {
		return modberr.New(modberr.CodeInvalidArgument, "a vector space must name an embedding model").
			WithDetail("field", "space")
	}
	if len(docs) == 0 {
		return nil
	}

	// Normalize before taking the lock and before mutating anything: a batch containing one bad
	// vector must not leave half of itself applied.
	normalized := make([]Vector, len(docs))
	for i, d := range docs {
		v, err := normalize(d.Vector)
		if err != nil {
			return err
		}
		normalized[i] = v
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.partitionFor(space, true)

	// V8. The width is fixed by the first vector and enforced thereafter. Coercing instead —
	// truncating or zero-padding — would produce a cosine that is arithmetically valid and
	// semantically meaningless, which is the failure mode nobody notices.
	if p.dims == 0 {
		p.dims = len(normalized[0])
	}
	for _, v := range normalized {
		if len(v) != p.dims {
			return modberr.New(modberr.CodeInvalidArgument,
				"vector width does not match the rest of the partition").
				WithDetail("field", "vector")
		}
	}

	// V5.
	seen := make(map[string]bool, len(docs))
	for _, d := range docs {
		path := normalizePath(d.Path)
		if !seen[path] {
			p.retract(path)
			seen[path] = true
		}
	}
	for i, d := range docs {
		p.add(normalizePath(d.Path), d.Span, normalized[i])
	}
	return nil
}

// Remove implements VectorIndex.
func (m *MemoryVectorIndex) Remove(space VectorSpace, paths ...string) error {
	if len(paths) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.partitionFor(space, false)
	if p == nil {
		return nil
	}
	for _, path := range paths {
		p.retract(normalizePath(path))
	}
	return nil
}

func (p *vectorPartition) add(path string, span Span, v Vector) {
	ordinal := -1
	if n := len(p.free); n > 0 {
		ordinal = p.free[n-1]
		p.free = p.free[:n-1]
	} else {
		ordinal = len(p.docs)
		p.docs = append(p.docs, vectorEntry{})
	}
	// V9. The location and the vector, never the text. An index holding chunk bodies would be a
	// second copy of the repository outside the classifier's reach.
	p.docs[ordinal] = vectorEntry{path: path, span: span, vector: v, live: true}
	p.byPath[path] = append(p.byPath[path], ordinal)
}

func (p *vectorPartition) retract(path string) {
	for _, ordinal := range p.byPath[path] {
		if !p.docs[ordinal].live {
			continue
		}
		// The vector is dropped, not merely unlinked: leaving it reachable through the slice would
		// keep an embedding of retracted content resident for the process's lifetime.
		p.docs[ordinal] = vectorEntry{}
		p.free = append(p.free, ordinal)
	}
	delete(p.byPath, path)
}

// Search implements VectorIndex.
func (m *MemoryVectorIndex) Search(space VectorSpace, query Vector, k int) ([]Match, error) {
	if !space.Valid() {
		return nil, modberr.New(modberr.CodeInvalidArgument, "a vector space must name an embedding model").
			WithDetail("field", "space")
	}
	if k <= 0 {
		return nil, modberr.New(modberr.CodeInvalidArgument, "search requires a positive result count").
			WithDetail("field", "k")
	}
	q, err := normalize(query)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	// V1 and V2 both rest on this: the key digests the revision and the model together, so a query
	// can only reach vectors produced for the same tree by the same model. A missing partition is an
	// empty result, never a fallback to a neighbouring one.
	p := m.partitionFor(space, false)
	if p == nil || p.dims == 0 {
		return nil, nil
	}
	if len(q) != p.dims {
		return nil, modberr.New(modberr.CodeInvalidArgument,
			"query vector width does not match the index").
			WithDetail("field", "query")
	}

	matches := make([]Match, 0, k)
	for _, d := range p.docs {
		if !d.live {
			continue
		}
		// Both sides are unit vectors, so the dot product is the cosine.
		var score float64
		for i, x := range d.vector {
			score += float64(x) * float64(q[i])
		}
		matches = append(matches, Match{Path: d.path, Span: d.span, Score: score})
	}
	if len(matches) == 0 {
		return nil, nil
	}

	// V6. Same reasoning as the lexical channel: near-identical chunks produce near-identical
	// scores, and an unbroken tie makes a recorded retrieval irreproducible.
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

// normalize returns v scaled to unit length.
//
// V8. Normalizing on admission is what makes a dot product a cosine, so every comparison in the
// index is against the same scale regardless of what a provider returned. A zero-magnitude vector is
// refused rather than passed through: it has no direction, so its similarity to everything is zero,
// and it would sit in the index as a document that silently never matches.
func normalize(v Vector) (Vector, error) {
	if len(v) == 0 {
		return nil, modberr.New(modberr.CodeInvalidArgument, "a vector must have at least one dimension").
			WithDetail("field", "vector")
	}
	var sum float64
	for _, x := range v {
		f := float64(x)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			// A NaN propagates through every later comparison and turns the whole partition's
			// ordering into nonsense, so it is refused where it enters.
			return nil, modberr.New(modberr.CodeInvalidArgument,
				"a vector cannot contain NaN or infinity").
				WithDetail("field", "vector")
		}
		sum += f * f
	}
	if sum == 0 {
		return nil, modberr.New(modberr.CodeInvalidArgument,
			"a zero-magnitude vector has no direction and cannot be indexed").
			WithDetail("field", "vector")
	}
	norm := math.Sqrt(sum)
	out := make(Vector, len(v))
	for i, x := range v {
		out[i] = float32(float64(x) / norm)
	}
	return out, nil
}

// EmbedChangeSet updates a semantic index from one reindex delta.
//
// It mirrors ApplyChangeSet: removals first, Chunk as the gate (V3), and a file that cannot be read
// costs its own documents rather than the whole batch. The embedder is called once per file rather
// than once per chunk, because a provider round trip per chunk would make indexing a repository a
// per-chunk billing event.
func EmbedChangeSet(ctx context.Context, idx VectorIndex, embedder Embedder, revision Revision, set ChangeSet, read func(path string) ([]byte, error)) error {
	if idx == nil {
		return modberr.New(modberr.CodeInvalidArgument, "embedding a change set requires an index").
			WithDetail("field", "index")
	}
	if embedder == nil {
		return modberr.New(modberr.CodeInvalidArgument, "embedding a change set requires an embedder").
			WithDetail("field", "embedder")
	}
	if read == nil {
		return modberr.New(modberr.CodeInvalidArgument, "embedding a change set requires a reader").
			WithDetail("field", "read")
	}
	space := VectorSpace{Revision: revision, Model: embedder.Model()}
	if !space.Valid() {
		return modberr.New(modberr.CodeInvalidArgument, "the embedder reported no model identity").
			WithDetail("field", "embedder")
	}

	if len(set.Removals) > 0 {
		if err := idx.Remove(space, set.Removals...); err != nil {
			return err
		}
	}

	degraded := 0
	for _, entry := range set.Upserts {
		if entry.IsDir || !entry.Indexable() {
			continue
		}
		content, err := read(entry.Path)
		if err != nil {
			degraded++
			continue
		}
		docs, err := Chunk(entry, content)
		if err != nil {
			return err
		}
		if len(docs) == 0 {
			if err := idx.Remove(space, entry.Path); err != nil {
				return err
			}
			continue
		}

		texts := make([]string, len(docs))
		for i, d := range docs {
			texts[i] = d.Text
		}
		vectors, err := embedder.Embed(ctx, texts)
		if err != nil {
			// An embedding failure is not the index's to retry: it may be a DLP refusal, a budget
			// ceiling, or a provider outage, and each has a different recovery. It is surfaced with
			// its cause intact.
			return modberr.Wrap(err, modberr.CodeContextDegraded, "chunks could not be embedded").
				WithDetail("degraded_channels", "semantic")
		}
		if len(vectors) != len(docs) {
			// A provider returning a different number of vectors than texts would otherwise pair
			// each chunk with a neighbour's embedding — every result subtly wrong, nothing failing.
			return modberr.New(modberr.CodeContextDegraded,
				"embedder returned a different number of vectors than chunks").
				WithDetail("degraded_channels", "semantic")
		}

		embedded := make([]EmbeddedDocument, len(docs))
		for i, d := range docs {
			embedded[i] = EmbeddedDocument{Document: d, Vector: vectors[i]}
		}
		if err := idx.Upsert(space, embedded...); err != nil {
			return err
		}
	}

	if degraded > 0 {
		return modberr.New(modberr.CodeContextDegraded,
			"some files could not be read and are missing from the semantic index").
			WithDetail("degraded_channels", "semantic")
	}
	return nil
}
