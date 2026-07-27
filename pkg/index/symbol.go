package index

import (
	"cmp"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/modbit/modbit/pkg/modberr"
)

// Symbol invariants (G1–G8).
//
// This is CTX-5's symbol and graph channels. dev-06 places tree-sitter behind it with a per-language
// grammar pack; that is a cgo dependency and belongs in an ADR. What ships now is the port plus a Go
// extractor built entirely on the standard library, which is a real implementation rather than a
// placeholder — this repository is Go, so the channel is useful the day it lands.
//
//	G1 A symbol indexed for one revision is never returned to a query on another.
//	G2 Only indexable content is parsed; Chunk's gate applies here too.
//	G3 Parsing never executes repository code.
//	G4 A removed path never appears in a later result.
//	G5 Re-indexing a path replaces its symbols and edges.
//	G6 Results are deterministic.
//	G7 Every symbol and edge carries the path and span a citation needs.
//	G8 A file that cannot be parsed degrades visibly and does not abort the batch.
//
// G3 is the one worth dwelling on. CTX-12 forbids indexing from executing repository code, and Go's
// own tooling makes that easy to violate by accident: go/build shells out through os/exec, and
// go/importer can invoke a compiler. go/parser and go/ast do neither — they read bytes and return a
// tree. The rule is kept structural rather than remembered:
// TestSecurityIndexPackageCannotReachTheNetwork fails on os/exec, go/build, and go/importer, so an
// import that would let a parse become an execution cannot land quietly.

// SymbolKind classifies a declaration. The set is deliberately small and language-neutral: a
// per-language extractor maps its own concepts onto these, so a query does not have to know which
// language it is asking about.
type SymbolKind string

const (
	SymbolFunction  SymbolKind = "function"
	SymbolMethod    SymbolKind = "method"
	SymbolType      SymbolKind = "type"
	SymbolInterface SymbolKind = "interface"
	SymbolStruct    SymbolKind = "struct"
	SymbolConst     SymbolKind = "const"
	SymbolVar       SymbolKind = "var"
)

// Symbol is one declaration found in a file.
type Symbol struct {
	Name string     `json:"name"`
	Kind SymbolKind `json:"kind"`
	Path string     `json:"path"`
	// Span covers the declaration and its doc comment, so citing a symbol carries the prose that
	// explains it. A citation of a function without its doc comment routinely omits the one sentence
	// that answers the question being asked.
	Span Span `json:"span"`
	// Container is the receiver type for a method, empty otherwise.
	Container string `json:"container,omitempty"`
	// Exported reports whether the symbol is visible outside its package.
	Exported bool `json:"exported"`
}

// Qualified renders the symbol the way a lookup names it: "Type.Method" or "Function".
func (s Symbol) Qualified() string {
	if s.Container != "" {
		return s.Container + "." + s.Name
	}
	return s.Name
}

// EdgeKind classifies a dependency-graph edge.
type EdgeKind string

// EdgeImports is a file's dependency on a package.
//
// dev-06 lists calls, inherits, implements, and references as well. Those need scope and binding
// resolution across files, which is CTX-B01's deep graph; an import is exact, static, and derivable
// from one file, so it is the edge this channel can assert rather than estimate.
const EdgeImports EdgeKind = "imports"

// Edge is one dependency-graph edge. CTX-7 requires cross-repository links to be explicit and
// attributable, which is why an edge names its span rather than only its endpoints: the line that
// creates the dependency is what a reviewer needs.
type Edge struct {
	Kind EdgeKind `json:"kind"`
	// From is the repository-relative path that declares the dependency.
	From string `json:"from"`
	// To is the imported package path.
	To   string `json:"to"`
	Span Span   `json:"span"`
}

// SymbolExtractor turns one classified file into symbols and edges.
//
// Implementations are per-language. A tree-sitter-backed extractor covering the remaining languages
// is the natural next one, and it implements this interface without changing anything above it.
type SymbolExtractor interface {
	// Handles reports whether this extractor understands the path's language.
	Handles(path string) bool
	// Extract parses content. It must not execute anything it reads (G3, CTX-12).
	Extract(entry Entry, content []byte) ([]Symbol, []Edge, error)
}

// GoExtractor extracts symbols from Go source using the standard library parser.
//
// It uses go/parser and go/ast only. It deliberately does not type-check: go/types needs an importer
// to resolve other packages, and the importers that can do that either shell out to the compiler or
// read a build cache the repository can influence. Declarations are recoverable from the syntax tree
// alone, so the type checker buys resolution this channel does not promise and costs the guarantee
// that indexing executes nothing (CTX-12).
type GoExtractor struct{}

var _ SymbolExtractor = GoExtractor{}

// Handles implements SymbolExtractor.
func (GoExtractor) Handles(p string) bool { return strings.HasSuffix(p, ".go") }

// Extract implements SymbolExtractor.
func (GoExtractor) Extract(entry Entry, content []byte) ([]Symbol, []Edge, error) {
	if entry.IsDir || !entry.Indexable() {
		// G2. The same gate as Chunk, for the same reason: a file the classifier excluded must not
		// be parsed, and refusing at the entry point means no extractor has to remember to check.
		return nil, nil, modberr.New(modberr.CodeInvalidArgument,
			"only content classified for indexing can be parsed").
			WithDetail("field", "entry").
			WithDetail("resource_type", string(entry.Disposition))
	}

	fset := token.NewFileSet()
	// ParseComments so a declaration's doc range is available; SkipObjectResolution because the
	// object graph is unused here and building it is pure cost.
	file, err := parser.ParseFile(fset, entry.Path, content,
		parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		// G8. A file that does not parse is reported, not fatal: a repository mid-edit routinely
		// contains one, and an indexer that stopped there would index nothing for the rest of the
		// tree. The message carries the position, never the source line (R-ERR-02).
		return nil, nil, modberr.Wrap(err, modberr.CodeContextDegraded, "file could not be parsed").
			WithDetail("degraded_channels", "symbol")
	}

	spanOf := func(start, end token.Pos) Span {
		from, to := fset.Position(start), fset.Position(end)
		return Span{
			StartLine: from.Line,
			EndLine:   to.Line,
			StartByte: int64(from.Offset),
			EndByte:   int64(to.Offset),
		}
	}

	var (
		symbols []Symbol
		edges   []Edge
	)

	for _, imp := range file.Imports {
		target, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		edges = append(edges, Edge{
			Kind: EdgeImports,
			From: entry.Path,
			To:   target,
			Span: spanOf(imp.Pos(), imp.End()),
		})
	}

	add := func(name string, kind SymbolKind, container string, start, end token.Pos) {
		if name == "" || name == "_" {
			return
		}
		symbols = append(symbols, Symbol{
			Name:      name,
			Kind:      kind,
			Path:      entry.Path,
			Span:      spanOf(start, end),
			Container: container,
			Exported:  ast.IsExported(name),
		})
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			start := d.Pos()
			if d.Doc != nil {
				start = d.Doc.Pos()
			}
			kind, container := SymbolFunction, ""
			if d.Recv != nil && len(d.Recv.List) > 0 {
				kind, container = SymbolMethod, receiverName(d.Recv.List[0].Type)
			}
			add(d.Name.Name, kind, container, start, d.End())

		case *ast.GenDecl:
			for _, spec := range d.Specs {
				// A single-spec declaration carries its doc on the GenDecl; a grouped one carries it
				// per spec. Preferring the spec's own doc keeps a grouped constant from claiming the
				// whole block's comment as its own.
				start := spec.Pos()
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Doc != nil {
						start = s.Doc.Pos()
					} else if d.Doc != nil && len(d.Specs) == 1 {
						start = d.Doc.Pos()
					}
					add(s.Name.Name, typeKind(s.Type), "", start, s.End())
				case *ast.ValueSpec:
					if s.Doc != nil {
						start = s.Doc.Pos()
					} else if d.Doc != nil && len(d.Specs) == 1 {
						start = d.Doc.Pos()
					}
					kind := SymbolVar
					if d.Tok == token.CONST {
						kind = SymbolConst
					}
					for _, name := range s.Names {
						add(name.Name, kind, "", start, s.End())
					}
				}
			}
		}
	}

	sortSymbols(symbols)
	return symbols, edges, nil
}

func typeKind(expr ast.Expr) SymbolKind {
	switch expr.(type) {
	case *ast.InterfaceType:
		return SymbolInterface
	case *ast.StructType:
		return SymbolStruct
	default:
		return SymbolType
	}
}

// receiverName reduces a receiver expression to its type name, dropping pointers and type
// parameters so that (*Server[T]) and (Server) name the same container.
func receiverName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverName(t.X)
	case *ast.IndexExpr:
		return receiverName(t.X)
	case *ast.IndexListExpr:
		return receiverName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return ""
	}
}

// G6. Declaration order is source order, which is deterministic, but a grouped ValueSpec emits
// several symbols at one position; sorting makes the total order explicit rather than incidental.
func sortSymbols(symbols []Symbol) {
	slices.SortFunc(symbols, func(a, b Symbol) int {
		if c := cmp.Compare(a.Span.StartByte, b.Span.StartByte); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Container, b.Container); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
}

// SymbolIndex is the port for symbol and dependency-graph retrieval.
type SymbolIndex interface {
	// Upsert replaces everything previously held for path.
	Upsert(revision Revision, path string, symbols []Symbol, edges []Edge) error
	// Remove drops everything held for each path.
	Remove(revision Revision, paths ...string) error
	// Lookup returns symbols matching a name, which may be bare ("Handler") or qualified
	// ("Server.Handler").
	Lookup(revision Revision, name string) ([]Symbol, error)
	// Dependencies returns the edges a path declares.
	Dependencies(revision Revision, path string) ([]Edge, error)
	// Dependents returns the edges pointing at an import path.
	Dependents(revision Revision, importPath string) ([]Edge, error)
}

// MemorySymbolIndex is an in-process implementation of SymbolIndex.
type MemorySymbolIndex struct {
	mu         sync.RWMutex
	partitions map[string]*symbolPartition
}

type symbolPartition struct {
	byPath map[string][]Symbol
	// byName indexes bare names. A qualified lookup filters this, so "Handler" and "Server.Handler"
	// share one map rather than two that could disagree.
	byName    map[string][]Symbol
	edgesFrom map[string][]Edge
	edgesTo   map[string][]Edge
}

// NewMemorySymbolIndex returns an empty in-process symbol index.
func NewMemorySymbolIndex() *MemorySymbolIndex {
	return &MemorySymbolIndex{partitions: make(map[string]*symbolPartition)}
}

var _ SymbolIndex = (*MemorySymbolIndex)(nil)

func (m *MemorySymbolIndex) partitionFor(revision Revision, create bool) *symbolPartition {
	key := revision.Key()
	p := m.partitions[key]
	if p == nil && create {
		p = &symbolPartition{
			byPath:    make(map[string][]Symbol),
			byName:    make(map[string][]Symbol),
			edgesFrom: make(map[string][]Edge),
			edgesTo:   make(map[string][]Edge),
		}
		m.partitions[key] = p
	}
	return p
}

// Upsert implements SymbolIndex.
func (m *MemorySymbolIndex) Upsert(revision Revision, p string, symbols []Symbol, edges []Edge) error {
	normalized := normalizePath(p)
	if normalized == "" {
		return modberr.New(modberr.CodeInvalidArgument, "a symbol upsert must name a path").
			WithDetail("field", "path")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	part := m.partitionFor(revision, true)
	part.retract(normalized) // G5
	for _, s := range symbols {
		s.Path = normalized
		part.byPath[normalized] = append(part.byPath[normalized], s)
		part.byName[s.Name] = append(part.byName[s.Name], s)
	}
	for _, e := range edges {
		e.From = normalized
		part.edgesFrom[normalized] = append(part.edgesFrom[normalized], e)
		part.edgesTo[e.To] = append(part.edgesTo[e.To], e)
	}
	return nil
}

// Remove implements SymbolIndex.
func (m *MemorySymbolIndex) Remove(revision Revision, paths ...string) error {
	if len(paths) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	part := m.partitionFor(revision, false)
	if part == nil {
		return nil
	}
	for _, p := range paths {
		part.retract(normalizePath(p))
	}
	return nil
}

// retract drops everything a path contributed. G4 depends on it reaching every index: a symbol left
// in byName would keep answering lookups for a file that no longer exists.
func (p *symbolPartition) retract(pathKey string) {
	for _, s := range p.byPath[pathKey] {
		remaining := p.byName[s.Name][:0]
		for _, existing := range p.byName[s.Name] {
			if existing.Path != pathKey {
				remaining = append(remaining, existing)
			}
		}
		if len(remaining) == 0 {
			delete(p.byName, s.Name)
		} else {
			p.byName[s.Name] = remaining
		}
	}
	delete(p.byPath, pathKey)

	for _, e := range p.edgesFrom[pathKey] {
		remaining := p.edgesTo[e.To][:0]
		for _, existing := range p.edgesTo[e.To] {
			if existing.From != pathKey {
				remaining = append(remaining, existing)
			}
		}
		if len(remaining) == 0 {
			delete(p.edgesTo, e.To)
		} else {
			p.edgesTo[e.To] = remaining
		}
	}
	delete(p.edgesFrom, pathKey)
}

// Lookup implements SymbolIndex.
func (m *MemorySymbolIndex) Lookup(revision Revision, name string) ([]Symbol, error) {
	if name == "" {
		return nil, nil
	}
	container, bare, qualified := strings.Cut(name, ".")
	if !qualified {
		bare = container
		container = ""
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	// G1.
	part := m.partitionFor(revision, false)
	if part == nil {
		return nil, nil
	}

	var out []Symbol
	for _, s := range part.byName[bare] {
		if container != "" && s.Container != container {
			continue
		}
		out = append(out, s)
	}
	sortSymbolsByLocation(out)
	return out, nil
}

// Dependencies implements SymbolIndex.
func (m *MemorySymbolIndex) Dependencies(revision Revision, p string) ([]Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	part := m.partitionFor(revision, false)
	if part == nil {
		return nil, nil
	}
	return sortedEdges(part.edgesFrom[normalizePath(p)]), nil
}

// Dependents implements SymbolIndex.
func (m *MemorySymbolIndex) Dependents(revision Revision, importPath string) ([]Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	part := m.partitionFor(revision, false)
	if part == nil {
		return nil, nil
	}
	return sortedEdges(part.edgesTo[importPath]), nil
}

// G6. Both accessors sort, because both read from maps whose iteration order is random and both feed
// results a run can be asked to reproduce.
func sortSymbolsByLocation(symbols []Symbol) {
	slices.SortFunc(symbols, func(a, b Symbol) int {
		if c := cmp.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return cmp.Compare(a.Span.StartByte, b.Span.StartByte)
	})
}

func sortedEdges(edges []Edge) []Edge {
	if len(edges) == 0 {
		return nil
	}
	out := slices.Clone(edges)
	slices.SortFunc(out, func(a, b Edge) int {
		if c := cmp.Compare(a.From, b.From); c != 0 {
			return c
		}
		if c := cmp.Compare(a.To, b.To); c != 0 {
			return c
		}
		return cmp.Compare(a.Span.StartByte, b.Span.StartByte)
	})
	return out
}

// ExtractChangeSet updates a symbol index from one reindex delta.
//
// It mirrors ApplyChangeSet and EmbedChangeSet: removals first, the classifier's gate applied per
// entry, and a file that cannot be read or parsed costs its own symbols rather than the batch's.
func ExtractChangeSet(idx SymbolIndex, extractor SymbolExtractor, revision Revision, set ChangeSet, read func(path string) ([]byte, error)) error {
	if idx == nil {
		return modberr.New(modberr.CodeInvalidArgument, "extracting a change set requires an index").
			WithDetail("field", "index")
	}
	if extractor == nil {
		return modberr.New(modberr.CodeInvalidArgument, "extracting a change set requires an extractor").
			WithDetail("field", "extractor")
	}
	if read == nil {
		return modberr.New(modberr.CodeInvalidArgument, "extracting a change set requires a reader").
			WithDetail("field", "read")
	}

	if len(set.Removals) > 0 {
		if err := idx.Remove(revision, set.Removals...); err != nil {
			return err
		}
	}

	degraded := 0
	for _, entry := range set.Upserts {
		if entry.IsDir || !entry.Indexable() || !extractor.Handles(entry.Path) {
			continue
		}
		content, err := read(entry.Path)
		if err != nil {
			degraded++
			continue
		}
		symbols, edges, err := extractor.Extract(entry, content)
		if err != nil {
			// G8. A repository mid-edit routinely holds a file that does not parse. Stopping here
			// would leave every later file unindexed for a condition the user is about to fix.
			degraded++
			// Whatever the path held before is now wrong, so it is retracted rather than left stale.
			if err := idx.Remove(revision, entry.Path); err != nil {
				return err
			}
			continue
		}
		if err := idx.Upsert(revision, entry.Path, symbols, edges); err != nil {
			return err
		}
	}

	if degraded > 0 {
		return modberr.New(modberr.CodeContextDegraded,
			"some files could not be read or parsed and are missing from the symbol index").
			WithDetail("degraded_channels", "symbol")
	}
	return nil
}

// PackageOf returns the directory a repository-relative path sits in, which is the unit an import
// edge resolves against for languages whose packages are directories.
func PackageOf(p string) string {
	dir := path.Dir(normalizePath(p))
	if dir == "." {
		return ""
	}
	return dir
}
