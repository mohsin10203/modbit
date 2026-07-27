// Package taint implements provenance classification and propagation for run context.
//
// Boundary: the class lattice, propagation arithmetic, and the per-run ledger. It does not decide
// approvals — pkg/policy consumes a Set as a policy input dimension — and it does not attach
// classes to content; the Provenance Tagger in the context plane does that at context-pack
// assembly.
//
// Requirements: PRD v5.1 §12A. TNT-1 (every unit of context carries a class), TNT-2 (propagation
// and declassification), TNT-5 (visibility through events and the ledger), TNT-6 (unknown
// provenance fails closed to the highest-risk class).
//
// # Why an ordinal lattice
//
// Propagation must answer "what is the risk of content derived from these inputs" with a single
// value, deterministically, in the microseconds available inside a policy decision (SDD §18 budgets
// taint evaluation at under 10 ms p95 for the whole decision). A total order over classes makes
// propagation a maximum and makes a Set a bitmask, so a run's accumulated taint is one machine word
// and membership tests are constant time.
//
// The ordering below is a Modbit default, not a fact stated by the PRD: the PRD fixes the class
// names (TNT-1) and names web, mcp-result, and repository-untrusted as the default escalation
// triggers (TNT-4), but does not rank them against each other. Policy selects trigger classes
// explicitly through taint.escalation.trigger_classes, so the ranking here only decides what
// "highest risk" resolves to for unknown provenance and for propagation.
package taint

import (
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// Class is a provenance class (TNT-1).
type Class uint8

// Classes, ordered from least to most risky. The zero value is UserTrusted, which is deliberate:
// an uninitialized Class is the *lowest* privilege claim, not an accidental grant. Code that has
// not classified its input must call Unknown, not rely on the zero value.
const (
	// UserTrusted is direct user input received through a trusted Modbit surface.
	UserTrusted Class = iota
	// Generated is model-produced content. On its own it means "derived from trusted input";
	// content generated from tainted input inherits the higher class through Propagate.
	Generated
	// ToolResult is output from a local or platform tool.
	ToolResult
	// Integration is a normalized inbound event from a connected integration.
	Integration
	// RepositoryUntrusted is repository content, including repository-authored instructions.
	RepositoryUntrusted
	// Web is search results, fetched pages, and browser-extracted content.
	Web
	// MCPResult is output from an MCP server. It ranks highest among provenance classes because an
	// MCP server is remote, third-party, and returns tool-shaped output that a model is predisposed
	// to act on.
	MCPResult
	// KnownSecret marks content a detector positively identified as credential material. It sits
	// above every provenance class because it is a different kind of claim: the others describe
	// where content came from, this one describes what it contains.
	//
	// It is sticky. Declassify refuses it outright; the only way down is RedactSecret, which
	// requires a verification artifact proving the redaction actually happened. A secret that can be
	// argued away with a rationale is not confined at all.
	KnownSecret
)

// maxClass is the highest-risk registered class, used when an out-of-range value must be coerced.
const maxClass = KnownSecret

// unknownProvenanceClass is what unverifiable provenance resolves to (TNT-6).
//
// It is deliberately MCPResult rather than KnownSecret. Failing closed means assuming the worst
// *provenance*, not asserting a fact we do not have: content of unknown origin is not known to
// contain a secret, and classifying it as one would make it undeclassifiable forever.
const unknownProvenanceClass = MCPResult

var classNames = map[Class]string{
	UserTrusted:         "user_trusted",
	Generated:           "generated",
	ToolResult:          "tool_result",
	Integration:         "integration",
	RepositoryUntrusted: "repository_untrusted",
	Web:                 "web",
	MCPResult:           "mcp_result",
	KnownSecret:         "known_secret",
}

var classByName = func() map[string]Class {
	out := make(map[string]Class, len(classNames))
	for c, n := range classNames {
		out[n] = c
		// Accept the hyphenated spelling used in PRD prose so a policy authored from the document
		// resolves identically to one authored from the settings contract.
		out[strings.ReplaceAll(n, "_", "-")] = c
	}
	return out
}()

// String returns the canonical snake_case name.
func (c Class) String() string {
	if n, ok := classNames[c]; ok {
		return n
	}
	return "unknown"
}

// Valid reports whether c is a registered class.
func (c Class) Valid() bool {
	_, ok := classNames[c]
	return ok
}

// Highest returns the highest-risk registered class, which is KnownSecret.
func Highest() Class { return maxClass }

// Classes returns every registered class, least risky first.
func Classes() []Class {
	out := make([]Class, 0, len(classNames))
	for c := range classNames {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ParseClass resolves a class name.
//
// An unrecognized name resolves to the highest-risk class and returns an error. Both are returned
// on purpose: the caller must be able to record the diagnostic, and must not be able to accidentally
// continue with a permissive value if it ignores the error (TNT-6, fail closed).
func ParseClass(name string) (Class, error) {
	if c, ok := classByName[strings.ToLower(strings.TrimSpace(name))]; ok {
		return c, nil
	}
	return unknownProvenanceClass, modberr.Newf(modberr.CodeInvalidArgument,
		"unrecognized provenance class %q; failing closed to %q", name, unknownProvenanceClass).
		WithDetail("field", "taint_class").
		WithDetail("constraint", "registered_class")
}

// Propagate returns the class that content derived from inputs inherits: the highest-risk
// contributing class (TNT-2).
//
// Deriving with no inputs returns UserTrusted, because content with no tainted contributor has no
// taint to inherit. Callers that cannot enumerate their inputs must use Unknown instead.
func Propagate(inputs ...Class) Class {
	out := UserTrusted
	for _, c := range inputs {
		if !c.Valid() {
			// An out-of-range class is unverifiable provenance, which fails closed (TNT-6).
			return unknownProvenanceClass
		}
		if c > out {
			out = c
		}
	}
	return out
}

// Unknown returns the class assigned to content whose provenance cannot be verified (TNT-6).
//
// This is the highest-risk *provenance* class, not Highest(): see unknownProvenanceClass.
func Unknown() Class { return unknownProvenanceClass }

// Set is the set of classes present in a run context.
//
// It is a bitmask so that a run's accumulated taint is one word, membership is constant time, and a
// policy decision can carry it by value without allocating.
type Set uint32

// NewSet returns a Set containing classes.
func NewSet(classes ...Class) Set {
	var s Set
	for _, c := range classes {
		s = s.With(c)
	}
	return s
}

// With returns a copy of s including c. An invalid class is recorded as the highest-risk class
// rather than being dropped.
func (s Set) With(c Class) Set {
	if !c.Valid() {
		c = unknownProvenanceClass
	}
	return s | Set(1)<<c
}

// Contains reports whether c is present.
func (s Set) Contains(c Class) bool { return s&(Set(1)<<c) != 0 }

// ContainsAny reports whether any of classes is present. This is the hot path for TNT-4 trigger
// evaluation.
func (s Set) ContainsAny(classes ...Class) bool {
	for _, c := range classes {
		if s.Contains(c) {
			return true
		}
	}
	return false
}

// Empty reports whether no class is present.
func (s Set) Empty() bool { return s == 0 }

// Len returns the number of distinct classes present.
func (s Set) Len() int { return bits.OnesCount32(uint32(s)) }

// Max returns the highest-risk class present, and false when the set is empty.
func (s Set) Max() (Class, bool) {
	if s == 0 {
		return UserTrusted, false
	}
	return Class(31 - bits.LeadingZeros32(uint32(s))), true
}

// Slice returns the classes present, least risky first.
func (s Set) Slice() []Class {
	out := make([]Class, 0, s.Len())
	for _, c := range Classes() {
		if s.Contains(c) {
			out = append(out, c)
		}
	}
	return out
}

// Union returns the union of s and other.
func (s Set) Union(other Set) Set { return s | other }

// String renders the set for events, chips, and audit records.
func (s Set) String() string {
	names := make([]string, 0, s.Len())
	for _, c := range s.Slice() {
		names = append(names, c.String())
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// Entry records one unit of tainted content entering a run context (TNT-1, TNT-5).
type Entry struct {
	ID    id.ID
	Class Class
	// Source describes where the content came from — a context item id, a tool name, an MCP server
	// id, or a URL host. It never contains the content itself.
	Source string
	// DerivedFrom lists the entries this one inherited from, so the propagation tree is
	// reconstructible for the taint ledger artifact (modbit.run.taint).
	DerivedFrom []id.ID
	EnteredAt   time.Time
}

// Declassification records an authorized downgrade (TNT-2).
type Declassification struct {
	ID      id.ID
	EntryID id.ID
	// From and To record the downgrade. To is always lower risk than From.
	From Class
	To   Class
	// Actor and Rationale are mandatory: a declassification without an accountable human is not a
	// declassification, it is a bypass.
	Actor     string
	Rationale string
	// VerificationRef points at the artifact proving a redaction happened. It is set only by
	// RedactSecret; an ordinary declassification leaves it zero.
	VerificationRef id.ID
	DeclassifiedAt  time.Time
}

// Ledger is the append-only taint record for one run.
//
// It is not safe for concurrent use; a run's taint is mutated on the run's own transition path,
// which holds the single active transition lease (R-EVT-06).
type Ledger struct {
	runID             id.ID
	entries           []Entry
	declassifications []Declassification
	// set is maintained incrementally so a policy decision reads a precomputed value rather than
	// walking the ledger (SDD §18: taint adds under 10 ms p95 to a policy decision).
	set Set
	// firstEntry records when each class first entered, which is what makes the TNT-4 carve-out
	// decidable: an operation declared in the plan *before* the taint entered is exempt.
	firstEntry map[Class]time.Time
	generator  *id.Generator
}

// NewLedger returns an empty Ledger for runID. A nil generator means the process CSPRNG.
func NewLedger(runID id.ID, generator *id.Generator) (*Ledger, error) {
	if !runID.HasPrefix(id.Run) {
		return nil, modberr.New(modberr.CodeInvalidArgument, "taint ledger requires a run identifier").
			WithDetail("field", "run_id")
	}
	if generator == nil {
		generator = id.NewGenerator(nil)
	}
	return &Ledger{
		runID:      runID,
		firstEntry: make(map[Class]time.Time, len(classNames)),
		generator:  generator,
	}, nil
}

// RunID returns the run this ledger belongs to.
func (l *Ledger) RunID() id.ID { return l.runID }

// Record appends an entry for content entering the run context and returns it.
//
// An invalid class is recorded as the highest-risk class rather than rejected: refusing the entry
// would leave the content in context with no taint at all, which is strictly worse than
// over-classifying it (TNT-6).
func (l *Ledger) Record(class Class, source string, at time.Time, derivedFrom ...id.ID) (Entry, error) {
	if !class.Valid() {
		class = maxClass
	}
	entryID, err := l.generator.New(id.TaintEntry)
	if err != nil {
		return Entry{}, modberr.Wrap(err, modberr.CodeInternal, "allocate taint entry identifier")
	}
	e := Entry{
		ID:          entryID,
		Class:       class,
		Source:      source,
		DerivedFrom: append([]id.ID(nil), derivedFrom...),
		EnteredAt:   at.UTC(),
	}
	l.entries = append(l.entries, e)
	if !l.set.Contains(class) {
		l.firstEntry[class] = e.EnteredAt
	}
	l.set = l.set.With(class)
	return e, nil
}

// Derive records content produced from existing entries, inheriting the highest contributing class
// (TNT-2). This is the path that closes the laundering gap: summarizing tainted content through a
// model still yields a tainted entry.
func (l *Ledger) Derive(source string, at time.Time, from ...Entry) (Entry, error) {
	classes := make([]Class, 0, len(from))
	refs := make([]id.ID, 0, len(from))
	for _, e := range from {
		classes = append(classes, e.Class)
		refs = append(refs, e.ID)
	}
	inherited := Propagate(classes...)
	// Derived content is at least Generated: a model rewriting trusted input still produces content
	// the platform did not receive directly from the user.
	if inherited < Generated {
		inherited = Generated
	}
	return l.Record(inherited, source, at, refs...)
}

// Declassify downgrades an entry, recording the accountable actor and rationale.
//
// It refuses to raise risk, to no-op, to act on an unknown entry, or to proceed without both an
// actor and a rationale. Every rejection is an error rather than a silent skip, because a
// declassification that appears to have happened but did not is the worst possible outcome.
func (l *Ledger) Declassify(entryID id.ID, to Class, actor, rationale string, at time.Time) (Declassification, error) {
	if strings.TrimSpace(actor) == "" {
		return Declassification{}, modberr.New(modberr.CodePermissionDenied,
			"declassification requires an accountable actor").WithDetail("resource_type", "taint_entry")
	}
	if strings.TrimSpace(rationale) == "" {
		return Declassification{}, modberr.New(modberr.CodeInvalidArgument,
			"declassification requires a rationale").WithDetail("field", "rationale")
	}
	if !to.Valid() {
		return Declassification{}, modberr.New(modberr.CodeInvalidArgument,
			"declassification target is not a registered class").WithDetail("field", "to")
	}
	idx := -1
	for i := range l.entries {
		if l.entries[i].ID == entryID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Declassification{}, modberr.New(modberr.CodeNotFound, "taint entry not found").
			WithDetail("resource_type", "taint_entry")
	}
	from := l.entries[idx].Class
	if from == KnownSecret {
		return Declassification{}, modberr.New(modberr.CodePolicyDenied,
			"known-secret content cannot be declassified by rationale; it must be redacted and the redaction verified").
			WithDetail("rule_id", "taint.known_secret_sticky").
			WithDetail("side_effect_class", "declassification")
	}
	if to >= from {
		return Declassification{}, modberr.Newf(modberr.CodeInvalidArgument,
			"declassification must lower risk: %q is not below %q", to, from).
			WithDetail("field", "to").
			WithDetail("constraint", "lower_risk")
	}

	declassID, err := l.generator.New(id.Declassification)
	if err != nil {
		return Declassification{}, modberr.Wrap(err, modberr.CodeInternal, "allocate declassification identifier")
	}
	d := Declassification{
		ID:             declassID,
		EntryID:        entryID,
		From:           from,
		To:             to,
		Actor:          actor,
		Rationale:      rationale,
		DeclassifiedAt: at.UTC(),
	}
	l.entries[idx].Class = to
	l.declassifications = append(l.declassifications, d)
	l.recomputeSet()
	return d, nil
}

// RedactSecret lowers a known-secret entry after a verified redaction.
//
// It is the only way out of the KnownSecret class, and it requires a verification artifact
// reference rather than a rationale. The distinction is the whole point: a declassification asserts
// a judgement, whereas a redaction asserts a fact that something else checked. Accepting prose here
// would make the sticky class decorative.
func (l *Ledger) RedactSecret(entryID id.ID, to Class, actor, rationale string, verification id.ID, at time.Time) (Declassification, error) {
	if strings.TrimSpace(actor) == "" {
		return Declassification{}, modberr.New(modberr.CodePermissionDenied,
			"redaction requires an accountable actor").WithDetail("resource_type", "taint_entry")
	}
	if strings.TrimSpace(rationale) == "" {
		return Declassification{}, modberr.New(modberr.CodeInvalidArgument,
			"redaction requires a rationale").WithDetail("field", "rationale")
	}
	if !verification.HasPrefix(id.Evidence) && !verification.HasPrefix(id.Artifact) {
		return Declassification{}, modberr.New(modberr.CodeEvidenceMissing,
			"redaction requires a verification artifact proving the content was removed").
			WithDetail("missing_evidence_kind", "redaction_verification")
	}
	if !to.Valid() || to >= KnownSecret {
		return Declassification{}, modberr.New(modberr.CodeInvalidArgument,
			"redaction must lower the class below known_secret").WithDetail("field", "to")
	}

	idx := -1
	for i := range l.entries {
		if l.entries[i].ID == entryID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Declassification{}, modberr.New(modberr.CodeNotFound, "taint entry not found").
			WithDetail("resource_type", "taint_entry")
	}
	if l.entries[idx].Class != KnownSecret {
		return Declassification{}, modberr.New(modberr.CodeInvalidArgument,
			"RedactSecret applies only to known-secret entries; use Declassify").
			WithDetail("field", "entry_id")
	}

	declassID, err := l.generator.New(id.Declassification)
	if err != nil {
		return Declassification{}, modberr.Wrap(err, modberr.CodeInternal, "allocate redaction identifier")
	}
	d := Declassification{
		ID: declassID, EntryID: entryID, From: KnownSecret, To: to,
		Actor: actor, Rationale: rationale, VerificationRef: verification, DeclassifiedAt: at.UTC(),
	}
	l.entries[idx].Class = to
	l.declassifications = append(l.declassifications, d)
	l.recomputeSet()
	return d, nil
}

// recomputeSet rebuilds the cached set and first-entry times after a declassification. A
// declassification is rare, so the linear rebuild is cheaper than maintaining reference counts on
// the hot Record path.
func (l *Ledger) recomputeSet() {
	l.set = 0
	l.firstEntry = make(map[Class]time.Time, len(classNames))
	for _, e := range l.entries {
		if existing, ok := l.firstEntry[e.Class]; !ok || e.EnteredAt.Before(existing) {
			l.firstEntry[e.Class] = e.EnteredAt
		}
		l.set = l.set.With(e.Class)
	}
}

// Set returns the run's current taint set.
func (l *Ledger) Set() Set { return l.set }

// FirstEntry returns when c first entered the run context.
func (l *Ledger) FirstEntry(c Class) (time.Time, bool) {
	t, ok := l.firstEntry[c]
	return t, ok
}

// EarliestEntry returns the earliest time any of classes entered the run context, which is the
// reference point for the TNT-4 plan-declaration carve-out.
func (l *Ledger) EarliestEntry(classes ...Class) (time.Time, bool) {
	var earliest time.Time
	found := false
	for _, c := range classes {
		t, ok := l.firstEntry[c]
		if !ok {
			continue
		}
		if !found || t.Before(earliest) {
			earliest, found = t, true
		}
	}
	return earliest, found
}

// Entries returns a copy of the ledger entries in insertion order.
func (l *Ledger) Entries() []Entry {
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Declassifications returns a copy of the declassification records.
func (l *Ledger) Declassifications() []Declassification {
	out := make([]Declassification, len(l.declassifications))
	copy(out, l.declassifications)
	return out
}

// MarshalText renders a Class for JSON and event payloads.
func (c Class) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// UnmarshalText parses a Class, failing closed to the highest-risk class on an unknown name.
func (c *Class) UnmarshalText(text []byte) error {
	parsed, err := ParseClass(string(text))
	*c = parsed
	return err
}

// MarshalText renders a Set as a comma-separated class list.
func (s Set) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses a comma-separated class list. Unknown names fail closed and are reported.
func (s *Set) UnmarshalText(text []byte) error {
	*s = 0
	raw := strings.TrimSpace(string(text))
	if raw == "" || raw == "none" {
		return nil
	}
	var firstErr error
	for _, name := range strings.Split(raw, ",") {
		c, err := ParseClass(name)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("taint set contains an unrecognized class: %w", err)
		}
		*s = s.With(c)
	}
	return firstErr
}
