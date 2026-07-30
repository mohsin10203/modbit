package sharedcontext_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/authz"
	"github.com/modbit/modbit/pkg/sharedcontext"
)

// LCX invariants (L1–L9). One test each; a test without an L-number, or an L-number without a test,
// is a gap.
//
//	L1 LCX-8: a match whose source will not resolve is dropped, not returned as a placeholder.
//	L2 Authorization runs per requester at query time, and an incomplete evaluation is not an allow.
//	L3 Encryption is not authorization: an encrypted index takes the identical path.
//	L4 IAM-5/INV-10: a match resolving outside the requested Space never reaches the authorizer.
//	L5 The reported total is post-filter, and a filtered match leaves no trace.
//	L6 LCX-9: a delegated retrieval cannot exceed the delegation, and an empty delegation is not all.
//	L7 LCX-5: partial availability is declared, and the zero Retrieval does not claim completeness.
//	L8 A missing resolver or authorizer fails closed rather than returning everything.
//	L9 Results are ordered by score, so truncation by a caller drops the least relevant.

// resolver maps refs to sources; a ref that is absent does not resolve.
type resolver map[string]sharedcontext.Source

func (r resolver) Resolve(ref string) (sharedcontext.Source, bool) {
	s, ok := r[ref]
	return s, ok
}

// authorizer allows every dimension unless the path is in deny, and can be asked to omit a
// dimension entirely so a gap is distinguishable from a denial.
type authorizer struct {
	deny  map[string]bool
	omit  authz.Dimension
	asked []sharedcontext.Source
}

func (a *authorizer) Evaluate(r sharedcontext.Requester, s sharedcontext.Source) authz.Evaluation {
	a.asked = append(a.asked, s)
	e := authz.Evaluation{}
	for _, d := range authz.Dimensions() {
		if d == a.omit {
			continue
		}
		if a.deny[s.Path] {
			e[d] = authz.Deny
			continue
		}
		e[d] = authz.Allow
	}
	return e
}

func source(space, path string) sharedcontext.Source {
	return sharedcontext.Source{
		SpaceID: space, RepositoryID: "acme/repo", Path: path, Revision: "abc123",
	}
}

func requester() sharedcontext.Requester {
	return sharedcontext.Requester{SubjectID: "user-1", SpaceID: "space-a"}
}

func wholeIndex() sharedcontext.Index {
	return sharedcontext.Index{Partitions: []string{"p1", "p2"}, Answered: []string{"p1", "p2"}}
}

// L1. LCX-8: a match whose source will not resolve is dropped.
//
// The tempting alternative is a "restricted result" with the content stripped, and that is an
// existence oracle: an attacker who can phrase queries learns which ones hit something.
func TestSecurityAnUnresolvableMatchIsDroppedNotPlaceheld(t *testing.T) {
	res := resolver{"ref-ok": source("space-a", "src/a.go")}
	auth := &authorizer{}

	got, err := sharedcontext.Retrieve(requester(), []sharedcontext.Match{
		{SourceRef: "ref-ok", Score: 0.9, Snippet: "func A()"},
		{SourceRef: "ref-gone", Score: 0.95, Snippet: "SECRET CONTENT"},
	}, wholeIndex(), res, auth)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}

	if len(got.Items) != 1 {
		t.Fatalf("items = %d, want only the resolvable one", len(got.Items))
	}
	if got.Items[0].Source.Path != "src/a.go" {
		t.Fatalf("item = %v, want the resolvable match", got.Items[0])
	}
	// Nothing of the dropped match survives, including the fact that it scored higher.
	for _, it := range got.Items {
		if strings.Contains(it.Snippet, "SECRET") {
			t.Fatal("the unresolvable match's content was returned")
		}
	}

	// A resolver that answers with an incomplete source is the same case: it has not told us enough
	// to authorize anything.
	partial := resolver{"ref-x": {SpaceID: "space-a", Path: "src/b.go"}} // no repository
	got, err = sharedcontext.Retrieve(requester(),
		[]sharedcontext.Match{{SourceRef: "ref-x", Snippet: "content"}}, wholeIndex(), partial, auth)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if len(got.Items) != 0 {
		t.Fatal("a match with an incompletely resolved source was returned")
	}
}

// L2. Authorization runs per requester at query time, and a gap is not an allow.
//
// Query time rather than index time, because permissions change after indexing and an index-time
// filter answers the question as it stood whenever the crawler last ran.
func TestSecurityAnIncompleteAuthorizationIsNotAnAllow(t *testing.T) {
	res := resolver{
		"a": source("space-a", "src/a.go"),
		"b": source("space-a", "src/secret.go"),
	}
	matches := []sharedcontext.Match{
		{SourceRef: "a", Score: 0.9, Snippet: "public"},
		{SourceRef: "b", Score: 0.8, Snippet: "confidential"},
	}

	// A denial on one source removes it and leaves the other.
	auth := &authorizer{deny: map[string]bool{"src/secret.go": true}}
	got, err := sharedcontext.Retrieve(requester(), matches, wholeIndex(), res, auth)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if len(got.Items) != 1 || got.Items[0].Source.Path != "src/a.go" {
		t.Fatalf("items = %v, want only the permitted source", got.Items)
	}
	if len(auth.asked) != 2 {
		t.Fatalf("the authorizer saw %d sources, want both", len(auth.asked))
	}

	// A dimension nobody evaluated must not read as permission. Each one in turn, because an
	// implementation checking a single dimension passes a single witness.
	for _, d := range authz.Dimensions() {
		gapped := &authorizer{omit: d}
		got, err := sharedcontext.Retrieve(requester(), matches, wholeIndex(), res, gapped)
		if err == nil && len(got.Items) > 0 {
			t.Errorf("a retrieval returned %d items with %s unevaluated", len(got.Items), d)
		}
	}
}

// L3. Encryption at rest is not access control.
//
// LCX-8 exists because "the vectors are encrypted, so the index is safe to share" sounds like an
// answer. It is not: the index is queried on somebody's behalf and returns something, and whatever
// comes back either resolves to a source they may read or it does not.
func TestSecurityAnEncryptedIndexGetsNoRelaxation(t *testing.T) {
	res := resolver{"b": source("space-a", "src/secret.go")}
	matches := []sharedcontext.Match{{SourceRef: "b", Score: 0.9, Snippet: "confidential"}}
	deny := map[string]bool{"src/secret.go": true}

	plain := wholeIndex()
	encrypted := wholeIndex()
	encrypted.Encrypted = true

	for name, idx := range map[string]sharedcontext.Index{"plain": plain, "encrypted": encrypted} {
		got, err := sharedcontext.Retrieve(requester(), matches, idx, res, &authorizer{deny: deny})
		if err != nil {
			t.Fatalf("%s: Retrieve: %v", name, err)
		}
		if len(got.Items) != 0 {
			t.Errorf("%s index returned a denied source", name)
		}
	}

	// And the two agree on the permitted case too, so the flag changes nothing in either direction.
	var plainItems, encItems int
	for _, idx := range []sharedcontext.Index{plain, encrypted} {
		got, err := sharedcontext.Retrieve(requester(), matches, idx, res, &authorizer{})
		if err != nil {
			t.Fatalf("Retrieve: %v", err)
		}
		if idx.Encrypted {
			encItems = len(got.Items)
		} else {
			plainItems = len(got.Items)
		}
	}
	if plainItems != encItems || plainItems != 1 {
		t.Fatalf("encrypted returned %d items and plain %d; the flag must change nothing",
			encItems, plainItems)
	}
}

// L4. IAM-5 and INV-10: a cross-Space match never reaches the authorizer.
//
// Checked before authorization rather than by it, because the evaluation a caller builds is for the
// requester's Space and putting another Space's source to it asks the wrong question.
func TestSecurityACrossSpaceMatchNeverReachesTheAuthorizer(t *testing.T) {
	res := resolver{
		"mine":     source("space-a", "src/a.go"),
		"theirs":   source("space-b", "src/theirs.go"),
		"noSpace":  {RepositoryID: "acme/repo", Path: "src/x.go"},
		"tenantB":  source("space-b", "src/other.go"),
		"mineToo2": source("space-a", "src/b.go"),
	}
	matches := []sharedcontext.Match{
		{SourceRef: "mine", Score: 0.5, Snippet: "ours"},
		{SourceRef: "theirs", Score: 0.99, Snippet: "ANOTHER TENANT"},
		{SourceRef: "noSpace", Score: 0.98, Snippet: "UNSCOPED"},
		{SourceRef: "tenantB", Score: 0.97, Snippet: "ANOTHER TENANT"},
		{SourceRef: "mineToo2", Score: 0.4, Snippet: "ours too"},
	}

	auth := &authorizer{}
	got, err := sharedcontext.Retrieve(requester(), matches, wholeIndex(), res, auth)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}

	for _, it := range got.Items {
		if it.Source.SpaceID != "space-a" {
			t.Fatalf("a result from Space %s crossed the boundary", it.Source.SpaceID)
		}
		if strings.Contains(it.Snippet, "ANOTHER TENANT") || strings.Contains(it.Snippet, "UNSCOPED") {
			t.Fatal("another Space's content was returned")
		}
	}
	if len(got.Items) != 2 {
		t.Fatalf("items = %d, want the two in-Space matches", len(got.Items))
	}
	// The authorizer was never asked about another Space, so no evaluation built for space-a was
	// applied to a space-b source.
	for _, asked := range auth.asked {
		if asked.SpaceID != "space-a" {
			t.Fatalf("the authorizer was asked about Space %s", asked.SpaceID)
		}
	}
}

// L5. The reported total counts what was returned.
//
// "47 matches, 3 hidden" is the same existence oracle as a placeholder result, written in a
// friendlier tone.
func TestSecurityTheTotalIsPostFilter(t *testing.T) {
	res := resolver{
		"a": source("space-a", "src/a.go"),
		"b": source("space-a", "src/secret.go"),
		"c": source("space-b", "src/theirs.go"),
	}
	matches := []sharedcontext.Match{
		{SourceRef: "a", Score: 0.9, Snippet: "public"},
		{SourceRef: "b", Score: 0.8, Snippet: "confidential"},
		{SourceRef: "c", Score: 0.7, Snippet: "other tenant"},
		{SourceRef: "gone", Score: 0.6, Snippet: "unresolvable"},
	}

	got, err := sharedcontext.Retrieve(requester(), matches, wholeIndex(), res,
		&authorizer{deny: map[string]bool{"src/secret.go": true}})
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got.Total != 1 {
		t.Fatalf("total = %d, want 1: the count must not reveal the three that were filtered",
			got.Total)
	}
	if got.Total != len(got.Items) {
		t.Fatalf("total = %d but %d items were returned", got.Total, len(got.Items))
	}

	// A requester permitted nothing gets the same shape as one whose query simply matched nothing.
	denied, err := sharedcontext.Retrieve(requester(), matches, wholeIndex(), res,
		&authorizer{deny: map[string]bool{"src/a.go": true, "src/secret.go": true}})
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	empty, err := sharedcontext.Retrieve(requester(), nil, wholeIndex(), res, &authorizer{})
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if denied.Total != empty.Total || len(denied.Items) != len(empty.Items) {
		t.Fatalf("a wholly-denied retrieval (%d) is distinguishable from an empty one (%d)",
			denied.Total, empty.Total)
	}
}

// L6. LCX-9: a delegated retrieval carries the delegating user's authority and no more.
//
// An empty delegation is the nil-versus-empty mistake again, with the tenant boundary behind it.
func TestSecurityADelegatedRetrievalCannotExceedItsDelegation(t *testing.T) {
	res := resolver{"a": source("space-a", "src/a.go")}
	matches := []sharedcontext.Match{{SourceRef: "a", Score: 0.9, Snippet: "public"}}

	within := requester()
	within.OnBehalfOf = "user-1"
	within.DelegatedSpaces = []string{"space-a", "space-c"}
	got, err := sharedcontext.Retrieve(within, matches, wholeIndex(), res, &authorizer{})
	if err != nil {
		t.Fatalf("a delegation covering the Space was refused: %v", err)
	}
	if len(got.Items) != 1 {
		t.Fatal("a properly delegated retrieval returned nothing")
	}

	outside := within
	outside.DelegatedSpaces = []string{"space-c"}
	if _, err := sharedcontext.Retrieve(outside, matches, wholeIndex(), res, &authorizer{}); err == nil {
		t.Fatal("a delegation not covering the Space produced a retrieval")
	}

	// An empty delegation conveys nothing; reading it as "all Spaces" is the failure.
	none := within
	none.DelegatedSpaces = nil
	err = none.Validate()
	if err == nil {
		t.Fatal("a delegation naming no Spaces was read as authority over some")
	}
	if !strings.Contains(err.Error(), "no Spaces") {
		t.Fatalf("error = %v; it must say the delegation conveys nothing", err)
	}

	// A non-delegated requester needs no delegation list, so the check is about delegation.
	if err := requester().Validate(); err != nil {
		t.Fatalf("a direct retrieval was refused: %v", err)
	}
	if requester().Delegated() {
		t.Fatal("a requester with no OnBehalfOf reported itself delegated")
	}
	for name, mutate := range map[string]func(*sharedcontext.Requester){
		"no subject": func(r *sharedcontext.Requester) { r.SubjectID = "" },
		"no space":   func(r *sharedcontext.Requester) { r.SpaceID = " " },
	} {
		r := requester()
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: an unscoped retrieval validated", name)
		}
	}
}

// L7. LCX-5: partial availability is declared.
//
// A retrieval over a partly-available index that presents itself as whole is worse than one that
// admits the gap: the caller's next move — concluding the codebase does not contain the thing — is
// wrong in a way nothing corrects.
func TestSecurityPartialAvailabilityIsDeclared(t *testing.T) {
	res := resolver{"a": source("space-a", "src/a.go")}
	matches := []sharedcontext.Match{{SourceRef: "a", Score: 0.9, Snippet: "public"}}

	whole, err := sharedcontext.Retrieve(requester(), matches, wholeIndex(), res, &authorizer{})
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if !whole.Complete {
		t.Fatal("a retrieval over a fully available index reported itself incomplete")
	}
	if len(whole.Missing) != 0 {
		t.Fatalf("missing = %v on a complete retrieval", whole.Missing)
	}

	degraded := sharedcontext.Index{
		Partitions: []string{"p1", "p2", "p3"}, Answered: []string{"p2"},
	}
	part, err := sharedcontext.Retrieve(requester(), matches, degraded, res, &authorizer{})
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if part.Complete {
		t.Fatal("a retrieval missing two partitions reported itself complete")
	}
	if len(part.Missing) != 2 || part.Missing[0] != "p1" || part.Missing[1] != "p3" {
		t.Fatalf("missing = %v, want p1 and p3 named", part.Missing)
	}
	// Results still come back — partial availability degrades the answer, it does not refuse it.
	if len(part.Items) != 1 {
		t.Fatalf("items = %d, want the available partition's result", len(part.Items))
	}

	// The zero Retrieval does not claim to be a whole answer.
	var zero sharedcontext.Retrieval
	if zero.Complete {
		t.Fatal("the zero Retrieval reports itself complete")
	}
}

// L8. A missing resolver or authorizer fails closed.
//
// Without this, a nil authorizer is the shortest path to returning everything unfiltered.
func TestSecurityAMissingResolverOrAuthorizerFailsClosed(t *testing.T) {
	res := resolver{"a": source("space-a", "src/a.go")}
	matches := []sharedcontext.Match{{SourceRef: "a", Score: 0.9, Snippet: "public"}}

	if _, err := sharedcontext.Retrieve(requester(), matches, wholeIndex(), nil, &authorizer{}); err == nil {
		t.Fatal("a retrieval with no resolver returned")
	}
	got, err := sharedcontext.Retrieve(requester(), matches, wholeIndex(), res, nil)
	if err == nil {
		t.Fatal("a retrieval with no authorizer returned")
	}
	if len(got.Items) != 0 {
		t.Fatal("a failed retrieval carried items")
	}
}

// L9. Results are ordered by score, so a caller truncating to a top-N drops the least relevant
// rather than whatever the index happened to emit last.
func TestResultsAreOrderedByScore(t *testing.T) {
	res := resolver{
		"a": source("space-a", "src/a.go"),
		"b": source("space-a", "src/b.go"),
		"c": source("space-a", "src/c.go"),
	}
	got, err := sharedcontext.Retrieve(requester(), []sharedcontext.Match{
		{SourceRef: "b", Score: 0.5, Snippet: "mid"},
		{SourceRef: "a", Score: 0.9, Snippet: "top"},
		{SourceRef: "c", Score: 0.1, Snippet: "low"},
	}, wholeIndex(), res, &authorizer{})
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if len(got.Items) != 3 {
		t.Fatalf("items = %d, want 3", len(got.Items))
	}
	for i := 1; i < len(got.Items); i++ {
		if got.Items[i-1].Score < got.Items[i].Score {
			t.Fatalf("scores out of order: %v", got.Items)
		}
	}
}
