// Package sharedcontext resolves and authorizes retrievals from a shared index (LCX-8, LCX-9).
//
// Boundary: it decides which similarity matches a requester may receive. It builds no index,
// computes no embedding, and ranks nothing — a caller supplies matches and the means to resolve and
// authorize them, and this decides what comes back.
//
// Requirements: PRD §8A.3 LCX-5 (partial availability), LCX-8 (shared context must specify
// authorized source resolution; encrypted embeddings alone are not a complete shared-context
// architecture), LCX-9 (a Context Gateway may serve authorized context to remote agents), §17
// IAM-5 (access to indexes follows tenant and Space boundaries). INV-10 makes a cross-Space leak a
// release blocker.
//
// # Why encryption is not authorization
//
// LCX-8 exists because encrypted embeddings look like they solve the sharing problem and do not.
// The PRD lists "encrypted embeddings alone are not described as searchable shared context" among
// the proposal elements it rejected outright, which is unusual — it is the requirement telling you
// what argument it expects to hear.
//
// The argument is that if the vectors are encrypted, the index is safe to share. It is not, because
// the index is *queried on somebody's behalf* and the query returns something. Whatever comes back
// either resolves to a source the requester may read or it does not, and encryption at rest changes
// neither. So an index declared encrypted takes exactly the same resolution and authorization path
// as one that is not, and there is no flag anywhere in this package that relaxes it.
//
// # An unresolvable match is dropped, not placeheld
//
// A match whose source cannot be resolved is one we cannot say anything about — including whether
// the requester may see that it exists. The tempting alternative is to return it with the content
// stripped, as a "restricted result", and that is an existence oracle: an attacker who can phrase
// queries learns which of them hit something. So it is dropped and not counted.
//
// # The count is post-filter
//
// For the same reason, the returned total counts what the requester received. "47 matches, 3
// hidden" is the same oracle written in a friendlier tone.
package sharedcontext

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/authz"
	"github.com/modbit/modbit/pkg/modberr"
)

// Source is where a match came from, resolved at query time.
//
// Resolved at query time rather than stored with the vector, because permissions change after
// indexing and an index-time filter answers the question as it stood whenever the crawler last ran.
type Source struct {
	SpaceID      string `json:"space_id"`
	RepositoryID string `json:"repository_id"`
	Path         string `json:"path"`
	Revision     string `json:"revision"`
}

// Valid reports whether a resolved source names everything needed to authorize it.
func (s Source) Valid() bool {
	return strings.TrimSpace(s.SpaceID) != "" &&
		strings.TrimSpace(s.RepositoryID) != "" &&
		strings.TrimSpace(s.Path) != ""
}

// Match is a similarity hit from the index, before resolution or authorization.
type Match struct {
	// SourceRef is the index's opaque handle for whatever this vector was built from.
	SourceRef string `json:"source_ref"`
	Score     float64
	// Snippet is content. It leaves this package only on an authorized item.
	Snippet string
}

// Item is an authorized result.
type Item struct {
	Source  Source  `json:"source"`
	Score   float64 `json:"score"`
	Snippet string  `json:"snippet"`
}

// Resolver turns an index's opaque reference into a source, or reports that it cannot.
//
// Reporting that it cannot is a first-class answer rather than an error: a reference can go stale
// because the file was deleted or the repository was detached, and that is ordinary. What must not
// happen is the match being returned anyway.
type Resolver interface {
	Resolve(ref string) (Source, bool)
}

// Authorizer supplies the per-dimension evaluation for a requester against a source.
//
// It returns an evaluation rather than a boolean so an incomplete authorization path is visible as
// a gap. A boolean would make "nobody checked Space membership" indistinguishable from "Space
// membership allowed".
type Authorizer interface {
	Evaluate(r Requester, s Source) authz.Evaluation
}

// Requester is who a retrieval is for.
type Requester struct {
	// SubjectID is the identity the retrieval runs as.
	SubjectID string `json:"subject_id"`
	// SpaceID is the Space being searched. Matches resolving outside it are dropped (IAM-5).
	SpaceID string `json:"space_id"`
	// OnBehalfOf is set when a remote agent retrieves for a user (LCX-9). The agent's authority is
	// the user's; see Validate for why it cannot exceed it.
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
	// DelegatedSpaces bounds what a delegated retrieval may reach. Empty means the delegation
	// carries no Space authority at all, which is why a delegated requester must name one.
	DelegatedSpaces []string `json:"delegated_spaces,omitempty"`
}

// Delegated reports whether this retrieval runs on someone else's behalf (LCX-9).
func (r Requester) Delegated() bool { return strings.TrimSpace(r.OnBehalfOf) != "" }

// Validate refuses a requester that could not be authorized soundly.
func (r Requester) Validate() error {
	switch {
	case strings.TrimSpace(r.SubjectID) == "":
		return field("a retrieval names no subject", "subject_id")
	case strings.TrimSpace(r.SpaceID) == "":
		// Without a Space the IAM-5 boundary has nothing to compare against, and every check
		// downstream would be comparing to "".
		return field("a retrieval names no Space", "space_id")
	}
	if !r.Delegated() {
		return nil
	}
	// LCX-9. A Context Gateway serving a remote agent hands out the delegating user's authority and
	// no more. A delegation listing no Spaces conveys nothing, and reading that as "all Spaces" is
	// the same nil-versus-empty mistake an allowlist makes, with the tenant boundary behind it.
	if len(r.DelegatedSpaces) == 0 {
		return denied(fmt.Sprintf(
			"the delegation for %s names no Spaces, so it conveys no retrieval authority", r.OnBehalfOf),
			"delegation_scope")
	}
	for _, s := range r.DelegatedSpaces {
		if s == r.SpaceID {
			return nil
		}
	}
	return denied(fmt.Sprintf(
		"the delegation for %s does not cover Space %s", r.OnBehalfOf, r.SpaceID), "delegation_scope")
}

// Index describes the shared index a retrieval ran against.
type Index struct {
	// Encrypted records that the vectors are encrypted at rest. It is recorded because it is worth
	// knowing and it is deliberately not consulted anywhere: LCX-8 exists because encryption at rest
	// is not an access-control answer, and a field that relaxed anything would be the bug the
	// requirement was written to prevent.
	Encrypted bool `json:"encrypted"`
	// Partitions are the index partitions a complete retrieval covers.
	Partitions []string `json:"partitions"`
	// Answered are the partitions that responded to this query (LCX-5 partial availability).
	Answered []string `json:"answered"`
}

// Retrieval is what a requester receives.
type Retrieval struct {
	Items []Item `json:"items"`
	// Total is the number of items returned. Post-filter, because a pre-filter count is an existence
	// oracle written in a friendly tone.
	Total int `json:"total"`
	// Complete reports that every partition answered. The zero value is false, so a Retrieval
	// nobody finished building does not claim to be a whole answer.
	Complete bool `json:"complete"`
	// Missing names the partitions that did not answer, so an incomplete result says what it is
	// missing rather than only that it is incomplete. Partition ids are index structure, which the
	// requester is already entitled to know from Index.
	Missing []string `json:"missing,omitempty"`
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

func denied(msg, constraint string) error {
	return modberr.New(modberr.CodePolicyDenied, msg).WithDetail("constraint", constraint)
}

// Retrieve resolves and authorizes matches for a requester (LCX-8).
//
// Every match takes the same path regardless of how the index is stored: resolve the source,
// confirm it is inside the requested Space, authorize the requester against it, and only then let
// the content through. A match that fails any step is dropped and leaves no trace in the result —
// not a count, not a placeholder, not a redacted entry.
func Retrieve(r Requester, matches []Match, idx Index, res Resolver, a Authorizer) (Retrieval, error) {
	if err := r.Validate(); err != nil {
		return Retrieval{}, err
	}
	if res == nil || a == nil {
		// Failing closed here rather than returning everything unfiltered, which is what a nil
		// authorizer would otherwise amount to.
		return Retrieval{}, field(
			"a shared-context retrieval needs both a resolver and an authorizer", "retrieve")
	}

	out := Retrieval{}
	for _, m := range matches {
		src, ok := res.Resolve(m.SourceRef)
		if !ok || !src.Valid() {
			// LCX-8. A source we cannot resolve is one we cannot say anything about, including
			// whether the requester may know it exists.
			continue
		}
		// IAM-5 and INV-10. Checked before authorization so a cross-Space match is never even put to
		// the authorizer, whose evaluation might be built from the wrong Space's membership.
		if src.SpaceID != r.SpaceID {
			continue
		}
		decision, err := authz.Authorize(a.Evaluate(r, src))
		if err != nil {
			// A malformed evaluation is a defect in the authorization path, not a denial, and it
			// must stop the retrieval rather than silently drop results.
			return Retrieval{}, err
		}
		if !decision.Allow {
			continue
		}
		out.Items = append(out.Items, Item{Source: src, Score: m.Score, Snippet: m.Snippet})
	}

	sort.SliceStable(out.Items, func(i, j int) bool { return out.Items[i].Score > out.Items[j].Score })
	out.Total = len(out.Items)
	out.Complete, out.Missing = coverage(idx)
	return out, nil
}

// coverage reports whether every partition answered, and which did not (LCX-5).
//
// Partial availability is declared rather than absorbed. A retrieval over a partly-available index
// that presents itself as whole is worse than one that admits the gap, because the caller's next
// move — concluding the codebase does not contain the thing — is wrong in a way nothing corrects.
func coverage(idx Index) (bool, []string) {
	answered := make(map[string]bool, len(idx.Answered))
	for _, p := range idx.Answered {
		answered[p] = true
	}
	var missing []string
	for _, p := range idx.Partitions {
		if !answered[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	return len(missing) == 0, missing
}
