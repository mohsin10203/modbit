package codewiki

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Configuration, annotations and sharing (WIKI-11..WIKI-15, WIKI-21, WIKI-22).
//
// Requirements: PRD §9A.3 WIKI-11 (UI and YAML configuration use the same schema), WIKI-12
// (explicit pages override automatic cluster planning), WIKI-13 (users add notes, rename pages,
// change hierarchy, request missing coverage), WIKI-14 (generated pages and user-authored
// annotations remain distinguishable), WIKI-15 (invalid configuration shows line-level
// diagnostics); §9A.5 WIKI-21 (private access follows repository and Space permissions), WIKI-22
// (public publishing is optional and disabled by default). The PRD's rejected proposal elements
// include "public unauthenticated access is not allowed for private Wiki content".
//
// # Why annotations are a separate list
//
// WIKI-14 asks that generated pages and user-authored annotations remain distinguishable, and the
// cheap way to satisfy it is a flag on each statement. That works right up until something appends
// to the wrong list, and then the two rules that govern them swap: WIKI-3 requires a generated
// technical statement to cite a source span, and a human writing "we should probably rewrite this"
// has nothing to cite and should not be asked to. Merge them and either the citation validator
// starts rejecting human prose, or it starts accepting uncited generated claims. The second is the
// one that ships.
//
// So annotations live in their own field, and the citation validator never sees them.
//
// # A share cannot exceed what it shares
//
// WIKI-21 makes private access follow repository and Space permissions and WIKI-22 makes public
// publishing opt-in. Between them sits the case the PRD rejected outright: a wiki generated from a
// private repository, published publicly. It is easy to reach because the wiki *feels* like a
// separate artifact — it is prose somebody generated, not the code — and it is a description of
// private code detailed enough to be worth writing.

// Author distinguishes what produced a piece of wiki content (WIKI-14).
type Author string

const (
	// AuthorUnattributed is the zero value and is never admissible. Content whose author nobody
	// recorded would be held to whichever rule the reader assumed.
	AuthorUnattributed Author = ""
	AuthorGenerated    Author = "generated"
	AuthorUser         Author = "user"
)

// Annotation is user-authored content attached to a page (WIKI-13, WIKI-14).
//
// It carries no citations because WIKI-3 does not apply to it: a person writing "this module is
// overdue for a rewrite" has nothing to cite and should not be asked to invent something.
type Annotation struct {
	// PagePath is the page this annotation belongs to. It travels with the annotation rather than
	// being implied by position, so a rename can move it (WIKI-13).
	PagePath string `json:"page_path"`
	AuthorID string `json:"author_id"`
	Body     string `json:"body"`
}

// Validate enforces WIKI-14's attributability.
func (a Annotation) Validate() error {
	switch {
	case strings.TrimSpace(a.PagePath) == "":
		return field("an annotation names no page", "page_path")
	case strings.TrimSpace(a.AuthorID) == "":
		// An unattributed annotation is indistinguishable from generated prose to a reader who is
		// deciding how much to trust it.
		return field("an annotation names no author", "author_id")
	case strings.TrimSpace(a.Body) == "":
		return field("an annotation has no body", "body")
	}
	return nil
}

// Visibility is how widely wiki content may be read.
type Visibility string

const (
	// VisibilityPrivate is the zero value: wiki content nobody classified is private. Public is
	// never a default anywhere, and WIKI-22 says publishing is disabled by default.
	VisibilityPrivate Visibility = ""
	// VisibilityPublic is unauthenticated read access.
	VisibilityPublic Visibility = "public"
)

// Share is a request to publish a wiki (WIKI-22).
type Share struct {
	RepositoryID string `json:"repository_id"`
	// Requested is the visibility being asked for.
	Requested Visibility `json:"requested"`
	// RepositoryVisibility is what the underlying repository is. Supplied by the caller from the
	// repository record, not from the share request, for the reason WRK-3's organization is a
	// parameter: the thing being checked does not get to state the answer.
	RepositoryVisibility Visibility `json:"repository_visibility"`
	// PolicyPermitsPublishing is the deployment's stance. WIKI-22 makes publishing optional, so a
	// deployment that has not enabled it has not enabled it.
	PolicyPermitsPublishing bool `json:"policy_permits_publishing"`
}

// Authorize decides whether a wiki may be published (WIKI-21, WIKI-22).
//
// A private repository's wiki cannot be published publicly. The wiki feels like a separate artifact
// — prose somebody generated rather than the code itself — and it is a description of the private
// code detailed enough to be worth writing down, which is exactly what makes publishing it look
// harmless and be the opposite.
func (s Share) Authorize() error {
	if strings.TrimSpace(s.RepositoryID) == "" {
		return field("a share names no repository", "repository_id")
	}
	if s.Requested != VisibilityPublic {
		// Private stays private and needs no publishing permission; WIKI-21's per-request permission
		// check is the caller's, against the repository and Space.
		return nil
	}
	if !s.PolicyPermitsPublishing {
		return modberr.Newf(modberr.CodePolicyDenied,
			"this deployment has not enabled public CodeWiki publishing").
			WithDetail("constraint", "wiki_publishing")
	}
	if s.RepositoryVisibility != VisibilityPublic {
		return modberr.Newf(modberr.CodePolicyDenied,
			"the CodeWiki for %s cannot be published publicly because the repository is not public; "+
				"the wiki is a description of the private code, not a separate artifact", s.RepositoryID).
			WithDetail("constraint", "wiki_visibility")
	}
	return nil
}

// Diagnostic is a line-level configuration problem (WIKI-15).
type Diagnostic struct {
	// Line is 1-indexed. Zero means the problem is not attributable to a line, which is itself worth
	// distinguishing from line 1.
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// Config is a wiki configuration, from the UI or from YAML (WIKI-11).
//
// One type for both, because WIKI-11 asks for one schema and two structs that are kept in sync by
// intention drift apart the first time someone adds a field to the form.
type Config struct {
	// ExplicitPages are WIKI-12's configured pages. Where one is configured for a path, cluster
	// planning does not get a say about that path.
	ExplicitPages []string `json:"explicit_pages"`
	// Hierarchy maps a page path to its parent (WIKI-13).
	Hierarchy map[string]string `json:"hierarchy,omitempty"`
	// RequestedCoverage names paths a user has asked to have documented (WIKI-13).
	RequestedCoverage []string `json:"requested_coverage,omitempty"`
}

// ValidateConfig checks a configuration and returns every problem with its line (WIKI-15).
//
// lineOf maps a page path to the source line it was declared on, so a YAML caller can produce
// line-level diagnostics and a UI caller can pass nil. Every problem is returned rather than the
// first, because a configuration with four mistakes should take one round trip to fix and not four.
func ValidateConfig(c Config, lineOf map[string]int) []Diagnostic {
	var out []Diagnostic
	add := func(path, msg string) {
		out = append(out, Diagnostic{Line: lineOf[path], Message: msg})
	}

	seen := map[string]bool{}
	for _, p := range c.ExplicitPages {
		switch {
		case strings.TrimSpace(p) == "":
			out = append(out, Diagnostic{Message: "an explicit page has no path"})
		case seen[p]:
			add(p, fmt.Sprintf("the page %q is declared twice", p))
		default:
			seen[p] = true
		}
	}

	for child, parent := range c.Hierarchy {
		switch {
		case strings.TrimSpace(parent) == "":
			add(child, fmt.Sprintf("the page %q names an empty parent", child))
		case child == parent:
			add(child, fmt.Sprintf("the page %q is its own parent", child))
		case !seen[parent]:
			add(child, fmt.Sprintf("the page %q names the parent %q, which is not declared",
				child, parent))
		}
	}
	if cycle := findCycle(c.Hierarchy); cycle != "" {
		add(cycle, fmt.Sprintf("the hierarchy through %q is a cycle", cycle))
	}

	for _, p := range c.RequestedCoverage {
		if strings.TrimSpace(p) == "" {
			out = append(out, Diagnostic{Message: "a coverage request names no path"})
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// findCycle returns a page on a hierarchy cycle, or "".
func findCycle(hierarchy map[string]string) string {
	for start := range hierarchy {
		seen := map[string]bool{start: true}
		for node := hierarchy[start]; node != ""; node = hierarchy[node] {
			if seen[node] {
				return start
			}
			seen[node] = true
		}
	}
	return ""
}

// PlanPages decides which pages exist, given cluster planning and explicit configuration (WIKI-12).
//
// An explicit page wins for its path. "Where configured" is per path rather than global: a
// configuration that named one page would otherwise switch cluster planning off for the whole
// repository, and the user who added one page did not ask for that.
func PlanPages(clustered []string, c Config) []string {
	explicit := map[string]bool{}
	for _, p := range c.ExplicitPages {
		if strings.TrimSpace(p) != "" {
			explicit[p] = true
		}
	}

	out := make([]string, 0, len(clustered)+len(explicit))
	for _, p := range clustered {
		if !explicit[p] {
			out = append(out, p)
		}
	}
	for p := range explicit {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// RenamePage moves a page and everything attached to it (WIKI-13).
//
// Annotations move with it. A rename that leaves them behind orphans a user's notes against a path
// that no longer exists, and the notes do not come back — they are the one part of a wiki that
// cannot be regenerated.
func RenamePage(from, to string, pages []Page, annotations []Annotation, c Config) ([]Page, []Annotation, Config, error) {
	switch {
	case strings.TrimSpace(from) == "" || strings.TrimSpace(to) == "":
		return nil, nil, Config{}, field("a rename names no page", "path")
	case from == to:
		return pages, annotations, c, nil
	}

	movedPages := make([]Page, 0, len(pages))
	found := false
	for _, p := range pages {
		if p.Path == to {
			return nil, nil, Config{}, field(fmt.Sprintf(
				"a page already exists at %q", to), "path")
		}
		if p.Path == from {
			p.Path = to
			found = true
		}
		movedPages = append(movedPages, p)
	}
	if !found {
		return nil, nil, Config{}, modberr.Newf(modberr.CodeNotFound,
			"there is no page at %q to rename", from).WithDetail("resource", "page")
	}

	movedAnnotations := make([]Annotation, 0, len(annotations))
	for _, a := range annotations {
		if a.PagePath == from {
			a.PagePath = to
		}
		movedAnnotations = append(movedAnnotations, a)
	}

	moved := Config{
		ExplicitPages:     make([]string, 0, len(c.ExplicitPages)),
		RequestedCoverage: append([]string(nil), c.RequestedCoverage...),
	}
	for _, p := range c.ExplicitPages {
		if p == from {
			p = to
		}
		moved.ExplicitPages = append(moved.ExplicitPages, p)
	}
	if c.Hierarchy != nil {
		moved.Hierarchy = make(map[string]string, len(c.Hierarchy))
		for child, parent := range c.Hierarchy {
			if child == from {
				child = to
			}
			if parent == from {
				parent = to
			}
			moved.Hierarchy[child] = parent
		}
	}
	return movedPages, movedAnnotations, moved, nil
}
