package taint_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/taint"
)

// Context-source catalogue invariants (F1–F6). One test each; a test without an F-number, or an
// F-number without a test, is a gap.
//
//	F1 An unregistered source resolves to Unknown, never to the zero Class.
//	F2 Every §9.2 source is registered, so the catalogue is not a subset of the requirement.
//	F3 Repository-derived sources are RepositoryUntrusted, including the indexes built from them.
//	F4 Integration sources are classed Integration, and repository content ranks above them.
//	F5 Web content outranks integration content, and nothing user-facing is Generated.
//	F6 A trusted-provenance source is still subject to propagation, so trusted is not immune.

// F1. The failure this catalogue exists to prevent.
//
// The zero Class is UserTrusted, deliberately, so an uninitialised class is the lowest privilege
// claim. But a caller who forgets the field entirely gets that zero, and the failure is silent and
// specific: a pull-request comment reading "ignore the previous instructions" arrives as though the
// user had typed it.
func TestSecurityAnUnregisteredSourceIsNotTrusted(t *testing.T) {
	var zero taint.ContextSource
	if zero != taint.SourceUnregistered {
		t.Fatalf("the zero ContextSource is %q", zero)
	}
	if zero.Registered() {
		t.Fatal("the zero ContextSource reports itself registered")
	}

	got := taint.ClassOf(zero)
	if got == taint.UserTrusted {
		t.Fatal("an unclassified source resolved to the most trusted class in the lattice")
	}
	if got != taint.Unknown() {
		t.Fatalf("an unclassified source resolved to %v, want Unknown", got)
	}

	// A source somebody invented but never registered gets the same answer.
	for _, s := range []taint.ContextSource{"slack_dm", "scratchpad"} {
		if s.Registered() {
			t.Errorf("%q reports itself registered", s)
		}
		if taint.ClassOf(s) != taint.Unknown() {
			t.Errorf("%q resolved to %v, want Unknown", s, taint.ClassOf(s))
		}
	}

	// And the rendering says so, rather than presenting the fallback as a decision somebody made.
	if !strings.Contains(zero.Describe(), "unregistered") {
		t.Fatalf("describe = %q; it must say the source was never classified", zero.Describe())
	}
}

// F2. The catalogue covers §9.2 rather than a convenient subset.
func TestEverySupportedContextSourceIsClassified(t *testing.T) {
	// The fifteen §9.2 sources, written out so this test fails if one is dropped from the catalogue
	// rather than silently shrinking with it.
	want := []taint.ContextSource{
		taint.SourceFile, taint.SourceSymbolIndex, taint.SourceGraph, taint.SourceGitHistory,
		taint.SourceBranchState, taint.SourcePullRequest, taint.SourceIssue,
		taint.SourceRepositoryDocs, taint.SourceADR, taint.SourceBuildMetadata,
		taint.SourceWebsite, taint.SourceConnector, taint.SourceUserAttachment,
		taint.SourceApprovedArtifact, taint.SourceProjectMemory,
	}
	for _, s := range want {
		if !s.Registered() {
			t.Errorf("%q is a §9.2 source and is not classified", s)
		}
		if taint.ClassOf(s) == taint.Unknown() && s != taint.SourceUnregistered {
			t.Errorf("%q falls through to Unknown rather than being decided", s)
		}
	}

	got := taint.ContextSources()
	if len(got) != len(want) {
		t.Fatalf("the catalogue holds %d sources and §9.2 lists %d", len(got), len(want))
	}
	// Sorted, so a settings screen or audit line renders them the same way every time.
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("the catalogue is not sorted: %v", got)
		}
	}
}

// F3. INV-13: repository content is untrusted, and so is anything derived from it.
//
// A symbol name is whatever the repository called it and a graph edge is whatever it imported, so
// an index built over the repository carries the repository's provenance rather than the
// platform's.
func TestSecurityRepositoryDerivedSourcesAreUntrusted(t *testing.T) {
	for _, s := range []taint.ContextSource{
		taint.SourceFile, taint.SourceGitHistory, taint.SourceRepositoryDocs, taint.SourceADR,
		taint.SourceSymbolIndex, taint.SourceGraph,
	} {
		if got := taint.ClassOf(s); got != taint.RepositoryUntrusted {
			t.Errorf("%q is classed %v, want RepositoryUntrusted", s, got)
		}
	}

	// Local tooling output is ToolResult rather than repository content: it describes the checkout
	// rather than being authored in it.
	for _, s := range []taint.ContextSource{taint.SourceBranchState, taint.SourceBuildMetadata} {
		if got := taint.ClassOf(s); got != taint.ToolResult {
			t.Errorf("%q is classed %v, want ToolResult", s, got)
		}
	}
}

// F4. Integration-borne sources are classed Integration, and repository content ranks above them.
//
// The first draft of this test asserted the opposite — that a review comment outranks a commit
// message, because a comment needs only a comment box on the hosting provider while a commit needs
// push access. The lattice disagreed and the lattice is right: the ordering is about what the
// content is used for, not who can author it. Repository content is executed and is where
// repository-authored agent instructions live; a review comment is read as text.
//
// The test is kept in the corrected direction rather than deleted, because the intuition that
// produced the wrong version is the one a reader will arrive with.
func TestSecurityIntegrationSourcesAreClassedBelowRepositoryContent(t *testing.T) {
	for _, s := range []taint.ContextSource{
		taint.SourcePullRequest, taint.SourceIssue, taint.SourceConnector,
	} {
		got := taint.ClassOf(s)
		if got != taint.Integration {
			t.Errorf("%q is classed %v, want Integration", s, got)
		}
		// Above trusted input, so an integration event can never be laundered down by mixing.
		if taint.Propagate(got, taint.UserTrusted) != got {
			t.Errorf("%q was laundered down by mixing with trusted input", s)
		}
		// And below repository content, which is executed.
		if taint.Propagate(got, taint.RepositoryUntrusted) != taint.RepositoryUntrusted {
			t.Errorf("%q outranks repository content; the lattice orders it the other way", s)
		}
	}

	// The two are still distinct classes, so a surface can tell a review comment from a commit
	// message even though neither is trusted.
	pr := taint.ClassOf(taint.SourcePullRequest)
	commit := taint.ClassOf(taint.SourceGitHistory)
	if pr == commit {
		t.Fatal("a review comment and a commit message are indistinguishable")
	}
}

// F5. Web content outranks integration content, and nothing here is Generated.
//
// Generated means model output. A context source is something the model reads, and classing one as
// Generated would let model output re-enter as though it were a source.
func TestSecurityWebOutranksIntegrationAndNoSourceIsGenerated(t *testing.T) {
	web := taint.ClassOf(taint.SourceWebsite)
	if web != taint.Web {
		t.Fatalf("a website is classed %v, want Web", web)
	}
	if taint.Propagate(web, taint.ClassOf(taint.SourceIssue)) != web {
		t.Fatal("an issue outranks a fetched web page")
	}
	if taint.Propagate(web, taint.ClassOf(taint.SourceFile)) != web {
		t.Fatal("repository content outranks a fetched web page")
	}

	for _, s := range taint.ContextSources() {
		switch taint.ClassOf(s) {
		case taint.Generated:
			t.Errorf("%q is classed Generated; a context source is something the model reads, and "+
				"classing one as model output lets output re-enter as a source", s)
		case taint.KnownSecret:
			t.Errorf("%q is classed KnownSecret; that describes what content *contains* and is "+
				"raised by a detector, not by where something came from", s)
		}
	}
}

// F6. A trusted-provenance source is not immune to what it contains.
//
// UserTrusted here says the user chose to supply it, not that its bytes are safe. A detector that
// finds a secret in an attachment still raises KnownSecret through propagation.
func TestSecurityATrustedSourceIsStillSubjectToPropagation(t *testing.T) {
	for _, s := range []taint.ContextSource{
		taint.SourceUserAttachment, taint.SourceApprovedArtifact, taint.SourceProjectMemory,
	} {
		got := taint.ClassOf(s)
		if got != taint.UserTrusted {
			t.Errorf("%q is classed %v, want UserTrusted", s, got)
		}
		// A secret detected inside it still dominates.
		if taint.Propagate(got, taint.KnownSecret) != taint.KnownSecret {
			t.Errorf("a secret found in %q did not raise the class", s)
		}
		// And mixing it with untrusted input yields the untrusted class, not the trusted one.
		if taint.Propagate(got, taint.RepositoryUntrusted) != taint.RepositoryUntrusted {
			t.Errorf("%q laundered repository content down to trusted", s)
		}
	}

	// Describe names the class, so a settings screen showing sources is showing the decision.
	d := taint.SourcePullRequest.Describe()
	if !strings.Contains(d, string(taint.SourcePullRequest)) {
		t.Fatalf("describe = %q, must name the source", d)
	}
	if strings.Contains(d, "unregistered") {
		t.Fatalf("describe = %q; a registered source must not be rendered as unregistered", d)
	}
}
