package taint_test

import (
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/taint"
)

func TestPropagateInheritsTheHighestRiskContributor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		inputs []taint.Class
		want   taint.Class
	}{
		{"no inputs", nil, taint.UserTrusted},
		{"trusted only", []taint.Class{taint.UserTrusted, taint.UserTrusted}, taint.UserTrusted},
		{"web dominates trusted", []taint.Class{taint.UserTrusted, taint.Web}, taint.Web},
		{"mcp dominates web", []taint.Class{taint.Web, taint.MCPResult}, taint.MCPResult},
		{"repository dominates tool", []taint.Class{taint.ToolResult, taint.RepositoryUntrusted}, taint.RepositoryUntrusted},
		{"order does not matter", []taint.Class{taint.MCPResult, taint.UserTrusted}, taint.MCPResult},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := taint.Propagate(tc.inputs...); got != tc.want {
				t.Errorf("Propagate(%v) = %v, want %v", tc.inputs, got, tc.want)
			}
		})
	}
}

// TNT-6: unverifiable provenance fails closed to the highest-risk *provenance* class.
//
// Not to Highest(), which is known_secret. Failing closed means assuming the worst origin, not
// asserting a fact we do not have — see TestUnknownProvenanceIsNotClassifiedAsASecret.
func TestUnknownProvenanceFailsClosed(t *testing.T) {
	t.Parallel()
	if got := taint.Unknown(); got == taint.UserTrusted {
		t.Fatalf("Unknown() = %v, must not be trusted", got)
	}

	parsed, err := taint.ParseClass("something-a-plugin-invented")
	if err == nil {
		t.Error("expected an error for an unrecognized class name")
	}
	if parsed != taint.Unknown() {
		t.Errorf("ParseClass fell back to %v, want %v", parsed, taint.Unknown())
	}

	// An out-of-range class value must also fail closed rather than being treated as trusted.
	if got := taint.Propagate(taint.Class(200)); got != taint.Unknown() {
		t.Errorf("Propagate(invalid) = %v, want %v", got, taint.Unknown())
	}
}

func TestParseClassAcceptsBothPRDAndContractSpellings(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"mcp_result", "mcp-result", "MCP_RESULT", "  web  "} {
		if _, err := taint.ParseClass(name); err != nil {
			t.Errorf("ParseClass(%q) = %v, want a recognized class", name, err)
		}
	}
}

func TestSetOperations(t *testing.T) {
	t.Parallel()
	s := taint.NewSet(taint.UserTrusted, taint.Web)

	if !s.Contains(taint.Web) || s.Contains(taint.MCPResult) {
		t.Errorf("membership incorrect for %v", s)
	}
	if !s.ContainsAny(taint.MCPResult, taint.Web) {
		t.Error("ContainsAny should match on web")
	}
	if s.ContainsAny(taint.MCPResult, taint.Integration) {
		t.Error("ContainsAny matched a class that is absent")
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
	max, ok := s.Max()
	if !ok || max != taint.Web {
		t.Errorf("Max = %v (%t), want web", max, ok)
	}
	if got := s.String(); got != "user_trusted,web" {
		t.Errorf("String = %q, want user_trusted,web", got)
	}

	var empty taint.Set
	if !empty.Empty() {
		t.Error("zero Set should be empty")
	}
	if _, ok := empty.Max(); ok {
		t.Error("empty Set should report no maximum")
	}
}

func TestSetTextRoundTripAndUnknownFailsClosed(t *testing.T) {
	t.Parallel()
	original := taint.NewSet(taint.RepositoryUntrusted, taint.Web)
	text, err := original.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	var restored taint.Set
	if err := restored.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if restored != original {
		t.Errorf("round trip changed the set: %v -> %v", original, restored)
	}

	var withUnknown taint.Set
	err = withUnknown.UnmarshalText([]byte("web,invented_class"))
	if err == nil {
		t.Error("expected an error reporting the unrecognized class")
	}
	if !withUnknown.Contains(taint.Unknown()) {
		t.Error("an unrecognized class must be recorded as the highest-risk provenance class")
	}
	if !withUnknown.Contains(taint.Web) {
		t.Error("recognized classes must still be recorded alongside the failure")
	}
}

func newLedger(t *testing.T) *taint.Ledger {
	t.Helper()
	l, err := taint.NewLedger(id.MustNew(id.Run), nil)
	if err != nil {
		t.Fatalf("NewLedger: %v", err)
	}
	return l
}

func TestLedgerRecordsEntriesAndMaintainsTheSet(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	base := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	if _, err := l.Record(taint.RepositoryUntrusted, "AGENTS.md", base); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := l.Record(taint.Web, "https://example.test", base.Add(time.Minute)); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if !l.Set().ContainsAny(taint.Web, taint.RepositoryUntrusted) {
		t.Errorf("set = %v, want both classes", l.Set())
	}
	if got, ok := l.FirstEntry(taint.Web); !ok || !got.Equal(base.Add(time.Minute)) {
		t.Errorf("first web entry = %v (%t), want %v", got, ok, base.Add(time.Minute))
	}
	earliest, ok := l.EarliestEntry(taint.Web, taint.RepositoryUntrusted)
	if !ok || !earliest.Equal(base) {
		t.Errorf("earliest = %v (%t), want %v", earliest, ok, base)
	}
	if len(l.Entries()) != 2 {
		t.Errorf("entries = %d, want 2", len(l.Entries()))
	}
}

// A later entry of the same class must not move the first-entry time forward, or the TNT-4
// carve-out could be defeated by re-fetching the same tainted source after the plan was approved.
func TestFirstEntryTimeIsNotAdvancedByLaterEntries(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	first := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	if _, err := l.Record(taint.Web, "first", first); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := l.Record(taint.Web, "second", first.Add(time.Hour)); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, ok := l.FirstEntry(taint.Web)
	if !ok || !got.Equal(first) {
		t.Errorf("first entry = %v, want %v", got, first)
	}
}

// TNT-2: summarizing tainted content still yields tainted content. This is the laundering path.
func TestDeriveInheritsTaintThroughSummarization(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	at := time.Now().UTC()

	page, err := l.Record(taint.Web, "https://example.test/docs", at)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	summary, err := l.Derive("model summary of fetched page", at, page)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if summary.Class != taint.Web {
		t.Errorf("summary class = %v, want web", summary.Class)
	}
	if len(summary.DerivedFrom) != 1 || summary.DerivedFrom[0] != page.ID {
		t.Errorf("propagation tree = %v, want [%s]", summary.DerivedFrom, page.ID)
	}
}

// Content derived from trusted input is still Generated, never UserTrusted: the platform did not
// receive it from the user directly.
func TestDeriveFromTrustedInputIsGenerated(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	at := time.Now().UTC()

	prompt, err := l.Record(taint.UserTrusted, "composer", at)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	derived, err := l.Derive("model output", at, prompt)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if derived.Class != taint.Generated {
		t.Errorf("derived class = %v, want generated", derived.Class)
	}
}

func TestDeclassifyRequiresAccountabilityAndLowersRisk(t *testing.T) {
	t.Parallel()
	at := time.Now().UTC()

	t.Run("requires an actor", func(t *testing.T) {
		l := newLedger(t)
		e, _ := l.Record(taint.Web, "page", at)
		if _, err := l.Declassify(e.ID, taint.UserTrusted, "", "reviewed", at); err == nil {
			t.Error("expected an error when no actor is supplied")
		}
	})

	t.Run("requires a rationale", func(t *testing.T) {
		l := newLedger(t)
		e, _ := l.Record(taint.Web, "page", at)
		if _, err := l.Declassify(e.ID, taint.UserTrusted, "usr_alice", "  ", at); err == nil {
			t.Error("expected an error when no rationale is supplied")
		}
	})

	t.Run("cannot raise risk", func(t *testing.T) {
		l := newLedger(t)
		e, _ := l.Record(taint.ToolResult, "grep", at)
		if _, err := l.Declassify(e.ID, taint.MCPResult, "usr_alice", "reviewed", at); err == nil {
			t.Error("declassification must not be usable to raise risk")
		}
	})

	t.Run("cannot be a no-op", func(t *testing.T) {
		l := newLedger(t)
		e, _ := l.Record(taint.Web, "page", at)
		if _, err := l.Declassify(e.ID, taint.Web, "usr_alice", "reviewed", at); err == nil {
			t.Error("declassifying to the same class must be rejected")
		}
	})

	t.Run("rejects an unknown entry", func(t *testing.T) {
		l := newLedger(t)
		if _, err := l.Declassify(id.MustNew(id.TaintEntry), taint.UserTrusted, "usr_alice", "reviewed", at); err == nil {
			t.Error("expected an error for an unknown entry")
		}
	})

	t.Run("succeeds and updates the set", func(t *testing.T) {
		l := newLedger(t)
		e, _ := l.Record(taint.Web, "page", at)
		if _, err := l.Record(taint.ToolResult, "grep", at); err != nil {
			t.Fatalf("Record: %v", err)
		}
		d, err := l.Declassify(e.ID, taint.UserTrusted, "usr_alice", "manually reviewed the fetched page", at)
		if err != nil {
			t.Fatalf("Declassify: %v", err)
		}
		if d.From != taint.Web || d.To != taint.UserTrusted {
			t.Errorf("declassification = %v -> %v, want web -> user_trusted", d.From, d.To)
		}
		if l.Set().Contains(taint.Web) {
			t.Errorf("set = %v, web should no longer be present", l.Set())
		}
		if !l.Set().Contains(taint.ToolResult) {
			t.Errorf("set = %v, unrelated classes must survive a declassification", l.Set())
		}
		if len(l.Declassifications()) != 1 {
			t.Errorf("declassification records = %d, want 1", len(l.Declassifications()))
		}
	})
}

func TestNewLedgerRequiresARunIdentifier(t *testing.T) {
	t.Parallel()
	if _, err := taint.NewLedger(id.MustNew(id.Approval), nil); err == nil {
		t.Fatal("expected an error when the identifier is not a run id")
	}
}

func TestEntriesAndDeclassificationsAreCopies(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	if _, err := l.Record(taint.Web, "page", time.Now().UTC()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	entries := l.Entries()
	entries[0].Class = taint.UserTrusted
	if l.Entries()[0].Class != taint.Web {
		t.Error("Entries must return a copy; the ledger is append-only")
	}
}

func BenchmarkSetContainsAny(b *testing.B) {
	s := taint.NewSet(taint.UserTrusted, taint.Generated, taint.Web)
	triggers := []taint.Class{taint.Web, taint.MCPResult, taint.RepositoryUntrusted}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !s.ContainsAny(triggers...) {
			b.Fatal("expected a trigger match")
		}
	}
}

// KnownSecret sits above every provenance class because it is a different kind of claim: the
// others describe where content came from, this one describes what it contains.
func TestKnownSecretIsTheHighestRiskClass(t *testing.T) {
	t.Parallel()
	if taint.Highest() != taint.KnownSecret {
		t.Errorf("Highest = %v, want known_secret", taint.Highest())
	}
	if taint.Propagate(taint.MCPResult, taint.KnownSecret) != taint.KnownSecret {
		t.Error("known_secret must dominate every provenance class")
	}
	if got := taint.Propagate(taint.UserTrusted, taint.KnownSecret); got != taint.KnownSecret {
		t.Errorf("Propagate = %v, want known_secret to propagate through derivation", got)
	}
}

// Failing closed means assuming the worst provenance, not asserting a fact we do not have.
// Classifying unknown content as a known secret would also make it permanently undeclassifiable.
func TestUnknownProvenanceIsNotClassifiedAsASecret(t *testing.T) {
	t.Parallel()
	if taint.Unknown() == taint.KnownSecret {
		t.Fatal("unknown provenance must not assert that content contains a secret")
	}
	if taint.Unknown() != taint.MCPResult {
		t.Errorf("Unknown = %v, want the highest provenance class", taint.Unknown())
	}
}

// A secret that can be argued away with a rationale is not confined at all.
func TestKnownSecretCannotBeDeclassifiedByRationale(t *testing.T) {
	t.Parallel()
	l := newLedger(t)
	at := time.Now().UTC()

	entry, err := l.Record(taint.KnownSecret, "scanner: aws key in tool output", at)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := l.Declassify(entry.ID, taint.ToolResult, "usr_alice", "reviewed, looks fine", at); err == nil {
		t.Fatal("Declassify must refuse a known-secret entry")
	}
	if !l.Set().Contains(taint.KnownSecret) {
		t.Error("the secret class must survive a refused declassification")
	}
}

// RedactSecret is the only way down, and it requires a verification artifact rather than prose:
// a declassification asserts a judgement, a redaction asserts a fact something else checked.
func TestRedactSecretRequiresVerifiedEvidence(t *testing.T) {
	t.Parallel()
	at := time.Now().UTC()

	t.Run("refuses without a verification artifact", func(t *testing.T) {
		l := newLedger(t)
		entry, _ := l.Record(taint.KnownSecret, "scanner", at)
		if _, err := l.RedactSecret(entry.ID, taint.ToolResult, "usr_alice", "redacted", "", at); err == nil {
			t.Error("redaction must require a verification artifact")
		}
	})

	t.Run("refuses to stay at known_secret", func(t *testing.T) {
		l := newLedger(t)
		entry, _ := l.Record(taint.KnownSecret, "scanner", at)
		verification := id.MustNew(id.Evidence)
		if _, err := l.RedactSecret(entry.ID, taint.KnownSecret, "usr_alice", "redacted", verification, at); err == nil {
			t.Error("redaction must lower the class")
		}
	})

	t.Run("refuses a non-secret entry", func(t *testing.T) {
		l := newLedger(t)
		entry, _ := l.Record(taint.Web, "page", at)
		verification := id.MustNew(id.Evidence)
		if _, err := l.RedactSecret(entry.ID, taint.UserTrusted, "usr_alice", "redacted", verification, at); err == nil {
			t.Error("RedactSecret applies only to known-secret entries")
		}
	})

	t.Run("succeeds with verified evidence", func(t *testing.T) {
		l := newLedger(t)
		entry, _ := l.Record(taint.KnownSecret, "scanner", at)
		verification := id.MustNew(id.Evidence)
		d, err := l.RedactSecret(entry.ID, taint.ToolResult, "usr_alice", "value removed and rescanned", verification, at)
		if err != nil {
			t.Fatalf("RedactSecret: %v", err)
		}
		if d.From != taint.KnownSecret || d.To != taint.ToolResult {
			t.Errorf("transition = %v -> %v", d.From, d.To)
		}
		if d.VerificationRef != verification {
			t.Errorf("verification reference = %q, want %q", d.VerificationRef, verification)
		}
		if l.Set().Contains(taint.KnownSecret) {
			t.Error("the secret class must be gone after a verified redaction")
		}
	})
}
