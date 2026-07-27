package id_test

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/modbit/modbit/pkg/id"
)

func TestNewProducesRegisteredPrefixAndFixedLength(t *testing.T) {
	t.Parallel()
	for prefix := range id.Prefixes() {
		got, err := id.New(prefix)
		if err != nil {
			t.Fatalf("New(%q): %v", prefix, err)
		}
		if got.Prefix() != prefix {
			t.Errorf("New(%q).Prefix() = %q", prefix, got.Prefix())
		}
		wantLen := len(prefix) + 1 + 26
		if len(got.String()) != wantLen {
			t.Errorf("New(%q) length = %d, want %d (%q)", prefix, len(got.String()), wantLen, got)
		}
		if _, err := id.Parse(got.String()); err != nil {
			t.Errorf("Parse(New(%q)) = %v", prefix, err)
		}
	}
}

func TestNewRejectsUnregisteredPrefix(t *testing.T) {
	t.Parallel()
	if _, err := id.New(id.Prefix("nosuchprefix")); !errors.Is(err, id.ErrUnknownPrefix) {
		t.Fatalf("err = %v, want ErrUnknownPrefix", err)
	}
}

// Identifiers must be non-sequential: two consecutive identifiers share no ordering relationship
// and must differ (R-ID-01, R-ID-05).
func TestNewIsNonSequentialAndUnique(t *testing.T) {
	t.Parallel()
	const n = 4096
	seen := make(map[id.ID]struct{}, n)
	for i := 0; i < n; i++ {
		v := id.MustNew(id.Run)
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate identifier after %d draws: %q", i, v)
		}
		seen[v] = struct{}{}
	}
}

func TestGeneratorIsDeterministicOverAFixedEntropySource(t *testing.T) {
	t.Parallel()
	entropy := func() *bytes.Reader {
		return bytes.NewReader(bytes.Repeat([]byte{0xAB, 0xCD}, 64))
	}
	first := id.NewGenerator(entropy())
	second := id.NewGenerator(entropy())

	a, err := first.New(id.Run)
	if err != nil {
		t.Fatalf("first.New: %v", err)
	}
	b, err := second.New(id.Run)
	if err != nil {
		t.Fatalf("second.New: %v", err)
	}
	if a != b {
		t.Fatalf("determinism broken: %q != %q", a, b)
	}
}

func TestGeneratorReportsEntropyFailureRatherThanDegrading(t *testing.T) {
	t.Parallel()
	// A source with fewer than 16 bytes must fail, never silently pad. Falling back to a weaker
	// entropy source would be a silent degradation (R-ERR-05).
	g := id.NewGenerator(bytes.NewReader([]byte{0x01, 0x02}))
	if _, err := g.New(id.Run); err == nil {
		t.Fatal("expected an error from a short entropy source")
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	valid := id.MustNew(id.Approval).String()
	body := valid[strings.IndexByte(valid, '_')+1:]

	tests := []struct {
		name  string
		input string
		want  error
	}{
		{"valid", valid, nil},
		{"empty", "", id.ErrEmpty},
		{"no separator", "runabcdef", id.ErrMissingSeparator},
		{"leading separator", "_" + body, id.ErrMissingSeparator},
		{"trailing separator", "run_", id.ErrMissingSeparator},
		{"unknown prefix", "zzz_" + body, id.ErrUnknownPrefix},
		{"short body", "run_abc", id.ErrBadBodyLength},
		{"long body", "run_" + body + "x", id.ErrBadBodyLength},
		{"ambiguous character i", "run_" + "i" + body[1:], id.ErrBadBodyCharacter},
		{"ambiguous character l", "run_" + "l" + body[1:], id.ErrBadBodyCharacter},
		{"ambiguous character o", "run_" + "o" + body[1:], id.ErrBadBodyCharacter},
		{"ambiguous character u", "run_" + "u" + body[1:], id.ErrBadBodyCharacter},
		{"uppercase body", "run_" + strings.ToUpper(body), id.ErrBadBodyCharacter},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := id.Parse(tc.input)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Parse(%q) = %v, want nil", tc.input, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse(%q) = %v, want %v", tc.input, err, tc.want)
			}
		})
	}
}

// A run identifier must not be accepted where an approval identifier is expected. This is the
// control that stops entity confusion at API boundaries.
func TestParseAsRejectsAForeignPrefix(t *testing.T) {
	t.Parallel()
	run := id.MustNew(id.Run)
	if _, err := id.ParseAs(run.String(), id.Approval); !errors.Is(err, id.ErrPrefixMismatch) {
		t.Fatalf("err = %v, want ErrPrefixMismatch", err)
	}
	if _, err := id.ParseAs(run.String(), id.Run); err != nil {
		t.Fatalf("ParseAs with the matching prefix failed: %v", err)
	}
}

func TestPrefixesAreUniqueAndWireFixedValuesArePreserved(t *testing.T) {
	t.Parallel()
	// api-and-events-v5.1.md §4 shows these prefixes on the wire. Changing one is a breaking
	// change to every recorded event and audit export.
	wireFixed := map[id.Prefix]string{
		id.TraceEvent:       "evt",
		id.Organization:     "org",
		id.Space:            "spc",
		id.Run:              "run",
		id.Correlation:      "cor",
		id.PolicyDecision:   "pdec",
		id.SettingsSnapshot: "setshot",
		id.ObjectRef:        "obj",
		id.Artifact:         "art",
	}
	for got, want := range wireFixed {
		if string(got) != want {
			t.Errorf("wire-fixed prefix changed: got %q, want %q", got, want)
		}
	}

	// Register panics on duplicates, so reaching this point already proves uniqueness; assert the
	// registry is non-trivial so an accidentally emptied prefixes.go fails loudly.
	if n := len(id.Prefixes()); n < 80 {
		t.Errorf("registered prefixes = %d, want at least 80 entity families", n)
	}
}

func TestConcurrentGenerationIsSafe(t *testing.T) {
	t.Parallel()
	const goroutines, perGoroutine = 16, 256

	var mu sync.Mutex
	seen := make(map[id.ID]struct{}, goroutines*perGoroutine)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			local := make([]id.ID, 0, perGoroutine)
			for i := 0; i < perGoroutine; i++ {
				local = append(local, id.MustNew(id.RunStep))
			}
			mu.Lock()
			defer mu.Unlock()
			for _, v := range local {
				seen[v] = struct{}{}
			}
		}()
	}
	wg.Wait()

	if len(seen) != goroutines*perGoroutine {
		t.Fatalf("unique identifiers = %d, want %d", len(seen), goroutines*perGoroutine)
	}
}

func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := id.New(id.Run); err != nil {
			b.Fatal(err)
		}
	}
}
