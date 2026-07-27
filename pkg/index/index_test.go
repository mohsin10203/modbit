package index_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/index"
	"github.com/modbit/modbit/pkg/settings"
	"github.com/modbit/modbit/pkg/taint"
)

func rules(t *testing.T, contents, base string, source index.IgnoreSource) *index.RuleSet {
	t.Helper()
	return index.NewRuleSet(index.ParseFile(contents, base, source))
}

func TestPatternParsing(t *testing.T) {
	t.Parallel()
	for _, line := range []string{"", "   ", "# a comment", "!", "/"} {
		if _, ok := index.ParsePattern(line, "", index.SourceGitignore); ok {
			t.Errorf("ParsePattern(%q) should not produce a rule", line)
		}
	}
	if p, ok := index.ParsePattern("!build/", "", index.SourceGitignore); !ok || !p.Negates() {
		t.Errorf("negation was not parsed: %+v %t", p, ok)
	}
}

// gitignore semantics are the contract users already know. Getting them wrong means either
// indexing what should be hidden or losing source that should be searchable.
func TestGitignoreSemantics(t *testing.T) {
	t.Parallel()
	r := rules(t, strings.Join([]string{
		"node_modules",     // unanchored: matches at any depth
		"/dist",            // anchored to the root only
		"*.log",            // extension glob
		"build/",           // directory only
		"docs/**/draft.md", // ** spanning segments
		"tmp",
		"!tmp/keep.txt", // negation inside a non-excluded path
	}, "\n"), "", index.SourceGitignore)

	tests := []struct {
		path    string
		isDir   bool
		ignored bool
		why     string
	}{
		{"node_modules/react/index.js", false, true, "unanchored pattern matches at depth"},
		{"web/node_modules/react/index.js", false, true, "unanchored pattern matches nested"},
		{"dist/bundle.js", false, true, "anchored pattern matches at the root"},
		{"web/dist/bundle.js", false, false, "anchored pattern must not match deeper"},
		{"server.log", false, true, "extension glob"},
		{"logs/server.log", false, true, "extension glob at depth"},
		{"build", true, true, "directory-only pattern matches a directory"},
		{"build", false, false, "directory-only pattern must not match a file"},
		{"docs/a/b/draft.md", false, true, "** spans multiple segments"},
		{"docs/draft.md", false, true, "** matches zero segments"},
		{"src/main.go", false, false, "unmatched paths are kept"},
	}
	for _, tc := range tests {
		t.Run(tc.path+"/"+tc.why, func(t *testing.T) {
			t.Parallel()
			if got := r.Match(tc.path, tc.isDir).Ignored; got != tc.ignored {
				t.Errorf("Match(%q, dir=%t) = %t, want %t — %s", tc.path, tc.isDir, got, tc.ignored, tc.why)
			}
		})
	}
}

// Last match wins, which is what makes a negation meaningful at all.
func TestLastMatchWins(t *testing.T) {
	t.Parallel()
	r := rules(t, "*.log\n!important.log\n", "", index.SourceGitignore)

	if !r.Match("server.log", false).Ignored {
		t.Error("*.log should exclude server.log")
	}
	if r.Match("important.log", false).Ignored {
		t.Error("the later negation should re-include important.log")
	}

	// Order matters: reversing it must reverse the outcome.
	reversed := rules(t, "!important.log\n*.log\n", "", index.SourceGitignore)
	if !reversed.Match("important.log", false).Ignored {
		t.Error("a negation before the exclusion must not survive it")
	}
}

// git: "it is not possible to re-include a file if a parent directory of that file is excluded".
// Without this, one `!` line in a nested ignore file could pull an entire excluded tree back in.
func TestNegationCannotReachInsideAnExcludedDirectory(t *testing.T) {
	t.Parallel()
	r := rules(t, "secrets/\n!secrets/public.txt\n", "", index.SourceGitignore)

	if !r.Match("secrets/public.txt", false).Ignored {
		t.Fatal("a negation must not re-include a file under an excluded directory")
	}
	if !r.Match("secrets/nested/deep.txt", false).Ignored {
		t.Error("the whole excluded subtree must stay excluded")
	}
}

// A nested ignore file governs only its own subtree.
func TestNestedIgnoreFilesAreScopedToTheirDirectory(t *testing.T) {
	t.Parallel()
	r := index.NewRuleSet(index.ParseFile("*.tmp\n", "packages/web", index.SourceModbitignore))

	if !r.Match("packages/web/cache.tmp", false).Ignored {
		t.Error("a nested rule should apply within its own directory")
	}
	if r.Match("packages/api/cache.tmp", false).Ignored {
		t.Error("a nested rule must not apply to a sibling directory")
	}
	if r.Match("cache.tmp", false).Ignored {
		t.Error("a nested rule must not apply above its directory")
	}
}

func config() index.Config {
	return index.Config{RespectGitignore: true, MaxFileBytes: 1024, ExcludedGlobs: nil}
}

func classifier(t *testing.T, c index.Config, r *index.RuleSet) *index.Classifier {
	t.Helper()
	cl, err := index.NewClassifier(c, r)
	if err != nil {
		t.Fatalf("NewClassifier: %v", err)
	}
	return cl
}

// INV-11. The protected list is hardcoded precisely so a repository cannot opt into having its
// credentials embedded, and an administrator cannot switch it off.
func TestSecurityProtectedPathsAreNeverIndexed(t *testing.T) {
	t.Parallel()
	// Every ignore source tries to re-include the secret, and settings do not exclude it.
	permissive := rules(t, "!**/*.pem\n!**/.env\n!**/.ssh/**\n!**/id_rsa\n", "", index.SourceModbitignore)
	cl := classifier(t, config(), permissive)

	secrets := []string{
		".ssh/id_rsa",
		"home/.ssh/authorized_keys",
		"certs/server.pem",
		"config/private.key",
		".env",
		".env.production",
		".aws/credentials",
		".npmrc",
		".kube/config",
		"deploy/secrets.yaml",
		"keys/store.jks",
	}
	for _, p := range secrets {
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			d := cl.Classify(index.File{Path: p, Size: 100, Contents: []byte("secret material")})
			if d.Disposition != index.DispositionExclude {
				t.Fatalf("%s = %s, want exclude", p, d.Disposition)
			}
			if d.Reason != index.ReasonProtectedPath {
				t.Errorf("%s reason = %q, want protected_path", p, d.Reason)
			}
		})
	}
}

// The protected check must precede the ignore rules, or a negation could reach a private key.
func TestProtectedPathsOutrankEveryOtherRule(t *testing.T) {
	t.Parallel()
	cl := classifier(t, config(), rules(t, "!certs/server.pem\n", "", index.SourceModbitignore))
	d := cl.Classify(index.File{Path: "certs/server.pem", Size: 10, Contents: []byte("x")})
	if d.Reason != index.ReasonProtectedPath {
		t.Fatalf("reason = %q, want protected_path to outrank the negation", d.Reason)
	}
}

// SDD §8 / TNT-1: repository content is untrusted, because a file in the tree is authored by
// whoever could commit to it.
func TestRepositoryContentIsClassifiedUntrusted(t *testing.T) {
	t.Parallel()
	cl := classifier(t, config(), nil)
	d := cl.Classify(index.File{Path: "src/main.go", Size: 20, Contents: []byte("package main")})
	if d.Provenance != taint.RepositoryUntrusted {
		t.Errorf("provenance = %v, want repository_untrusted", d.Provenance)
	}
	// Even an excluded file carries its class, so a later decision cannot read the zero value as
	// trusted.
	excluded := cl.Classify(index.File{Path: ".env", Size: 20, Contents: []byte("K=V")})
	if excluded.Provenance != taint.RepositoryUntrusted {
		t.Errorf("excluded provenance = %v, want repository_untrusted", excluded.Provenance)
	}
}

// Reference, not exclude: the file exists and may be cited, it just is not parsed or embedded.
func TestOversizedAndBinaryFilesStayCitable(t *testing.T) {
	t.Parallel()
	cl := classifier(t, config(), nil)

	big := cl.Classify(index.File{Path: "data/fixture.json", Size: 2048, Contents: []byte("{}")})
	if big.Disposition != index.DispositionReference || big.Reason != index.ReasonTooLarge {
		t.Errorf("oversized = %s/%s, want reference/too_large", big.Disposition, big.Reason)
	}

	binary := cl.Classify(index.File{
		Path: "assets/logo.png", Size: 100, Contents: []byte{0x89, 'P', 'N', 'G', 0x00, 0x1a},
	})
	if binary.Disposition != index.DispositionReference || binary.Reason != index.ReasonBinary {
		t.Errorf("binary = %s/%s, want reference/binary", binary.Disposition, binary.Reason)
	}

	empty := cl.Classify(index.File{Path: "src/empty.go", Size: 0})
	if empty.Disposition != index.DispositionReference || empty.Reason != index.ReasonEmpty {
		t.Errorf("empty = %s/%s, want reference/empty", empty.Disposition, empty.Reason)
	}
}

// A truncated sniff window can split a multi-byte rune, which must not be read as binary.
func TestUTF8TextIsNotMisreadAsBinary(t *testing.T) {
	t.Parallel()
	cl := classifier(t, config(), nil)

	text := []byte("// 日本語のコメント\npackage main")
	if d := cl.Classify(index.File{Path: "src/i18n.go", Size: int64(len(text)), Contents: text}); !d.Indexable() {
		t.Errorf("valid UTF-8 was classified %s/%s", d.Disposition, d.Reason)
	}

	// A prefix ending mid-rune is still text.
	truncated := text[:len(text)-1]
	if d := cl.Classify(index.File{Path: "src/i18n.go", Size: 900, Contents: truncated}); !d.Indexable() {
		t.Errorf("a rune split at the sniff boundary was misread as binary: %s/%s", d.Disposition, d.Reason)
	}
}

// Generated files are indexed but marked, because editing one is almost always wrong (NER-5).
func TestGeneratedFilesAreIndexedButMarked(t *testing.T) {
	t.Parallel()
	cl := classifier(t, config(), nil)

	for _, header := range []string{
		"// Code generated by tools/modbitgen. DO NOT EDIT.\n\npackage settings",
		"/* @generated */\nexport const x = 1;",
		"# This file was automatically generated\n",
	} {
		d := cl.Classify(index.File{Path: "pkg/gen.go", Size: int64(len(header)), Contents: []byte(header)})
		if !d.Indexable() {
			t.Errorf("generated files remain indexable, got %s", d.Disposition)
		}
		if !d.Generated {
			t.Errorf("header %q was not recognized as generated", strings.SplitN(header, "\n", 2)[0])
		}
	}

	// A file merely discussing generated code is not itself generated.
	prose := []byte("package docs\n\n" + strings.Repeat("filler line\n", 300) + "// Code generated by something")
	if d := cl.Classify(index.File{Path: "docs/about.go", Size: int64(len(prose)), Contents: prose}); d.Generated {
		t.Error("a marker far below the header must not mark the file generated")
	}
}

// The repository's build exclusions are not necessarily its indexing exclusions, so gitignore is
// honoured only when policy says so. Modbit's own ignore files always apply.
func TestGitignoreIsHonouredOnlyWhenPolicyAllows(t *testing.T) {
	t.Parallel()
	gitRules := rules(t, "vendor/\n", "", index.SourceGitignore)

	respecting := classifier(t, index.Config{RespectGitignore: true, MaxFileBytes: 1024}, gitRules)
	if d := respecting.Classify(index.File{Path: "vendor/lib.go", Size: 10, Contents: []byte("x")}); d.Disposition != index.DispositionExclude {
		t.Errorf("with respect_gitignore on, vendor should be excluded, got %s", d.Disposition)
	}

	ignoring := classifier(t, index.Config{RespectGitignore: false, MaxFileBytes: 1024}, gitRules)
	if d := ignoring.Classify(index.File{Path: "vendor/lib.go", Size: 10, Contents: []byte("x")}); !d.Indexable() {
		t.Errorf("with respect_gitignore off, vendor should be indexable, got %s/%s", d.Disposition, d.Reason)
	}

	// A Modbit ignore file is not subject to that switch.
	modbitRules := rules(t, "vendor/\n", "", index.SourceModbitignore)
	always := classifier(t, index.Config{RespectGitignore: false, MaxFileBytes: 1024}, modbitRules)
	if d := always.Classify(index.File{Path: "vendor/lib.go", Size: 10, Contents: []byte("x")}); d.Disposition != index.DispositionExclude {
		t.Errorf(".modbitignore must apply regardless of the gitignore setting, got %s", d.Disposition)
	}
}

func TestSettingsExclusionsApply(t *testing.T) {
	t.Parallel()
	cfg := config()
	cfg.ExcludedGlobs = []string{"**/testdata/**", "*.snap"}
	cl := classifier(t, cfg, nil)

	for _, p := range []string{"pkg/index/testdata/big.json", "ui/Button.snap"} {
		d := cl.Classify(index.File{Path: p, Size: 10, Contents: []byte("x")})
		if d.Disposition != index.DispositionExclude || d.Reason != index.ReasonSettingsExclusion {
			t.Errorf("%s = %s/%s, want exclude/settings_exclusion", p, d.Disposition, d.Reason)
		}
	}
}

func TestPathNormalization(t *testing.T) {
	t.Parallel()
	cl := classifier(t, config(), rules(t, "build/\n", "", index.SourceModbitignore))

	for _, variant := range []string{"build/out.o", "./build/out.o", "/build/out.o", `build\out.o`} {
		if d := cl.Classify(index.File{Path: variant, Size: 10, Contents: []byte("x")}); d.Disposition != index.DispositionExclude {
			t.Errorf("%q was not normalized: got %s", variant, d.Disposition)
		}
	}
}

func TestClassifierRequiresAPositiveSizeLimit(t *testing.T) {
	t.Parallel()
	if _, err := index.NewClassifier(index.Config{MaxFileBytes: 0}, nil); err == nil {
		t.Fatal("a zero size limit must be refused; it would classify every file as oversized")
	}
}

// The classifier reads its settings from the run's frozen snapshot, so a mid-run change cannot
// alter what a run indexes (INV-6).
func TestConfigFromSnapshot(t *testing.T) {
	t.Parallel()
	resolver, err := settings.NewResolver(settings.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	result, err := resolver.Resolve([]settings.Layer{{
		Scope: settings.ScopeOrganization,
		Values: map[settings.Key]any{
			settings.KeyContextIndexingMaxFileBytes:     4096,
			settings.KeyContextIndexingRespectGitignore: true,
		},
	}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	snap, err := settings.NewSnapshot(result, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}

	cfg, err := index.ConfigFromSnapshot(snap)
	if err != nil {
		t.Fatalf("ConfigFromSnapshot: %v", err)
	}
	if cfg.MaxFileBytes != 4096 || !cfg.RespectGitignore {
		t.Errorf("config = %+v", cfg)
	}
	if len(cfg.ExcludedGlobs) == 0 {
		t.Error("the shipped default exclusions should be present")
	}
}

func BenchmarkClassify(b *testing.B) {
	cl, err := index.NewClassifier(index.Config{RespectGitignore: true, MaxFileBytes: 1 << 20,
		ExcludedGlobs: []string{"**/node_modules/**", "**/dist/**"}},
		index.NewRuleSet(index.ParseFile("*.log\nbuild/\n!keep.log\n", "", index.SourceGitignore)))
	if err != nil {
		b.Fatal(err)
	}
	f := index.File{Path: "packages/web/src/components/Button.tsx", Size: 4096,
		Contents: []byte("import React from 'react';\n")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cl.Classify(f)
	}
}
