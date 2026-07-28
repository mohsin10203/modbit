package settings_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/settings"
)

func writeSettings(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func diagnosticCodes(diags []settings.Diagnostic) []string {
	out := make([]string, 0, len(diags))
	for _, d := range diags {
		out = append(out, d.Code)
	}
	return out
}

func hasCode(diags []settings.Diagnostic, code string) bool {
	for _, d := range diags {
		if d.Code == code {
			return true
		}
	}
	return false
}

// F1, F2. A repository-committed settings document is content a contributor chose, so it is
// untrusted input the product reads and acts on. A repository that could author a policy scope would
// be publishing its own constraint envelope — the exact inversion the scope hierarchy prevents, and
// one the resolver cannot catch on its own because it trusts the scope the layer declares.
func TestSecurityALocalFileCanNeverAuthorAPolicyScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeSettings(t, path, `{"agent.default_mode":"code"}`)

	for _, scope := range []settings.Scope{
		settings.ScopeProductSafety,
		settings.ScopeEnterprisePolicy,
		settings.ScopeOrganization,
		settings.ScopeTeam,
		settings.ScopeSpace,
		settings.ScopeAgentProfile,
	} {
		t.Run(string(scope), func(t *testing.T) {
			_, _, err := settings.LoadFile(
				settings.FileSource{Scope: scope, Path: path}, settings.Default())
			if !modberr.Is(err, modberr.CodeSettingPolicyViolation) {
				t.Fatalf("error = %v, want a policy violation for scope %q", err, scope)
			}
		})
	}

	// The scopes a file may legitimately author still work, so the refusals above are the gate
	// rather than loading being broken.
	for _, scope := range []settings.Scope{
		settings.ScopeRepository, settings.ScopeRepositoryLocal,
		settings.ScopeUser, settings.ScopeDevice, settings.ScopeSession,
	} {
		if _, _, err := settings.LoadFile(
			settings.FileSource{Scope: scope, Path: path}, settings.Default()); err != nil {
			t.Fatalf("scope %q was refused: %v", scope, err)
		}
	}
}

// F1, second half: the scope comes from the location. Nothing inside the document can change it, so
// a committed file declaring itself organization-scoped is just a file with an unknown key in it.
func TestSecurityAFileCannotDeclareItsOwnScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeSettings(t, path, `{"scope":"enterprise_policy","agent.retry_limit":9}`)

	layer, diags, err := settings.LoadFile(
		settings.FileSource{Scope: settings.ScopeRepository, Path: path, Committed: true},
		settings.Default())
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if layer.Scope != settings.ScopeRepository {
		t.Fatalf("layer scope = %q; a document must not be able to choose its own scope", layer.Scope)
	}
	// The "scope" key is simply unknown, and is reported as such rather than acted on.
	if !hasCode(diags, "unknown_setting") {
		t.Fatalf("diagnostics = %v, want the bogus key reported", diagnosticCodes(diags))
	}
	if _, present := layer.Values["scope"]; present {
		t.Fatal("an unknown key was applied as a value")
	}
}

// F3. Falling back to defaults silently would leave a user believing their configuration is in
// force when it is not — for a security setting, the worst available outcome.
func TestMalformedAndOversizedFilesAreDiagnosedNotIgnored(t *testing.T) {
	dir := t.TempDir()
	registry := settings.Default()

	malformed := filepath.Join(dir, "bad.json")
	writeSettings(t, malformed, `{"agent.retry_limit": 3,,,}`)
	layer, diags, err := settings.LoadFile(
		settings.FileSource{Scope: settings.ScopeUser, Path: malformed}, registry)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(layer.Values) != 0 {
		t.Fatal("a malformed file contributed values")
	}
	if !hasCode(diags, "settings_file_malformed") {
		t.Fatalf("diagnostics = %v, want the malformed file reported", diagnosticCodes(diags))
	}
	for _, d := range diags {
		if d.Severity != settings.SeverityError {
			continue
		}
		if strings.Contains(d.Message, "retry_limit") {
			t.Fatal("the diagnostic echoed the file's contents")
		}
	}

	oversized := filepath.Join(dir, "big.json")
	writeSettings(t, oversized, `{"padding":"`+strings.Repeat("x", settings.MaxSettingsFileBytes)+`"}`)
	layer, diags, err = settings.LoadFile(
		settings.FileSource{Scope: settings.ScopeUser, Path: oversized}, registry)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(layer.Values) != 0 {
		t.Fatal("an oversized file contributed values")
	}
	if !hasCode(diags, "settings_file_too_large") {
		t.Fatalf("diagnostics = %v, want the oversized file reported", diagnosticCodes(diags))
	}
}

// F4. SET-2: a key from a newer build must not be destroyed by an older one reading the same file.
func TestUnknownKeysInAFileArePreservedAndReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeSettings(t, path, `{"agent.retry_limit":2,"agent.future_setting":true}`)

	layer, diags, err := settings.LoadFile(
		settings.FileSource{Scope: settings.ScopeUser, Path: path}, settings.Default())
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if _, ok := layer.Values["agent.retry_limit"]; !ok {
		t.Fatal("the known setting was not applied")
	}
	if _, ok := layer.Values["agent.future_setting"]; ok {
		t.Fatal("an unknown setting was applied rather than preserved unapplied")
	}
	if !hasCode(diags, "unknown_setting") {
		t.Fatalf("diagnostics = %v, want the unknown key reported", diagnosticCodes(diags))
	}
}

// F5. A repository can commit a symlink, and following one would read a file the repository chose
// from somewhere the layout never declared — the same reasoning that stops the indexer following
// links.
func TestSecuritySymlinkedSettingsFilesAreNotFollowed(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "elsewhere.json")
	writeSettings(t, secret, `{"agent.retry_limit":10}`)

	link := filepath.Join(dir, "settings.json")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	layer, diags, err := settings.LoadFile(
		settings.FileSource{Scope: settings.ScopeRepository, Path: link, Committed: true},
		settings.Default())
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(layer.Values) != 0 {
		t.Fatal("a symlinked settings file was followed")
	}
	if !hasCode(diags, "settings_file_symlink") {
		t.Fatalf("diagnostics = %v, want the symlink reported", diagnosticCodes(diags))
	}
}

// F6. A definition lists the scopes it may be authored at. Loading a value into a scope the
// definition forbids would let a repository set something only an organization may set.
func TestSecurityAFileCannotAuthorASettingItsScopeForbids(t *testing.T) {
	registry := settings.Default()

	// Find a setting that is not authorable at repository_local, so the test tracks the contract
	// rather than a hardcoded key that may be re-scoped later.
	var restricted settings.Key
	for _, def := range registry.Definitions() {
		if !def.AllowsScope(settings.ScopeRepositoryLocal) {
			restricted = def.Key
			break
		}
	}
	if restricted == "" {
		t.Skip("no setting in the registry forbids repository_local")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "settings.local.json")
	writeSettings(t, path, `{"`+string(restricted)+`":"anything"}`)

	layer, diags, err := settings.LoadFile(
		settings.FileSource{Scope: settings.ScopeRepositoryLocal, Path: path}, registry)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if _, applied := layer.Values[restricted]; applied {
		t.Fatalf("%q was authored at a scope its definition forbids", restricted)
	}
	if !hasCode(diags, "scope_not_permitted") {
		t.Fatalf("diagnostics = %v, want the scope refusal reported", diagnosticCodes(diags))
	}
}

// F7. Discovery order decides which file wins when two author the same key, and a map would make
// that answer vary per run — the same defect as B-9 in the index ignore files.
func TestDiscoveryOrderIsDeterministic(t *testing.T) {
	root := t.TempDir()

	var first []string
	for range 20 {
		sources, err := settings.RepositoryFiles(root)
		if err != nil {
			t.Fatalf("RepositoryFiles: %v", err)
		}
		order := make([]string, 0, len(sources))
		for _, src := range sources {
			order = append(order, string(src.Scope)+":"+filepath.Base(src.Path))
		}
		if first == nil {
			first = order
			continue
		}
		for i := range first {
			if order[i] != first[i] {
				t.Fatalf("discovery order changed at %d: %q then %q", i, first[i], order[i])
			}
		}
	}

	// Key order within a file matters for the same reason: two identical loads must produce the
	// same diagnostics in the same order, or a report is not comparable against its predecessor.
	// This was missed the first time — the file-source order above comes from a static slice and
	// would be stable with no sorting at all, so it could not catch an unsorted key walk.
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeSettings(t, path, `{"zz.unknown":1,"aa.unknown":2,"mm.unknown":3,"bb.unknown":4}`)

	var firstKeys []string
	for range 20 {
		_, diags, err := settings.LoadFile(
			settings.FileSource{Scope: settings.ScopeUser, Path: path}, settings.Default())
		if err != nil {
			t.Fatalf("LoadFile: %v", err)
		}
		keys := make([]string, 0, len(diags))
		for _, d := range diags {
			keys = append(keys, string(d.Key))
		}
		if len(keys) != 4 {
			t.Fatalf("diagnostics = %v, want one per unknown key", keys)
		}
		if firstKeys == nil {
			firstKeys = keys
			if !slices.IsSorted(keys) {
				t.Fatalf("diagnostic keys are not sorted: %v", keys)
			}
			continue
		}
		for i := range firstKeys {
			if keys[i] != firstKeys[i] {
				t.Fatalf("diagnostic order is unstable at %d: %q then %q", i, firstKeys[i], keys[i])
			}
		}
	}

	// The committed file must come first and be marked committed; the personal override must not be.
	sources, _ := settings.RepositoryFiles(root)
	if !sources[0].Committed {
		t.Fatal("the committed repository file is not marked committed")
	}
	if sources[1].Committed {
		t.Fatal("the personal override is marked committed")
	}
	if sources[0].Scope != settings.ScopeRepository || sources[1].Scope != settings.ScopeRepositoryLocal {
		t.Fatalf("scopes = %q, %q", sources[0].Scope, sources[1].Scope)
	}
}

// F8. Most of these files do not exist on most machines, and treating absence as a failure would
// make the ordinary case noisy.
func TestAMissingFileIsAnOrdinaryOutcome(t *testing.T) {
	root := t.TempDir()
	sources, err := settings.RepositoryFiles(root)
	if err != nil {
		t.Fatalf("RepositoryFiles: %v", err)
	}

	layers, diags, err := settings.LoadLayers(sources, settings.Default())
	if err != nil {
		t.Fatalf("LoadLayers: %v", err)
	}
	if len(layers) != 0 {
		t.Fatalf("layers = %d, want none from an empty tree", len(layers))
	}
	if len(diags) != 0 {
		t.Fatalf("diagnostics = %v, want none for absent files", diagnosticCodes(diags))
	}
}

// The loader feeds the resolver, and the two together are what SET-A01 is for: a repository's
// preference applies, and a repository cannot weaken a higher scope.
func TestLoadedLayersResolveThroughTheRegistry(t *testing.T) {
	root := t.TempDir()
	// context.indexing.max_file_bytes is authorable at both repository scopes and merges by
	// minimum, so this asserts the loader feeding the resolver rather than a scope precedence rule.
	writeSettings(t, filepath.Join(root, ".modbit", "settings.json"), `{"context.indexing.max_file_bytes":2000000}`)
	writeSettings(t, filepath.Join(root, ".modbit", "settings.local.json"), `{"context.indexing.max_file_bytes":500000}`)

	sources, err := settings.RepositoryFiles(root)
	if err != nil {
		t.Fatalf("RepositoryFiles: %v", err)
	}
	layers, diags, err := settings.LoadLayers(sources, settings.Default())
	if err != nil {
		t.Fatalf("LoadLayers: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diagnosticCodes(diags))
	}
	if len(layers) != 2 {
		t.Fatalf("layers = %d, want 2", len(layers))
	}

	resolver, err := settings.NewResolver(settings.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	result, err := resolver.Resolve(layers)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	value, ok := result.Value("context.indexing.max_file_bytes")
	if !ok {
		t.Fatal("context.indexing.max_file_bytes did not resolve")
	}
	if got := toInt(t, value); got != 500000 {
		t.Fatalf("max_file_bytes = %d, want the minimum of the two authored values", got)
	}
}

func toInt(t *testing.T, value any) int64 {
	t.Helper()
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	default:
		t.Fatalf("value %v is not numeric (%T)", value, value)
		return 0
	}
}
