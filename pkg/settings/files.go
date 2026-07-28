package settings

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/modbit/modbit/pkg/modberr"
)

// Local settings files (F1–F8).
//
// PRD §20A places authored settings in files at several scopes, and one of those files travels with
// the repository. That single fact shapes everything here: a repository-committed settings document
// is content a contributor chose, which makes it untrusted input (TNT-1) that the product reads and
// acts on. The resolver already refuses a lower scope weakening a higher-scope security setting; the
// loader's job is to make sure a file can never be *presented* as a scope it did not come from.
//
// One test each in files_test.go. A test without an F-number, or an F-number without a test, is a
// gap.
//
//	F1 A file's scope comes from its location, never from its contents.
//	F2 A repository-committed file can never author a policy scope.
//	F3 An unreadable, oversized, or malformed file is a diagnostic, never a silent default.
//	F4 Unknown keys are preserved and reported.
//	F5 Files are read only from declared locations; a symlink out is refused.
//	F6 A file may only author settings whose definition permits that scope.
//	F7 Discovery order is deterministic.
//	F8 A missing file is an ordinary outcome, not an error.

// MaxSettingsFileBytes bounds a settings document.
//
// A settings file is a small structured document. Anything larger is not the file a person wrote,
// and reading it unbounded lets a repository choose how much memory the product spends — the same
// reasoning that bounds the git plumbing files the indexer reads.
const MaxSettingsFileBytes = 1 << 20

// FileSource is one settings document and the scope its location authorizes.
type FileSource struct {
	// Scope is decided by where the file is, not by anything inside it (F1).
	Scope Scope
	Path  string
	// Committed marks a file that travels with the repository, and therefore carries repository
	// provenance. It is recorded so a reader of the source map can tell which values a contributor
	// could have influenced.
	Committed bool
}

// repositoryLayout is the declared set of repository-relative settings files, in discovery order.
//
// F7. The order is a contract, not an implementation detail: it decides which file's value survives
// when two author the same key at the same scope, and a map would make that answer vary per run —
// the same defect as B-9 in the index ignore files.
var repositoryLayout = []struct {
	rel       string
	scope     Scope
	committed bool
}{
	// Committed, team-shared. Untrusted: a contributor chose its contents.
	{rel: ".modbit/settings.json", scope: ScopeRepository, committed: true},
	// Personal, not committed. Conventionally gitignored.
	{rel: ".modbit/settings.local.json", scope: ScopeRepositoryLocal, committed: false},
}

// userLayout is the declared set of home-relative settings files, in discovery order.
var userLayout = []struct {
	rel   string
	scope Scope
}{
	{rel: ".modbit/settings.json", scope: ScopeUser},
	{rel: ".modbit/device.json", scope: ScopeDevice},
}

// RepositoryFiles returns the settings documents a repository may carry, in discovery order.
//
// F5. Paths are joined to the resolved root and never taken from the documents themselves, so no
// value inside a settings file can redirect the loader at another path.
func RepositoryFiles(root string) ([]FileSource, error) {
	resolved, err := filepath.Abs(root)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "repository root cannot be resolved")
	}
	out := make([]FileSource, 0, len(repositoryLayout))
	for _, entry := range repositoryLayout {
		out = append(out, FileSource{
			Scope:     entry.scope,
			Path:      filepath.Join(resolved, filepath.FromSlash(entry.rel)),
			Committed: entry.committed,
		})
	}
	return out, nil
}

// UserFiles returns the settings documents a home directory may carry, in discovery order.
func UserFiles(home string) ([]FileSource, error) {
	resolved, err := filepath.Abs(home)
	if err != nil {
		return nil, modberr.Wrap(err, modberr.CodeInvalidArgument, "home directory cannot be resolved")
	}
	out := make([]FileSource, 0, len(userLayout))
	for _, entry := range userLayout {
		out = append(out, FileSource{
			Scope: entry.scope,
			Path:  filepath.Join(resolved, filepath.FromSlash(entry.rel)),
		})
	}
	return out, nil
}

// fileScopes is the closed set of scopes a local file may author.
//
// F2. Policy scopes are absent, and that absence is the control. A repository that could author
// `product_safety` or `enterprise_policy` would be publishing its own constraint envelope — the
// exact inversion the scope hierarchy exists to prevent, and one that a resolver check alone would
// not stop, because the resolver trusts the scope the layer declares.
var fileScopes = map[Scope]bool{
	ScopeRepository:      true,
	ScopeRepositoryLocal: true,
	ScopeUser:            true,
	ScopeDevice:          true,
	ScopeSession:         true,
}

// LoadFile reads one settings document into a layer.
//
// A missing file returns an empty layer and no error (F8): most of these files do not exist on most
// machines, and treating absence as a failure would make the ordinary case noisy.
func LoadFile(src FileSource, registry *Registry) (Layer, []Diagnostic, error) {
	if registry == nil {
		return Layer{}, nil, modberr.New(modberr.CodeInvalidArgument, "loading settings requires a registry").
			WithDetail("field", "registry")
	}
	// F1, F2. The scope is checked against the closed set before anything is read, so a caller
	// cannot construct a FileSource claiming a policy scope and have it honoured.
	if !fileScopes[src.Scope] {
		return Layer{}, nil, modberr.Newf(modberr.CodeSettingPolicyViolation,
			"scope %q cannot be authored by a local file", src.Scope).
			WithDetail("scope", string(src.Scope))
	}

	layer := Layer{Scope: src.Scope, SourceID: src.Path, Values: map[Key]any{}}

	info, err := os.Lstat(src.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return layer, nil, nil
	}
	if err != nil {
		return layer, []Diagnostic{{
			Scope: src.Scope, Severity: SeverityWarning, Code: "settings_file_unreadable",
			Message: "settings file could not be inspected",
		}}, nil
	}
	// F5. A symlinked settings file is not followed. A repository can commit a link, and following
	// one would read a file the repository chose from somewhere the layout never declared — the same
	// reasoning that stops the indexer following links (CTX-A01b decision 52).
	if info.Mode()&fs.ModeSymlink != 0 {
		return layer, []Diagnostic{{
			Scope: src.Scope, Severity: SeverityWarning, Code: "settings_file_symlink",
			Message: "settings file is a symbolic link and was not read",
		}}, nil
	}
	if !info.Mode().IsRegular() {
		return layer, []Diagnostic{{
			Scope: src.Scope, Severity: SeverityWarning, Code: "settings_file_irregular",
			Message: "settings file is not a regular file and was not read",
		}}, nil
	}
	if info.Size() > MaxSettingsFileBytes {
		// F3. Refusing loudly beats reading a document nobody wrote by hand.
		return layer, []Diagnostic{{
			Scope: src.Scope, Severity: SeverityError, Code: "settings_file_too_large",
			Message: "settings file exceeds the maximum size and was not read",
		}}, nil
	}

	contents, err := os.ReadFile(src.Path)
	if err != nil {
		return layer, []Diagnostic{{
			Scope: src.Scope, Severity: SeverityWarning, Code: "settings_file_unreadable",
			Message: "settings file could not be read",
		}}, nil
	}

	var raw map[string]any
	if err := json.Unmarshal(contents, &raw); err != nil {
		// F3. A malformed file is reported and contributes nothing. Falling back to defaults
		// silently would leave a user believing their configuration is in force when it is not,
		// which for a security setting is the worst available outcome.
		return layer, []Diagnostic{{
			Scope: src.Scope, Severity: SeverityError, Code: "settings_file_malformed",
			Message: "settings file is not a valid JSON object and was not applied",
		}}, nil
	}

	var diagnostics []Diagnostic
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	// F7. Sorted so diagnostics come out in a stable order; map iteration would reorder them per run
	// and make two identical loads produce different reports.
	slices.Sort(keys)

	for _, name := range keys {
		key := Key(name)
		def, known := registry.Lookup(key)
		if !known {
			// F4. SET-2: unknown keys survive and are reported rather than being dropped. A key from
			// a newer build must not be destroyed by an older one reading the same file.
			diagnostics = append(diagnostics, Diagnostic{
				Key: key, Scope: src.Scope, Severity: SeverityInfo, Code: "unknown_setting",
				Message: "setting is not in this build's registry and was preserved unapplied",
			})
			continue
		}
		// F6. A definition lists the scopes it may be authored at. Loading a value into a scope the
		// definition forbids would let a repository set something only an organization may set.
		if !def.AllowsScope(src.Scope) {
			diagnostics = append(diagnostics, Diagnostic{
				Key: key, Scope: src.Scope, Severity: SeverityWarning, Code: "scope_not_permitted",
				Message: "setting cannot be authored at this scope and was ignored",
			})
			continue
		}
		layer.Values[key] = raw[name]
	}
	return layer, diagnostics, nil
}

// LoadLayers reads every source in order and returns the layers that carry values.
//
// Diagnostics accumulate across sources rather than stopping at the first problem: a user with two
// malformed files should learn about both, not discover the second only after fixing the first.
func LoadLayers(sources []FileSource, registry *Registry) ([]Layer, []Diagnostic, error) {
	var (
		layers      []Layer
		diagnostics []Diagnostic
	)
	for _, src := range sources {
		layer, diags, err := LoadFile(src, registry)
		if err != nil {
			return nil, diagnostics, err
		}
		diagnostics = append(diagnostics, diags...)
		if len(layer.Values) > 0 {
			layers = append(layers, layer)
		}
	}
	return layers, diagnostics, nil
}
