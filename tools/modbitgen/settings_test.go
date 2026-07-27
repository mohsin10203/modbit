package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeContracts materializes a minimal contracts tree containing the supplied settings file, so
// each case exercises the real loader rather than a mocked one.
func writeContracts(t *testing.T, settingsYAML string) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"settings", "errors", "events", "capabilities"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	write := func(rel, content string) {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	write("settings/t.yaml", settingsYAML)
	write("errors/catalog.yaml", "version: 1\ncodes:\n  - code: MODBIT_INTERNAL\n    http_status: 500\n    retryable: false\n    description: Internal.\n    detail_keys: []\n")
	write("events/catalog.yaml", "version: 1\nfamilies:\n  - id: run\n    description: Run.\nevents:\n  - { type: run.created, family: run, scope: run }\n")
	return root
}

const validSetting = `version: 1
namespace: t
settings:
  - key: t.mode
    type: enum
    enum: [manual, auto]
    default: auto
    scopes: [organization, user]
    merge: most_restrictive
    restrictive_order: [manual, auto]
    change_effect: next_run
    security_class: high
    description: A mode.
`

func TestLoadSettingsCatalogAcceptsAValidContract(t *testing.T) {
	t.Parallel()
	catalog, err := loadSettingsCatalog(filepath.Join(writeContracts(t, validSetting), "settings"))
	if err != nil {
		t.Fatalf("loadSettingsCatalog: %v", err)
	}
	if len(catalog.Definitions) != 1 || catalog.Definitions[0].Key != "t.mode" {
		t.Fatalf("definitions = %+v", catalog.Definitions)
	}
}

// Each case is a way a contract author could accidentally produce a setting whose security
// semantics are undefined or unenforceable. The generator is the gate that catches them, so every
// rejection is asserted here rather than left to review.
func TestSettingsContractValidationRejectsUnsafeDefinitions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		yaml       string
		wantSubstr string
	}{
		{
			name:       "key outside its namespace",
			yaml:       strings.Replace(validSetting, "key: t.mode", "key: other.mode", 1),
			wantSubstr: "must start with the file namespace",
		},
		{
			name:       "unknown type",
			yaml:       strings.Replace(validSetting, "type: enum", "type: colour", 1),
			wantSubstr: "invalid type",
		},
		{
			name:       "unknown merge strategy",
			yaml:       strings.Replace(validSetting, "merge: most_restrictive", "merge: last_wins", 1),
			wantSubstr: "invalid merge strategy",
		},
		{
			name:       "missing change effect",
			yaml:       strings.Replace(validSetting, "change_effect: next_run", "change_effect: eventually", 1),
			wantSubstr: "invalid change_effect",
		},
		{
			name:       "unknown scope",
			yaml:       strings.Replace(validSetting, "scopes: [organization, user]", "scopes: [organization, galaxy]", 1),
			wantSubstr: "invalid scope",
		},
		{
			name:       "default outside the enum",
			yaml:       strings.Replace(validSetting, "default: auto", "default: turbo", 1),
			wantSubstr: "not a member of the enum",
		},
		{
			// Without a total ordering, "most restrictive" has no defined meaning and an
			// implementation would be free to pick the permissive value.
			name:       "most_restrictive without an ordering",
			yaml:       strings.Replace(validSetting, "    restrictive_order: [manual, auto]\n", "", 1),
			wantSubstr: "restrictive_order must list all",
		},
		{
			name:       "incomplete ordering",
			yaml:       strings.Replace(validSetting, "restrictive_order: [manual, auto]", "restrictive_order: [manual]", 1),
			wantSubstr: "restrictive_order must list all",
		},
		{
			name:       "list strategy on a non-list type",
			yaml:       strings.Replace(validSetting, "merge: most_restrictive", "merge: union_deny", 1),
			wantSubstr: "requires type string_list",
		},
		{
			name:       "numeric strategy on a non-numeric type",
			yaml:       strings.Replace(validSetting, "merge: most_restrictive", "merge: minimum", 1),
			wantSubstr: "requires a numeric type",
		},
		{
			name: "most_restrictive on a numeric type is ambiguous",
			yaml: `version: 1
namespace: t
settings:
  - key: t.cap
    type: int
    default: 5
    scopes: [organization]
    merge: most_restrictive
    change_effect: next_run
    security_class: high
    description: A cap.
`,
			wantSubstr: "ambiguous for a numeric type",
		},
		{
			name: "default below the declared minimum",
			yaml: `version: 1
namespace: t
settings:
  - key: t.cap
    type: int
    default: 1
    min: 10
    max: 100
    scopes: [organization]
    merge: minimum
    change_effect: next_run
    security_class: high
    description: A cap.
`,
			wantSubstr: "below min",
		},
		{
			name:       "missing description",
			yaml:       strings.Replace(validSetting, "description: A mode.", `description: ""`, 1),
			wantSubstr: "description is required",
		},
		{
			name:       "missing namespace version",
			yaml:       strings.Replace(validSetting, "version: 1\n", "", 1),
			wantSubstr: "version is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadSettingsCatalog(filepath.Join(writeContracts(t, tc.yaml), "settings"))
			if err == nil {
				t.Fatalf("expected a validation error mentioning %q", tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestDuplicateSettingsKeyAcrossFilesIsRejected(t *testing.T) {
	t.Parallel()
	root := writeContracts(t, validSetting)
	if err := os.WriteFile(filepath.Join(root, "settings", "t2.yaml"), []byte(validSetting), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadSettingsCatalog(filepath.Join(root, "settings"))
	if err == nil || !strings.Contains(err.Error(), "duplicate settings key") {
		t.Fatalf("error = %v, want a duplicate-key rejection", err)
	}
}

// R-ERR-02 is enforced at generation time: a detail key whose name invites a sensitive value is
// rejected before it can reach an error payload.
func TestErrorCatalogRejectsSensitiveDetailKeys(t *testing.T) {
	t.Parallel()
	root := writeContracts(t, validSetting)
	bad := `version: 1
codes:
  - code: MODBIT_INTERNAL
    http_status: 500
    retryable: false
    description: Internal.
    detail_keys: [provider_api_key]
`
	if err := os.WriteFile(filepath.Join(root, "errors", "catalog.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadErrorCatalog(filepath.Join(root, "errors", "catalog.yaml"))
	if err == nil || !strings.Contains(err.Error(), "R-ERR-02") {
		t.Fatalf("error = %v, want a sensitive-detail-key rejection", err)
	}
}

func TestEventCatalogRejectsAnUnknownFamilyOrScope(t *testing.T) {
	t.Parallel()
	root := writeContracts(t, validSetting)

	writeEvents := func(content string) string {
		path := filepath.Join(root, "events", "catalog.yaml")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return path
	}

	path := writeEvents("version: 1\nfamilies:\n  - id: run\n    description: Run.\nevents:\n  - { type: run.created, family: nosuch, scope: run }\n")
	if _, err := loadEventCatalog(path); err == nil || !strings.Contains(err.Error(), "unknown family") {
		t.Errorf("error = %v, want an unknown-family rejection", err)
	}

	path = writeEvents("version: 1\nfamilies:\n  - id: run\n    description: Run.\nevents:\n  - { type: run.created, family: run, scope: galaxy }\n")
	if _, err := loadEventCatalog(path); err == nil || !strings.Contains(err.Error(), "invalid scope") {
		t.Errorf("error = %v, want an invalid-scope rejection", err)
	}

	path = writeEvents("version: 1\nfamilies:\n  - id: run\n    description: Run.\nevents:\n  - { type: runcreated, family: run, scope: run }\n")
	if _, err := loadEventCatalog(path); err == nil || !strings.Contains(err.Error(), "must be dotted") {
		t.Errorf("error = %v, want a naming rejection", err)
	}
}

// A capability that names an event or setting which does not exist would pass capability-check
// while its surfaces are unobservable or unconfigurable.
func TestCapabilityValidationCrossChecksEventsAndSettings(t *testing.T) {
	t.Parallel()
	root := writeContracts(t, validSetting)
	settingsCat, err := loadSettingsCatalog(filepath.Join(root, "settings"))
	if err != nil {
		t.Fatalf("loadSettingsCatalog: %v", err)
	}
	eventCat, err := loadEventCatalog(filepath.Join(root, "events", "catalog.yaml"))
	if err != nil {
		t.Fatalf("loadEventCatalog: %v", err)
	}

	writeCapability := func(content string) *capabilityCatalog {
		if err := os.WriteFile(filepath.Join(root, "capabilities", "c.yaml"), []byte(content), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		catalog, err := loadCapabilityCatalog(filepath.Join(root, "capabilities"))
		if err != nil {
			t.Fatalf("loadCapabilityCatalog: %v", err)
		}
		return catalog
	}

	const base = `id: t.cap
version: 1
owner: platform
security_class: high
requirements: [PRD-v5.1-1]
surfaces:
  desktop: required
events: [%s]
settings: [%s]
tests: [conformance/t]
`

	catalog := writeCapability(fmt.Sprintf(base, "run.created", "t.mode"))
	if err := catalog.validate(settingsCat, eventCat); err != nil {
		t.Fatalf("a valid capability was rejected: %v", err)
	}

	catalog = writeCapability(fmt.Sprintf(base, "run.invented", "t.mode"))
	if err := catalog.validate(settingsCat, eventCat); err == nil || !strings.Contains(err.Error(), "absent from contracts/events") {
		t.Errorf("error = %v, want an unknown-event rejection", err)
	}

	catalog = writeCapability(fmt.Sprintf(base, "run.created", "t.invented"))
	if err := catalog.validate(settingsCat, eventCat); err == nil || !strings.Contains(err.Error(), "absent from contracts/settings") {
		t.Errorf("error = %v, want an unknown-setting rejection", err)
	}
}
