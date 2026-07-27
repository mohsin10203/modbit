package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// capabilityCatalog is the machine-readable Capability Registry
// (capability-matrix-v5.1.md "Release gate").
type capabilityCatalog struct {
	Capabilities []capability
}

type capability struct {
	ID            string            `yaml:"id"`
	Version       int               `yaml:"version"`
	Owner         string            `yaml:"owner"`
	SecurityClass string            `yaml:"security_class"`
	Requirements  []string          `yaml:"requirements"`
	Surfaces      map[string]string `yaml:"surfaces"`
	Events        []string          `yaml:"events"`
	Settings      []string          `yaml:"settings"`
	Tests         []string          `yaml:"tests"`

	source string
}

// surfaceStates mirror the capability-matrix legend: required, equivalent structured workflow,
// administrator only, or not applicable.
var surfaceStates = map[string]bool{
	"required": true, "equivalent": true, "admin_only": true, "not_applicable": true,
}

var knownSurfaces = map[string]bool{
	"desktop": true, "cli": true, "ts_sdk": true, "python_sdk": true,
	"web": true, "extension": true, "jetbrains": true, "mobile": true,
}

func loadCapabilityCatalog(dir string) (*capabilityCatalog, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return &capabilityCatalog{}, nil
		}
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	sort.Strings(paths)

	catalog := &capabilityCatalog{}
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var c capability
		if err := yaml.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		c.source = p
		if _, dup := seen[c.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate capability id %q", p, c.ID)
		}
		seen[c.ID] = struct{}{}
		catalog.Capabilities = append(catalog.Capabilities, c)
	}
	return catalog, nil
}

// validate cross-checks every capability against the event and settings catalogs. A registry entry
// that names a nonexistent event or setting would let a capability pass `capability-check` while
// its surfaces are unobservable or unconfigurable.
func (c *capabilityCatalog) validate(settings *settingsCatalog, events *eventCatalog) error {
	knownEvents := make(map[string]struct{}, len(events.Events))
	for _, e := range events.Events {
		knownEvents[e.Type] = struct{}{}
	}
	knownSettings := make(map[string]struct{}, len(settings.Definitions))
	for _, d := range settings.Definitions {
		knownSettings[d.Key] = struct{}{}
	}

	for _, cap := range c.Capabilities {
		fail := func(format string, args ...any) error {
			return fmt.Errorf("%s: capability %q: %s", cap.source, cap.ID, fmt.Sprintf(format, args...))
		}
		if cap.ID == "" {
			return fmt.Errorf("%s: capability id is required", cap.source)
		}
		if cap.Version == 0 {
			return fail("version is required")
		}
		if cap.Owner == "" {
			return fail("owner is required (PRD §0.3: every shipped capability has an owner)")
		}
		if !validSecurityClasses[cap.SecurityClass] {
			return fail("invalid security_class %q", cap.SecurityClass)
		}
		if len(cap.Requirements) == 0 {
			return fail("at least one PRD requirement reference is required (R-DOC-01)")
		}
		if len(cap.Surfaces) == 0 {
			return fail("surfaces are required")
		}
		for surface, state := range cap.Surfaces {
			if !knownSurfaces[surface] {
				return fail("unknown surface %q", surface)
			}
			if !surfaceStates[state] {
				return fail("surface %q has invalid state %q", surface, state)
			}
		}
		for _, e := range cap.Events {
			if _, ok := knownEvents[e]; !ok {
				return fail("references event %q which is absent from contracts/events/catalog.yaml", e)
			}
		}
		for _, s := range cap.Settings {
			if _, ok := knownSettings[s]; !ok {
				return fail("references setting %q which is absent from contracts/settings", s)
			}
		}
		if len(cap.Tests) == 0 {
			return fail("at least one test reference is required (R-TST-01)")
		}
		if strings.TrimSpace(strings.Join(cap.Tests, "")) == "" {
			return fail("test references must be non-empty")
		}
	}
	return nil
}
