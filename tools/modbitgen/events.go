package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// eventCatalog mirrors contracts/events/catalog.yaml.
type eventCatalog struct {
	Version  int           `yaml:"version"`
	Families []eventFamily `yaml:"families"`
	Events   []eventDef    `yaml:"events"`
}

type eventFamily struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
}

type eventDef struct {
	Type          string `yaml:"type"`
	Version       int    `yaml:"version"`
	Family        string `yaml:"family"`
	Scope         string `yaml:"scope"`
	Description   string `yaml:"description"`
	Audit         bool   `yaml:"audit"`
	PayloadSchema string `yaml:"payload_schema"`
}

// validScopes drives envelope validation in pkg/event. The order is least to most constrained.
var validScopes = map[string]bool{
	"system":       true,
	"organization": true,
	"worker":       true,
	"space":        true,
	"run":          true,
}

func loadEventCatalog(path string) (*eventCatalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c eventCatalog
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.normalizeAndValidate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *eventCatalog) normalizeAndValidate() error {
	if c.Version == 0 {
		return fmt.Errorf("catalog version is required")
	}
	families := make(map[string]struct{}, len(c.Families))
	for _, f := range c.Families {
		if f.ID == "" {
			return fmt.Errorf("family id is required")
		}
		if _, dup := families[f.ID]; dup {
			return fmt.Errorf("duplicate family %q", f.ID)
		}
		families[f.ID] = struct{}{}
	}

	seen := make(map[string]struct{}, len(c.Events))
	for i := range c.Events {
		e := &c.Events[i]
		if e.Version == 0 {
			e.Version = 1 // catalog omits version 1 for readability
		}
		if e.Type == "" {
			return fmt.Errorf("event type is required")
		}
		if e.Type != strings.ToLower(e.Type) {
			return fmt.Errorf("event %q must be lower case", e.Type)
		}
		if !strings.Contains(e.Type, ".") {
			return fmt.Errorf("event %q must be dotted <domain>.<subject>.<verb>", e.Type)
		}
		key := fmt.Sprintf("%s@%d", e.Type, e.Version)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate event %q", key)
		}
		seen[key] = struct{}{}
		if _, ok := families[e.Family]; !ok {
			return fmt.Errorf("event %q references unknown family %q", e.Type, e.Family)
		}
		if !validScopes[e.Scope] {
			return fmt.Errorf("event %q has invalid scope %q", e.Type, e.Scope)
		}
	}
	return nil
}

func (c *eventCatalog) emitGo() []byte {
	var b strings.Builder
	b.WriteString(generatedGoHeader("event", "contracts/events/catalog.yaml"))

	fmt.Fprintf(&b, "// CatalogVersion is the version of contracts/events/catalog.yaml this file was generated from.\nconst CatalogVersion = %d\n\n", c.Version)

	b.WriteString("// Event families.\nconst (\n")
	for _, f := range c.Families {
		b.WriteString(wrapComment(f.Description, "\t", 100))
		fmt.Fprintf(&b, "\tFamily%s Family = %s\n\n", goIdent(f.ID), goQuote(f.ID))
	}
	b.WriteString(")\n\n")

	b.WriteString("// Canonical event types. Every authoritative run transition emits one of these (INV-5).\nconst (\n")
	for _, e := range c.Events {
		if e.Description != "" {
			b.WriteString(wrapComment(e.Description, "\t", 100))
		}
		fmt.Fprintf(&b, "\tType%s Type = %s\n", goIdent(e.Type), goQuote(e.Type))
	}
	b.WriteString(")\n\n")

	b.WriteString("// specs is the generated catalog consulted by New and Validate.\nvar specs = map[Type]Spec{\n")
	for _, e := range c.Events {
		fmt.Fprintf(&b, "\tType%s: {\n", goIdent(e.Type))
		fmt.Fprintf(&b, "\t\tType:    %s,\n", goQuote(e.Type))
		fmt.Fprintf(&b, "\t\tVersion: %d,\n", e.Version)
		fmt.Fprintf(&b, "\t\tFamily:  %s,\n", goQuote(e.Family))
		fmt.Fprintf(&b, "\t\tScope:   %s,\n", "Scope"+goIdent(e.Scope))
		fmt.Fprintf(&b, "\t\tAudit:   %t,\n", e.Audit)
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func (c *eventCatalog) emitTS() []byte {
	var b strings.Builder
	b.WriteString(generatedTSHeader("contracts/events/catalog.yaml"))

	fmt.Fprintf(&b, "export const EVENT_CATALOG_VERSION = %d;\n\n", c.Version)

	b.WriteString("export const EventType = {\n")
	for _, e := range c.Events {
		fmt.Fprintf(&b, "  %s: %s,\n", tsConstName(e.Type), goQuote(e.Type))
	}
	b.WriteString("} as const;\n\n")
	b.WriteString("export type EventType = (typeof EventType)[keyof typeof EventType];\n\n")

	b.WriteString("export type EventScope = 'system' | 'organization' | 'worker' | 'space' | 'run';\n\n")
	b.WriteString("export interface EventSpec {\n  readonly type: EventType;\n  readonly version: number;\n  readonly family: string;\n  readonly scope: EventScope;\n  readonly audit: boolean;\n}\n\n")

	b.WriteString("export const EVENT_SPECS: Readonly<Record<EventType, EventSpec>> = {\n")
	for _, e := range c.Events {
		fmt.Fprintf(&b, "  [EventType.%s]: { type: %s, version: %d, family: %s, scope: %s, audit: %t },\n",
			tsConstName(e.Type), goQuote(e.Type), e.Version, goQuote(e.Family), goQuote(e.Scope), e.Audit)
	}
	b.WriteString("} as const;\n")
	return []byte(b.String())
}
