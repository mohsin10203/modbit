package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// settingsCatalog is the union of every contracts/settings/*.yaml namespace file.
type settingsCatalog struct {
	Namespaces  []string
	Definitions []settingDef
}

type settingsFile struct {
	Version   int          `yaml:"version"`
	Namespace string       `yaml:"namespace"`
	Settings  []settingDef `yaml:"settings"`
}

type settingDef struct {
	Key              string   `yaml:"key"`
	Type             string   `yaml:"type"`
	Enum             []string `yaml:"enum"`
	Default          any      `yaml:"default"`
	Min              *int64   `yaml:"min"`
	Max              *int64   `yaml:"max"`
	Scopes           []string `yaml:"scopes"`
	Merge            string   `yaml:"merge"`
	RestrictiveOrder []any    `yaml:"restrictive_order"`
	ChangeEffect     string   `yaml:"change_effect"`
	SecurityClass    string   `yaml:"security_class"`
	Description      string   `yaml:"description"`
	Deprecated       bool     `yaml:"deprecated"`
	// UI metadata. All optional: what can be derived from the key and type is derived, so a new
	// setting is renderable the moment it is declared. Only what derivation cannot know is declared
	// here — an "advanced" disclosure is a product judgement, not a property of a key.
	Label    string `yaml:"label"`
	Group    string `yaml:"group"`
	Widget   string `yaml:"widget"`
	Advanced bool   `yaml:"advanced"`

	namespace string
	version   int
	// uiOrder is the setting's position within its contract file. Declaration order is already a
	// reviewed sequence — the author grouped related keys together — so it is a better default
	// ordering than anything derivable from the key, and it costs nothing to carry.
	uiOrder int
}

var (
	validTypes = map[string]bool{
		"bool": true, "int": true, "number": true, "string": true,
		"enum": true, "string_list": true, "object": true,
	}
	// Scope names follow PRD v5.1 §20A.4. product_safety is implicit and not authorable in a
	// contract file, so it is absent here.
	validSettingScopes = map[string]bool{
		"enterprise_policy": true, "organization": true, "team": true, "space": true,
		"repository": true, "agent_profile": true, "user": true, "device": true,
		"repository_local": true, "session": true,
	}
	validMerges = map[string]bool{
		"override": true, "append_unique": true, "union": true, "intersection": true,
		"union_deny": true, "minimum": true, "maximum": true, "most_restrictive": true,
		"deep_merge": true, "custom": true,
	}
	validChangeEffects = map[string]bool{
		"immediate": true, "next_tool_call": true, "next_run": true,
		"next_index": true, "restart_required": true,
	}
	validSecurityClasses = map[string]bool{
		"none": true, "low": true, "medium": true, "high": true, "critical": true,
	}
	// listMerges are strategies that only make sense for string_list.
	listMerges = map[string]bool{
		"append_unique": true, "union": true, "intersection": true, "union_deny": true,
	}
	numericMerges = map[string]bool{"minimum": true, "maximum": true}
	numericTypes  = map[string]bool{"int": true, "number": true}
)

func loadSettingsCatalog(dir string) (*settingsCatalog, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	sort.Strings(paths) // deterministic emission order

	catalog := &settingsCatalog{}
	seen := make(map[string]string) // key -> source file, for duplicate detection
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var f settingsFile
		if err := yaml.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		if f.Namespace == "" {
			return nil, fmt.Errorf("%s: namespace is required", p)
		}
		if f.Version == 0 {
			return nil, fmt.Errorf("%s: version is required (SET-3)", p)
		}
		catalog.Namespaces = append(catalog.Namespaces, f.Namespace)
		for index, d := range f.Settings {
			if prev, dup := seen[d.Key]; dup {
				return nil, fmt.Errorf("%s: duplicate settings key %q (already defined in %s)", p, d.Key, prev)
			}
			seen[d.Key] = p
			d.namespace = f.Namespace
			d.version = f.Version
			d.uiOrder = index
			if err := d.validate(p); err != nil {
				return nil, err
			}
			if err := d.validateUI(); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			catalog.Definitions = append(catalog.Definitions, d)
		}
	}
	sort.Slice(catalog.Definitions, func(i, j int) bool {
		return catalog.Definitions[i].Key < catalog.Definitions[j].Key
	})
	if len(catalog.Definitions) == 0 {
		return nil, fmt.Errorf("%s: no settings definitions found", dir)
	}
	return catalog, nil
}

func (d settingDef) validate(source string) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%s: setting %q: %s", source, d.Key, fmt.Sprintf(format, args...))
	}

	if d.Key == "" {
		return fmt.Errorf("%s: a setting is missing its key", source)
	}
	if !strings.HasPrefix(d.Key, d.namespace+".") {
		return fail("key must start with the file namespace %q", d.namespace+".")
	}
	if d.Key != strings.ToLower(d.Key) {
		return fail("key must be lower case")
	}
	if !validTypes[d.Type] {
		return fail("invalid type %q", d.Type)
	}
	if !validMerges[d.Merge] {
		return fail("invalid merge strategy %q", d.Merge)
	}
	if !validChangeEffects[d.ChangeEffect] {
		return fail("invalid change_effect %q (SET / §20A.8 requires a declared application timing)", d.ChangeEffect)
	}
	if !validSecurityClasses[d.SecurityClass] {
		return fail("invalid security_class %q", d.SecurityClass)
	}
	if strings.TrimSpace(d.Description) == "" {
		return fail("description is required")
	}
	if len(d.Scopes) == 0 {
		return fail("at least one scope is required")
	}
	seenScope := make(map[string]struct{}, len(d.Scopes))
	for _, s := range d.Scopes {
		if !validSettingScopes[s] {
			return fail("invalid scope %q", s)
		}
		if _, dup := seenScope[s]; dup {
			return fail("duplicate scope %q", s)
		}
		seenScope[s] = struct{}{}
	}

	// Type/merge compatibility. A mismatched strategy is the most common way a security envelope
	// silently stops being restrictive, so it is rejected at generation time (R-SET-05).
	switch {
	case listMerges[d.Merge] && d.Type != "string_list":
		return fail("merge %q requires type string_list, got %q", d.Merge, d.Type)
	case numericMerges[d.Merge] && !numericTypes[d.Type]:
		return fail("merge %q requires a numeric type, got %q", d.Merge, d.Type)
	case d.Merge == "deep_merge" && d.Type != "object":
		return fail("merge deep_merge requires type object, got %q", d.Type)
	}

	if d.Type == "enum" {
		if len(d.Enum) == 0 {
			return fail("type enum requires an enum list")
		}
		if !containsString(d.Enum, fmt.Sprint(d.Default)) {
			return fail("default %v is not a member of the enum", d.Default)
		}
	} else if len(d.Enum) > 0 {
		return fail("enum is only valid for type enum")
	}

	if d.Merge == "most_restrictive" {
		if err := d.validateRestrictiveOrder(fail); err != nil {
			return err
		}
	} else if len(d.RestrictiveOrder) > 0 {
		return fail("restrictive_order is only meaningful for merge most_restrictive")
	}

	if d.Default == nil && d.Type != "object" && d.Type != "string_list" && d.Type != "string" {
		return fail("default is required")
	}
	if err := d.validateDefaultType(fail); err != nil {
		return err
	}
	if (d.Min != nil || d.Max != nil) && !numericTypes[d.Type] {
		return fail("min/max are only valid for numeric types")
	}
	if d.Min != nil && d.Max != nil && *d.Min > *d.Max {
		return fail("min %d exceeds max %d", *d.Min, *d.Max)
	}
	if n, ok := asInt64(d.Default); ok {
		if d.Min != nil && n < *d.Min {
			return fail("default %d is below min %d", n, *d.Min)
		}
		if d.Max != nil && n > *d.Max {
			return fail("default %d is above max %d", n, *d.Max)
		}
	}
	return nil
}

// validateRestrictiveOrder requires an explicit, total ordering from most to least restrictive.
// Without it, a "most_restrictive" merge has no defined meaning for enums and bools, and an
// implementation would be free to pick the permissive value.
func (d settingDef) validateRestrictiveOrder(fail func(string, ...any) error) error {
	switch d.Type {
	case "enum":
		if len(d.RestrictiveOrder) != len(d.Enum) {
			return fail("restrictive_order must list all %d enum values from most to least restrictive, got %d", len(d.Enum), len(d.RestrictiveOrder))
		}
		seen := make(map[string]struct{}, len(d.RestrictiveOrder))
		for _, v := range d.RestrictiveOrder {
			s := fmt.Sprint(v)
			if !containsString(d.Enum, s) {
				return fail("restrictive_order contains %q which is not an enum member", s)
			}
			if _, dup := seen[s]; dup {
				return fail("restrictive_order repeats %q", s)
			}
			seen[s] = struct{}{}
		}
	case "bool":
		if len(d.RestrictiveOrder) != 2 {
			return fail("restrictive_order for a bool must list both values, most restrictive first")
		}
		a, aok := d.RestrictiveOrder[0].(bool)
		b, bok := d.RestrictiveOrder[1].(bool)
		if !aok || !bok || a == b {
			return fail("restrictive_order for a bool must be [true, false] or [false, true]")
		}
	case "int", "number":
		if len(d.RestrictiveOrder) > 0 {
			return fail("numeric settings express restriction through merge minimum or maximum, not restrictive_order")
		}
		return fail("merge most_restrictive is ambiguous for a numeric type; use minimum or maximum")
	default:
		return fail("merge most_restrictive is not supported for type %q", d.Type)
	}
	return nil
}

func (d settingDef) validateDefaultType(fail func(string, ...any) error) error {
	switch d.Type {
	case "bool":
		if _, ok := d.Default.(bool); !ok {
			return fail("default must be a bool")
		}
	case "int":
		if _, ok := asInt64(d.Default); !ok {
			return fail("default must be an integer")
		}
	case "number":
		switch d.Default.(type) {
		case int, int64, float64:
		default:
			return fail("default must be numeric")
		}
	case "string", "enum":
		if _, ok := d.Default.(string); !ok {
			return fail("default must be a string")
		}
	case "string_list":
		if d.Default == nil {
			return nil
		}
		items, ok := d.Default.([]any)
		if !ok {
			return fail("default must be a list")
		}
		for _, it := range items {
			if _, ok := it.(string); !ok {
				return fail("default list must contain only strings")
			}
		}
	case "object":
		if d.Default == nil {
			return nil
		}
		if _, ok := d.Default.(map[string]any); !ok {
			return fail("default must be an object")
		}
	}
	return nil
}

func (c *settingsCatalog) emitGo() []byte {
	var b strings.Builder
	b.WriteString(generatedGoHeader("settings", "contracts/settings/*.yaml"))

	b.WriteString("// Settings keys. Consume these constants; string literals for settings keys are\n// prohibited (R-SET-02).\nconst (\n")
	for _, d := range c.Definitions {
		b.WriteString(wrapComment(d.Description, "\t", 100))
		fmt.Fprintf(&b, "\tKey%s Key = %s\n\n", goIdent(d.Key), goQuote(d.Key))
	}
	b.WriteString(")\n\n")

	b.WriteString("// definitions is the generated Settings Registry. NewRegistry copies it.\nvar definitions = []Definition{\n")
	for _, d := range c.Definitions {
		fmt.Fprintf(&b, "\t{\n")
		fmt.Fprintf(&b, "\t\tKey:              %s,\n", goQuote(d.Key))
		fmt.Fprintf(&b, "\t\tNamespace:        %s,\n", goQuote(d.namespace))
		fmt.Fprintf(&b, "\t\tSchemaVersion:    %d,\n", d.version)
		fmt.Fprintf(&b, "\t\tType:             %s,\n", "Type"+goIdent(d.Type))
		if len(d.Enum) > 0 {
			fmt.Fprintf(&b, "\t\tEnum:             %s,\n", goStringSlice(d.Enum))
		}
		fmt.Fprintf(&b, "\t\tDefault:          %s,\n", goAnyLiteral(normalizeDefault(d)))
		if d.Min != nil {
			fmt.Fprintf(&b, "\t\tMin:              ptrInt64(%d),\n", *d.Min)
		}
		if d.Max != nil {
			fmt.Fprintf(&b, "\t\tMax:              ptrInt64(%d),\n", *d.Max)
		}
		fmt.Fprintf(&b, "\t\tScopes:           %s,\n", goScopeSlice(d.Scopes))
		fmt.Fprintf(&b, "\t\tMerge:            %s,\n", "Merge"+goIdent(d.Merge))
		if len(d.RestrictiveOrder) > 0 {
			fmt.Fprintf(&b, "\t\tRestrictiveOrder: %s,\n", goAnySlice(d.RestrictiveOrder))
		}
		fmt.Fprintf(&b, "\t\tChangeEffect:     %s,\n", "Effect"+goIdent(d.ChangeEffect))
		fmt.Fprintf(&b, "\t\tSecurityClass:    %s,\n", "Security"+goIdent(d.SecurityClass))
		fmt.Fprintf(&b, "\t\tDescription:      %s,\n", goQuote(strings.Join(strings.Fields(d.Description), " ")))
		if d.Deprecated {
			b.WriteString("\t\tDeprecated:       true,\n")
		}
		ui := d.uiMetadata()
		fmt.Fprintf(&b, "\t\tUI: UI{Label: %s, Group: %s, Order: %d, Widget: %s",
			goQuote(ui.label), goQuote(ui.group), ui.order, widgetIdent(ui.widget))
		if ui.advanced {
			b.WriteString(", Advanced: true")
		}
		b.WriteString("},\n")
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n\nfunc ptrInt64(v int64) *int64 { return &v }\n")
	return []byte(b.String())
}

// normalizeDefault fills in the zero value for optional container defaults so the generated
// registry never carries a nil where the resolver expects a typed empty value.
func normalizeDefault(d settingDef) any {
	if d.Default != nil {
		return d.Default
	}
	switch d.Type {
	case "string_list":
		return []any{}
	case "object":
		return map[string]any{}
	case "string":
		return ""
	default:
		return nil
	}
}

func goScopeSlice(scopes []string) string {
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		parts[i] = "Scope" + goIdent(s)
	}
	return "[]Scope{" + strings.Join(parts, ", ") + "}"
}

func (c *settingsCatalog) emitTS() []byte {
	var b strings.Builder
	b.WriteString(generatedTSHeader("contracts/settings/*.yaml"))

	b.WriteString("export const SettingKey = {\n")
	for _, d := range c.Definitions {
		fmt.Fprintf(&b, "  %s: %s,\n", tsConstName(d.Key), goQuote(d.Key))
	}
	b.WriteString("} as const;\n\n")
	b.WriteString("export type SettingKey = (typeof SettingKey)[keyof typeof SettingKey];\n\n")

	b.WriteString("export type SettingType =\n  | 'bool'\n  | 'int'\n  | 'number'\n  | 'string'\n  | 'enum'\n  | 'string_list'\n  | 'object';\n\n")
	b.WriteString("export type SettingScope =\n  | 'product_safety'\n  | 'enterprise_policy'\n  | 'organization'\n  | 'team'\n  | 'space'\n  | 'repository'\n  | 'agent_profile'\n  | 'user'\n  | 'device'\n  | 'repository_local'\n  | 'session';\n\n")
	b.WriteString("export type MergeStrategy =\n  | 'override'\n  | 'append_unique'\n  | 'union'\n  | 'intersection'\n  | 'union_deny'\n  | 'minimum'\n  | 'maximum'\n  | 'most_restrictive'\n  | 'deep_merge'\n  | 'custom';\n\n")
	b.WriteString("export type ChangeEffect =\n  | 'immediate'\n  | 'next_tool_call'\n  | 'next_run'\n  | 'next_index'\n  | 'restart_required';\n\n")
	b.WriteString("export type SecurityClass = 'none' | 'low' | 'medium' | 'high' | 'critical';\n\n")

	b.WriteString("export interface SettingDefinition {\n")
	b.WriteString("  readonly key: SettingKey;\n  readonly namespace: string;\n  readonly schemaVersion: number;\n")
	b.WriteString("  readonly type: SettingType;\n  readonly enum?: readonly string[];\n  readonly default: unknown;\n")
	b.WriteString("  readonly min?: number;\n  readonly max?: number;\n  readonly scopes: readonly SettingScope[];\n")
	b.WriteString("  readonly merge: MergeStrategy;\n  readonly restrictiveOrder?: readonly unknown[];\n")
	b.WriteString("  readonly changeEffect: ChangeEffect;\n  readonly securityClass: SecurityClass;\n")
	b.WriteString("  readonly description: string;\n  readonly deprecated: boolean;\n")
	// §20A.6: ts_sdk and web are declared surfaces for the settings capability, so they need the
	// same presentation metadata the Go registry carries. Emitting it from one contract is what
	// stops the two surfaces disagreeing about what a control is called.
	b.WriteString("  readonly ui: SettingUI;\n}\n\n")
	b.WriteString("export interface SettingUI {\n")
	b.WriteString("  readonly label: string;\n  readonly group: string;\n")
	b.WriteString("  readonly order: number;\n  readonly widget: Widget;\n")
	b.WriteString("  readonly advanced: boolean;\n}\n\n")
	b.WriteString("export type Widget = \"toggle\" | \"select\" | \"number\" | \"text\" | \"list\" | \"json\";\n\n")

	b.WriteString("export const SETTING_DEFINITIONS: Readonly<Record<SettingKey, SettingDefinition>> = {\n")
	for _, d := range c.Definitions {
		fmt.Fprintf(&b, "  [SettingKey.%s]: {\n", tsConstName(d.Key))
		fmt.Fprintf(&b, "    key: %s,\n", goQuote(d.Key))
		fmt.Fprintf(&b, "    namespace: %s,\n", goQuote(d.namespace))
		fmt.Fprintf(&b, "    schemaVersion: %d,\n", d.version)
		fmt.Fprintf(&b, "    type: %s,\n", goQuote(d.Type))
		if len(d.Enum) > 0 {
			fmt.Fprintf(&b, "    enum: %s,\n", tsLiteral(toAnySlice(d.Enum)))
		}
		fmt.Fprintf(&b, "    default: %s,\n", tsLiteral(normalizeDefault(d)))
		if d.Min != nil {
			fmt.Fprintf(&b, "    min: %d,\n", *d.Min)
		}
		if d.Max != nil {
			fmt.Fprintf(&b, "    max: %d,\n", *d.Max)
		}
		fmt.Fprintf(&b, "    scopes: %s,\n", tsLiteral(toAnySlice(d.Scopes)))
		fmt.Fprintf(&b, "    merge: %s,\n", goQuote(d.Merge))
		if len(d.RestrictiveOrder) > 0 {
			fmt.Fprintf(&b, "    restrictiveOrder: %s,\n", tsLiteral(d.RestrictiveOrder))
		}
		fmt.Fprintf(&b, "    changeEffect: %s,\n", goQuote(d.ChangeEffect))
		fmt.Fprintf(&b, "    securityClass: %s,\n", goQuote(d.SecurityClass))
		fmt.Fprintf(&b, "    description: %s,\n", goQuote(strings.Join(strings.Fields(d.Description), " ")))
		ui := d.uiMetadata()
		fmt.Fprintf(&b, "    ui: { label: %s, group: %s, order: %d, widget: %s, advanced: %t },\n",
			goQuote(ui.label), goQuote(ui.group), ui.order, goQuote(ui.widget), ui.advanced)
		fmt.Fprintf(&b, "    deprecated: %t,\n", d.Deprecated)
		b.WriteString("  },\n")
	}
	b.WriteString("} as const;\n")
	return []byte(b.String())
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		if t == float64(int64(t)) {
			return int64(t), true
		}
	}
	return 0, false
}

// resolvedUI is a definition's presentation metadata after derivation and overrides.
type resolvedUI struct {
	label    string
	group    string
	order    int
	widget   string
	advanced bool
}

// widgetsForType mirrors pkg/settings.widgetsForType. It is duplicated rather than imported because
// the generator must not depend on the package it generates — a generator that imported its own
// output could not build from a clean tree. The pair is kept honest by
// TestGeneratorWidgetTableMatchesTheRuntime.
var widgetsForType = map[string][]string{
	"bool":        {"toggle"},
	"int":         {"number"},
	"number":      {"number"},
	"string":      {"text", "select"},
	"enum":        {"select"},
	"string_list": {"list"},
	"object":      {"json"},
}

// uiMetadata derives presentation metadata, letting any declared value win (U3).
func (d settingDef) uiMetadata() resolvedUI {
	ui := resolvedUI{
		label:    d.Label,
		group:    d.Group,
		widget:   d.Widget,
		advanced: d.Advanced,
		order:    d.uiOrder,
	}
	if ui.label == "" {
		ui.label = deriveLabel(d.Key)
	}
	if ui.group == "" {
		ui.group = deriveGroup(d.Key)
	}
	if ui.widget == "" {
		ui.widget = defaultWidget(d.Type)
	}
	return ui
}

// widgetIdent maps a contract widget name onto its Go constant. It is an explicit table rather than
// goIdent because "json" must become WidgetJSON, and a generic identifier rule produces WidgetJson —
// a mismatch the compiler catches, but only after the generated file is written.
func widgetIdent(widget string) string {
	switch widget {
	case "toggle":
		return "WidgetToggle"
	case "select":
		return "WidgetSelect"
	case "number":
		return "WidgetNumber"
	case "text":
		return "WidgetText"
	case "list":
		return "WidgetList"
	default:
		return "WidgetJSON"
	}
}

func defaultWidget(t string) string {
	if allowed := widgetsForType[t]; len(allowed) > 0 {
		return allowed[0]
	}
	return "json"
}

// generatorInitialisms mirrors pkg/settings.initialisms, for the same reason widgetsForType is
// duplicated.
var generatorInitialisms = map[string]string{
	"api": "API", "cpu": "CPU", "dlp": "DLP", "gpu": "GPU", "id": "ID",
	"ide": "IDE", "mb": "MB", "mcp": "MCP", "sso": "SSO", "ttl": "TTL",
	"ui": "UI", "url": "URL", "vcs": "VCS",
}

func deriveLabel(key string) string {
	segments := strings.Split(key, ".")
	words := strings.Split(segments[len(segments)-1], "_")
	for i, word := range words {
		if word == "" {
			continue
		}
		if upper, ok := generatorInitialisms[word]; ok {
			words[i] = upper
			continue
		}
		if i == 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

func deriveGroup(key string) string {
	segments := strings.Split(key, ".")
	if len(segments) >= 3 {
		return segments[1]
	}
	return segments[0]
}

// validateUI refuses a widget that cannot render its type (U4).
func (d settingDef) validateUI() error {
	if d.Widget == "" {
		return nil
	}
	for _, allowed := range widgetsForType[d.Type] {
		if allowed == d.Widget {
			return nil
		}
	}
	return fmt.Errorf("setting %q: widget %q cannot render type %q (permitted: %v)",
		d.Key, d.Widget, d.Type, widgetsForType[d.Type])
}
