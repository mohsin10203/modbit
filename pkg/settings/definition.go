// Package settings implements the Modbit Settings Registry, its scope model, and the resolver
// that compiles a policy envelope and merges preference scopes into an effective value.
//
// Boundary: definition, validation, envelope compilation, merge, and resolution diagnostics. This
// package does not read files, call the network, or persist anything; storage and sync live in the
// Settings service, and the desktop cache adapts this package to disk.
//
// Requirements: PRD v5.1 §20A.3–§20A.5, SET-1 (unknown settings preserved and reported), SET-2
// (no silent fallback), SET-3 (versioned schemas), SET-7 (no secrets); rules.md R-SET-01..10 and
// INV-9 (lower scopes never weaken higher-scope security policy).
package settings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Key is a Settings Registry key. Consume the generated Key* constants; string literals are
// prohibited (R-SET-02).
type Key string

// Type is a setting's value type.
type Type string

const (
	TypeBool       Type = "bool"
	TypeInt        Type = "int"
	TypeNumber     Type = "number"
	TypeString     Type = "string"
	TypeEnum       Type = "enum"
	TypeStringList Type = "string_list"
	TypeObject     Type = "object"
)

// Scope is a settings scope from PRD v5.1 §20A.4.
type Scope string

const (
	// ScopeProductSafety holds immutable Modbit hard protections. It is not authorable in a
	// contract file or a settings document; the platform installs it.
	ScopeProductSafety Scope = "product_safety"
	// ScopeEnterprisePolicy holds cross-organization enforced controls.
	ScopeEnterprisePolicy Scope = "enterprise_policy"
	ScopeOrganization     Scope = "organization"
	ScopeTeam             Scope = "team"
	ScopeSpace            Scope = "space"
	// ScopeRepository is the git-committed, team-shared repository configuration.
	ScopeRepository   Scope = "repository"
	ScopeAgentProfile Scope = "agent_profile"
	// ScopeUser is the synced personal preference scope.
	ScopeUser   Scope = "user"
	ScopeDevice Scope = "device"
	// ScopeRepositoryLocal is the personal, non-committed repository override.
	ScopeRepositoryLocal Scope = "repository_local"
	// ScopeSession is a temporary override for one session or run.
	ScopeSession Scope = "session"
	// ScopeProductDefault is the synthetic source reported when no layer supplied a value. It is
	// never a layer scope.
	ScopeProductDefault Scope = "product_default"
)

// policyScopes establish the allowed envelope, ordered from strongest authority downward. Lower
// scopes may narrow the envelope further but never widen it (INV-9).
var policyScopes = []Scope{
	ScopeProductSafety,
	ScopeEnterprisePolicy,
	ScopeOrganization,
	ScopeTeam,
	ScopeSpace,
	ScopeRepository,
}

// preferenceOrder is PRD v5.1 §20A.5 "Preference resolution", highest precedence first. Within the
// policy envelope, the closest applicable preference wins.
var preferenceOrder = []Scope{
	ScopeSession,
	ScopeRepositoryLocal,
	ScopeAgentProfile,
	ScopeRepository,
	ScopeSpace,
	ScopeDevice,
	ScopeUser,
	ScopeTeam,
	ScopeOrganization,
}

// IsPolicyScope reports whether s may publish policy constraints.
func IsPolicyScope(s Scope) bool {
	for _, p := range policyScopes {
		if p == s {
			return true
		}
	}
	return false
}

// PreferenceRank returns s's position in the preference order, lower being higher precedence, and
// whether s participates in preference resolution at all.
func PreferenceRank(s Scope) (int, bool) {
	for i, p := range preferenceOrder {
		if p == s {
			return i, true
		}
	}
	return 0, false
}

// MergeStrategy is how values from multiple scopes combine (PRD v5.1 §20A.5).
type MergeStrategy string

const (
	// MergeOverride takes the closest applicable preference.
	MergeOverride MergeStrategy = "override"
	// MergeAppendUnique concatenates lists in precedence order, dropping duplicates.
	MergeAppendUnique MergeStrategy = "append_unique"
	// MergeUnion is a sorted set union. Order carries no meaning for union settings.
	MergeUnion MergeStrategy = "union"
	// MergeIntersection keeps only entries present in every contributing scope. "*" is the
	// universal set, so a scope that has not narrowed the list does not accidentally empty it.
	MergeIntersection MergeStrategy = "intersection"
	// MergeUnionDeny is a sorted union used for denylists.
	MergeUnionDeny MergeStrategy = "union_deny"
	// MergeMinimum takes the smallest numeric value, used for caps and budgets.
	MergeMinimum MergeStrategy = "minimum"
	// MergeMaximum takes the largest numeric value, used for floors.
	MergeMaximum MergeStrategy = "maximum"
	// MergeMostRestrictive takes the value earliest in RestrictiveOrder.
	MergeMostRestrictive MergeStrategy = "most_restrictive"
	// MergeDeepMerge recursively merges objects, closest preference winning per leaf.
	MergeDeepMerge MergeStrategy = "deep_merge"
	// MergeCustom delegates to a merger registered with the Registry.
	MergeCustom MergeStrategy = "custom"
)

// ChangeEffect declares when a change takes effect. The Settings UI shows it (PRD §20A.8).
type ChangeEffect string

const (
	EffectImmediate       ChangeEffect = "immediate"
	EffectNextToolCall    ChangeEffect = "next_tool_call"
	EffectNextRun         ChangeEffect = "next_run"
	EffectNextIndex       ChangeEffect = "next_index"
	EffectRestartRequired ChangeEffect = "restart_required"
)

// SecurityClass grades a setting's blast radius. High and critical settings are lockable by policy
// and always appear in the audit trail.
type SecurityClass string

const (
	SecurityNone     SecurityClass = "none"
	SecurityLow      SecurityClass = "low"
	SecurityMedium   SecurityClass = "medium"
	SecurityHigh     SecurityClass = "high"
	SecurityCritical SecurityClass = "critical"
)

// Wildcard is the universal-set marker in allowlists. A scope that has not narrowed an allowlist
// carries ["*"], so intersecting with it is a no-op.
const Wildcard = "*"

// Definition is a Settings Registry entry.
type Definition struct {
	Key       Key
	Namespace string
	// SchemaVersion is the version of the namespace contract this definition came from (SET-3).
	SchemaVersion int
	Type          Type
	// Enum lists permitted values when Type is TypeEnum.
	Enum []string
	// Default is the product default: the safe value. Defaults never grant capability.
	Default any
	Min     *int64
	Max     *int64
	// Scopes lists the scopes where this setting may be authored.
	Scopes []Scope
	Merge  MergeStrategy
	// RestrictiveOrder lists values from most to least restrictive. Required for
	// MergeMostRestrictive and used to interpret a policy Ceiling.
	RestrictiveOrder []any
	ChangeEffect     ChangeEffect
	SecurityClass    SecurityClass
	Description      string
	Deprecated       bool
}

// AllowsScope reports whether this setting may be authored at s.
func (d Definition) AllowsScope(s Scope) bool {
	for _, allowed := range d.Scopes {
		if allowed == s {
			return true
		}
	}
	return false
}

// restrictiveIndex returns v's position in RestrictiveOrder, lower being more restrictive.
func (d Definition) restrictiveIndex(v any) (int, bool) {
	for i, candidate := range d.RestrictiveOrder {
		if valuesEqual(candidate, v) {
			return i, true
		}
	}
	return 0, false
}

// Merger implements MergeCustom for one key.
type Merger interface {
	// Merge folds contributions, ordered highest precedence first, into one value.
	Merge(def Definition, contributions []any) (any, error)
}

// Registry is an immutable, validated set of definitions.
type Registry struct {
	byKey   map[Key]Definition
	ordered []Definition
	mergers map[Key]Merger
}

// NewRegistry validates defs and returns a Registry.
//
// Validation duplicates part of the generator's contract validation on purpose: the generated
// registry is trusted, but a Registry assembled in a test or by a plugin registering a namespaced
// schema (SET-6) is not.
func NewRegistry(defs []Definition, mergers map[Key]Merger) (*Registry, error) {
	r := &Registry{
		byKey:   make(map[Key]Definition, len(defs)),
		ordered: make([]Definition, 0, len(defs)),
		mergers: make(map[Key]Merger, len(mergers)),
	}
	for k, m := range mergers {
		r.mergers[k] = m
	}
	for _, d := range defs {
		if _, dup := r.byKey[d.Key]; dup {
			return nil, modberr.Newf(modberr.CodeInvalidArgument, "duplicate settings key %q", d.Key).
				WithDetail("setting_key", string(d.Key))
		}
		if err := r.validateDefinition(d); err != nil {
			return nil, err
		}
		r.byKey[d.Key] = d
		r.ordered = append(r.ordered, d)
	}
	sort.Slice(r.ordered, func(i, j int) bool { return r.ordered[i].Key < r.ordered[j].Key })
	return r, nil
}

// listMerges only operate on string lists; numericMerges only on numbers.
var (
	listMerges = map[MergeStrategy]bool{
		MergeAppendUnique: true, MergeUnion: true, MergeIntersection: true, MergeUnionDeny: true,
	}
	numericMerges = map[MergeStrategy]bool{MergeMinimum: true, MergeMaximum: true}
	numericTypes  = map[Type]bool{TypeInt: true, TypeNumber: true}
	orderedTypes  = map[Type]bool{TypeEnum: true, TypeString: true, TypeBool: true}
)

func validateMergeForType(d Definition, fail func(string) error) error {
	switch {
	case listMerges[d.Merge] && d.Type != TypeStringList:
		return fail(fmt.Sprintf("merge %q requires type string_list, got %q", d.Merge, d.Type))
	case numericMerges[d.Merge] && !numericTypes[d.Type]:
		return fail(fmt.Sprintf("merge %q requires a numeric type, got %q", d.Merge, d.Type))
	case d.Merge == MergeDeepMerge && d.Type != TypeObject:
		return fail(fmt.Sprintf("merge deep_merge requires type object, got %q", d.Type))
	case d.Merge == MergeMostRestrictive && !orderedTypes[d.Type]:
		return fail(fmt.Sprintf("merge most_restrictive requires an ordered type, got %q", d.Type))
	}
	return nil
}

func (r *Registry) validateDefinition(d Definition) error {
	fail := func(msg string) error {
		return modberr.Newf(modberr.CodeSettingInvalid, "setting %q: %s", d.Key, msg).
			WithDetail("setting_key", string(d.Key))
	}
	if d.Key == "" {
		return fail("key is required")
	}
	if d.SchemaVersion <= 0 {
		return fail("schema version is required (SET-3)")
	}
	if len(d.Scopes) == 0 {
		return fail("at least one scope is required")
	}
	for _, s := range d.Scopes {
		if s == ScopeProductSafety || s == ScopeProductDefault {
			return fail("product_safety and product_default are not authorable scopes")
		}
	}
	switch d.Type {
	case TypeBool, TypeInt, TypeNumber, TypeString, TypeEnum, TypeStringList, TypeObject:
	default:
		return fail(fmt.Sprintf("unknown type %q", d.Type))
	}
	if d.Type == TypeEnum && len(d.Enum) == 0 {
		return fail("enum type requires enum values")
	}
	if d.Merge == MergeMostRestrictive && len(d.RestrictiveOrder) == 0 {
		return fail("merge most_restrictive requires restrictive_order")
	}
	// Merge/type compatibility. modbitgen rejects these in contract files, but a Registry may also
	// be built by a test or by a plugin registering a namespaced schema (SET-6), and those paths do
	// not pass through the generator. Without this check a mismatched pair reaches the merge switch
	// and fails a type assertion at resolution time, which is a panic on a request path (R-GO-08).
	if err := validateMergeForType(d, fail); err != nil {
		return err
	}
	if d.Merge == MergeCustom {
		if _, ok := r.mergers[d.Key]; !ok {
			return fail("merge custom requires a registered Merger")
		}
	}
	if _, err := coerce(d, d.Default); err != nil {
		return fail("default value is not valid for the declared type")
	}
	return nil
}

// Default returns the generated Settings Registry.
func Default() *Registry {
	r, err := NewRegistry(definitions, nil)
	if err != nil {
		// The generated registry is produced by modbitgen, which validates every definition before
		// emitting it. A failure here means generated code and this package disagree, which is a
		// build-time defect rather than a runtime condition (R-GO-08).
		panic(fmt.Sprintf("settings: generated registry is invalid: %v", err))
	}
	return r
}

// Lookup returns the definition for k.
func (r *Registry) Lookup(k Key) (Definition, bool) {
	d, ok := r.byKey[k]
	return d, ok
}

// Definitions returns every definition, sorted by key.
func (r *Registry) Definitions() []Definition {
	out := make([]Definition, len(r.ordered))
	copy(out, r.ordered)
	return out
}

// Keys returns every registered key, sorted.
func (r *Registry) Keys() []Key {
	out := make([]Key, 0, len(r.ordered))
	for _, d := range r.ordered {
		out = append(out, d.Key)
	}
	return out
}

// Namespaces returns the distinct namespaces present, sorted.
func (r *Registry) Namespaces() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, d := range r.ordered {
		if _, ok := seen[d.Namespace]; ok {
			continue
		}
		seen[d.Namespace] = struct{}{}
		out = append(out, d.Namespace)
	}
	sort.Strings(out)
	return out
}

// String renders a key for diagnostics.
func (k Key) String() string { return string(k) }

// Namespace returns the leading dotted segment of the key.
func (k Key) Namespace() string {
	if i := strings.IndexByte(string(k), '.'); i > 0 {
		return string(k)[:i]
	}
	return string(k)
}
