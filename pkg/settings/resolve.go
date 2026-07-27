package settings

import (
	"fmt"
	"sort"

	"github.com/modbit/modbit/pkg/modberr"
)

// authoredValue is one scope's coerced preference value, retained so that the source map can
// report which scope supplied it.
type authoredValue struct {
	scope    Scope
	sourceID string
	value    any
}

// Layer is one scope's contribution: authored preference values and, for policy scopes, the
// constraints that establish the allowed envelope.
type Layer struct {
	Scope Scope
	// SourceID identifies where the layer came from — a settings document id, a managed-policy
	// bundle id, or a file path. It appears in the source map so a user can see why a value won.
	SourceID string
	// Values holds authored preference values, in whatever shape they were decoded.
	Values map[Key]any
	// Constraints holds the policy envelope published by this scope. Ignored for non-policy scopes.
	Constraints map[Key]Constraint
}

// Constraint is a policy restriction published by a policy scope.
//
// Constraints only ever narrow. Compiling several constraints together takes the tightest of each
// dimension, so a team can restrict further than its organization but never loosen (INV-9).
type Constraint struct {
	// Lock fixes the value at Value and rejects any lower-scope preference.
	Lock bool
	// Value is the locked value. Required when Lock is set.
	Value any
	// Allowed narrows an enum, string, or string_list to these members. Wildcard means unrestricted.
	Allowed []string
	// Denied removes members and is unioned across scopes.
	Denied []string
	// Min and Max bound numeric values.
	Min *int64
	Max *int64
	// Ceiling is the least restrictive value permitted, interpreted against RestrictiveOrder.
	Ceiling any
}

// IsZero reports whether the constraint imposes nothing.
func (c Constraint) IsZero() bool {
	return !c.Lock && len(c.Allowed) == 0 && len(c.Denied) == 0 &&
		c.Min == nil && c.Max == nil && c.Ceiling == nil
}

// Envelope is the compiled policy envelope for one key.
//
// Each *From field records the scope that set the surviving constraint on that dimension. Without
// them a clamp diagnostic cannot name the policy responsible, and "your value was narrowed by
// policy" is unactionable for the person reading it.
type Envelope struct {
	Locked      bool
	LockedBy    Scope
	Value       any
	Allowed     []string
	AllowedFrom Scope
	Denied      []string
	DeniedFrom  Scope
	Min         *int64
	MinFrom     Scope
	Max         *int64
	MaxFrom     Scope
	Ceiling     any
	CeilingFrom Scope
}

// Severity grades a diagnostic.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Diagnostic codes. These are stable strings surfaced in the Settings UI and in CLI output.
const (
	// DiagUnknownKey reports a key absent from the registry. The value is preserved (SET-1).
	DiagUnknownKey = "unknown_setting"
	// DiagInvalidValue reports a value that failed type, enum, or range validation (SET-2).
	DiagInvalidValue = "invalid_value"
	// DiagScopeNotPermitted reports a value authored at a scope the definition does not allow.
	DiagScopeNotPermitted = "scope_not_permitted"
	// DiagLockedOverrideIgnored reports a lower scope attempting to change a locked value.
	DiagLockedOverrideIgnored = "locked_override_ignored"
	// DiagPolicyClamped reports a merged value narrowed to fit the envelope.
	DiagPolicyClamped = "policy_clamped"
	// DiagConstraintIgnored reports a constraint published by a non-policy scope.
	DiagConstraintIgnored = "constraint_ignored"
	// DiagDeprecated reports use of a deprecated setting.
	DiagDeprecated = "deprecated_setting"
	// DiagCustomMergeFailed reports a registered custom merger returning an error.
	DiagCustomMergeFailed = "custom_merge_failed"
)

// Diagnostic explains something the resolver had to correct, reject, or preserve. Diagnostics are
// the mechanism behind SET-1 and SET-2: nothing is silently dropped or silently defaulted.
type Diagnostic struct {
	Key      Key
	Scope    Scope
	Severity Severity
	Code     string
	Message  string
}

func (d Diagnostic) String() string {
	return fmt.Sprintf("[%s] %s (%s@%s): %s", d.Severity, d.Code, d.Key, d.Scope, d.Message)
}

// Contribution records one scope's authored value and whether it survived resolution.
type Contribution struct {
	Scope    Scope
	SourceID string
	Value    any
	// Applied is false when the value was rejected, clamped away, or outranked.
	Applied bool
}

// Resolution is the full result for one key: the effective value plus everything needed to explain
// it (R-SET-08).
type Resolution struct {
	Key          Key
	Definition   Definition
	Value        any
	Source       Scope
	SourceMap    []Contribution
	Locked       bool
	LockedBy     Scope
	ChangeEffect ChangeEffect
	Diagnostics  []Diagnostic
}

// HasErrors reports whether any diagnostic is an error.
func (r Resolution) HasErrors() bool {
	for _, d := range r.Diagnostics {
		if d.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Result is the resolution of every registered key against a set of layers.
type Result struct {
	Resolutions map[Key]Resolution
	// Unknown preserves values whose keys are absent from the registry, so a round trip through
	// Modbit does not delete configuration written by a newer version or a plugin (SET-1).
	Unknown     map[Scope]map[Key]any
	Diagnostics []Diagnostic
}

// Value returns the effective value for k.
func (r Result) Value(k Key) (any, bool) {
	res, ok := r.Resolutions[k]
	if !ok {
		return nil, false
	}
	return res.Value, true
}

// Resolver compiles envelopes and merges preferences for a registry.
type Resolver struct {
	registry *Registry
}

// NewResolver returns a Resolver over registry.
func NewResolver(registry *Registry) (*Resolver, error) {
	if registry == nil {
		return nil, modberr.New(modberr.CodeInvalidArgument, "resolver requires a registry")
	}
	return &Resolver{registry: registry}, nil
}

// Resolve computes the effective value for every registered key.
//
// Layers may arrive in any order; the resolver sorts them by preference rank itself so a caller
// cannot change the outcome by reordering its inputs.
func (r *Resolver) Resolve(layers []Layer) (Result, error) {
	if err := validateLayers(layers); err != nil {
		return Result{}, err
	}
	byScope := make(map[Scope]Layer, len(layers))
	for _, l := range layers {
		byScope[l.Scope] = l
	}

	out := Result{
		Resolutions: make(map[Key]Resolution, len(r.registry.ordered)),
		Unknown:     make(map[Scope]map[Key]any),
	}

	// Preserve and report unknown keys before resolving, so the report is complete even if a later
	// resolution fails.
	for _, l := range layers {
		for k, v := range l.Values {
			if _, known := r.registry.Lookup(k); known {
				continue
			}
			if out.Unknown[l.Scope] == nil {
				out.Unknown[l.Scope] = make(map[Key]any)
			}
			out.Unknown[l.Scope][k] = v
			out.Diagnostics = append(out.Diagnostics, Diagnostic{
				Key: k, Scope: l.Scope, Severity: SeverityWarning, Code: DiagUnknownKey,
				Message: "key is not in the Settings Registry; the value is preserved but not applied",
			})
		}
	}

	for _, def := range r.registry.ordered {
		res := r.resolveOne(def, byScope)
		out.Resolutions[def.Key] = res
		out.Diagnostics = append(out.Diagnostics, res.Diagnostics...)
	}

	sortDiagnostics(out.Diagnostics)
	return out, nil
}

func validateLayers(layers []Layer) error {
	seen := make(map[Scope]struct{}, len(layers))
	for _, l := range layers {
		if l.Scope == ScopeProductDefault {
			return modberr.New(modberr.CodeInvalidArgument, "product_default is not an authorable layer scope")
		}
		if _, dup := seen[l.Scope]; dup {
			return modberr.Newf(modberr.CodeInvalidArgument, "duplicate settings layer for scope %q", l.Scope)
		}
		seen[l.Scope] = struct{}{}
	}
	return nil
}

func (r *Resolver) resolveOne(def Definition, byScope map[Scope]Layer) Resolution {
	res := Resolution{
		Key:          def.Key,
		Definition:   def,
		ChangeEffect: def.ChangeEffect,
	}
	diag := func(scope Scope, sev Severity, code, msg string) {
		res.Diagnostics = append(res.Diagnostics, Diagnostic{
			Key: def.Key, Scope: scope, Severity: sev, Code: code, Message: msg,
		})
	}

	envelope := r.compileEnvelope(def, byScope, diag)
	res.Locked = envelope.Locked
	res.LockedBy = envelope.LockedBy

	// Gather authored preference values in precedence order, highest first.
	var contributions []authoredValue
	for _, scope := range preferenceOrder {
		layer, ok := byScope[scope]
		if !ok {
			continue
		}
		raw, present := layer.Values[def.Key]
		if !present {
			continue
		}
		if !def.AllowsScope(scope) {
			diag(scope, SeverityWarning, DiagScopeNotPermitted,
				fmt.Sprintf("setting cannot be authored at scope %q", scope))
			res.SourceMap = append(res.SourceMap, Contribution{Scope: scope, SourceID: layer.SourceID, Value: raw})
			continue
		}
		value, err := coerce(def, raw)
		if err != nil {
			// SET-2: an invalid value never silently falls back. It is dropped with a visible
			// diagnostic and resolution continues with the next-closest preference.
			diag(scope, SeverityError, DiagInvalidValue, errMessage(err))
			res.SourceMap = append(res.SourceMap, Contribution{Scope: scope, SourceID: layer.SourceID, Value: raw})
			continue
		}
		if def.Deprecated {
			diag(scope, SeverityWarning, DiagDeprecated, "setting is deprecated")
		}
		contributions = append(contributions, authoredValue{scope: scope, sourceID: layer.SourceID, value: value})
	}

	// A lock short-circuits preference resolution entirely.
	if envelope.Locked {
		for _, c := range contributions {
			applied := valuesEqual(c.value, envelope.Value)
			if !applied {
				diag(c.scope, SeverityWarning, DiagLockedOverrideIgnored,
					fmt.Sprintf("value is locked by scope %q and cannot be changed here", envelope.LockedBy))
			}
			res.SourceMap = append(res.SourceMap, Contribution{
				Scope: c.scope, SourceID: c.sourceID, Value: c.value, Applied: applied,
			})
		}
		res.Value = envelope.Value
		res.Source = envelope.LockedBy
		return res
	}

	values := make([]any, 0, len(contributions)+1)
	for _, c := range contributions {
		values = append(values, c.value)
	}
	defaultValue, err := coerce(def, def.Default)
	if err != nil {
		// Unreachable for a validated registry; surfaced rather than panicking so a plugin-supplied
		// definition cannot take down a resolution pass.
		diag(ScopeProductDefault, SeverityError, DiagInvalidValue, "product default is not valid for the declared type")
		defaultValue = def.Default
	}

	merged, source, mergeDiag := r.merge(def, values, contributions, defaultValue)
	if mergeDiag != nil {
		res.Diagnostics = append(res.Diagnostics, *mergeDiag)
	}

	clamped, clampDiags := clampToEnvelope(def, merged, envelope)
	for _, d := range clampDiags {
		res.Diagnostics = append(res.Diagnostics, Diagnostic{
			Key: def.Key, Scope: d.Scope, Severity: d.Severity, Code: d.Code, Message: d.Message,
		})
	}
	if !valuesEqual(clamped, merged) {
		// The policy envelope, not a preference, determined the final value.
		source = envelopeSource(envelope)
	}
	res.Value = clamped

	for _, c := range contributions {
		res.SourceMap = append(res.SourceMap, Contribution{
			Scope:    c.scope,
			SourceID: c.sourceID,
			Value:    c.value,
			Applied:  contributionApplied(def, c.value, clamped),
		})
	}
	if len(contributions) == 0 {
		source = ScopeProductDefault
	}
	res.Source = source
	return res
}

// contributionApplied reports whether a scope's authored value is visible in the final value. For
// aggregate strategies every accepted contribution participates; for winner-take-all strategies
// only the value that equals the result did.
func contributionApplied(def Definition, value, final any) bool {
	switch def.Merge {
	case MergeAppendUnique, MergeUnion, MergeUnionDeny, MergeIntersection, MergeDeepMerge:
		return true
	default:
		return valuesEqual(value, final)
	}
}

// envelopeSource names the scope whose constraint decided the final value. Order follows how
// clampToEnvelope applies dimensions, so the reported scope matches the narrowing the user sees.
func envelopeSource(e Envelope) Scope {
	for _, candidate := range []Scope{e.CeilingFrom, e.MaxFrom, e.MinFrom, e.DeniedFrom, e.AllowedFrom} {
		if candidate != "" {
			return candidate
		}
	}
	return ScopeProductSafety
}

// compileEnvelope folds every policy scope's constraints into one envelope, taking the tightest of
// each dimension. Iteration follows policyScopes order so that the strongest authority's lock wins.
func (r *Resolver) compileEnvelope(def Definition, byScope map[Scope]Layer, diag func(Scope, Severity, string, string)) Envelope {
	var env Envelope
	var allowlists [][]string

	for _, scope := range policyScopes {
		layer, ok := byScope[scope]
		if !ok {
			continue
		}
		c, present := layer.Constraints[def.Key]
		if !present || c.IsZero() {
			continue
		}
		if !env.Locked && c.Lock {
			value, err := coerce(def, c.Value)
			if err != nil {
				diag(scope, SeverityError, DiagInvalidValue, "locked value is not valid for the declared type")
			} else {
				env.Locked = true
				env.LockedBy = scope
				env.Value = value
			}
		}
		if len(c.Allowed) > 0 {
			allowlists = append(allowlists, c.Allowed)
			if env.AllowedFrom == "" {
				env.AllowedFrom = scope // strongest authority that narrowed the allowlist
			}
		}
		if len(c.Denied) > 0 {
			env.Denied = sortedUnique(append(env.Denied, c.Denied...))
			if env.DeniedFrom == "" {
				env.DeniedFrom = scope
			}
		}
		if c.Min != nil && (env.Min == nil || *c.Min > *env.Min) {
			env.Min, env.MinFrom = c.Min, scope // tightest lower bound
		}
		if c.Max != nil && (env.Max == nil || *c.Max < *env.Max) {
			env.Max, env.MaxFrom = c.Max, scope // tightest upper bound
		}
		if c.Ceiling != nil {
			if idx, ok := def.restrictiveIndex(c.Ceiling); ok {
				current, hasCurrent := def.restrictiveIndex(env.Ceiling)
				if !hasCurrent || idx < current {
					env.Ceiling = c.Ceiling
					env.CeilingFrom = scope
				}
			} else {
				diag(scope, SeverityError, DiagInvalidValue,
					"ceiling is not present in the setting's restrictive_order")
			}
		}
	}

	// Constraints published by a scope that has no policy authority are ignored loudly.
	for scope, layer := range byScope {
		if IsPolicyScope(scope) || len(layer.Constraints) == 0 {
			continue
		}
		if c, present := layer.Constraints[def.Key]; present && !c.IsZero() {
			diag(scope, SeverityWarning, DiagConstraintIgnored,
				fmt.Sprintf("scope %q cannot publish policy constraints", scope))
		}
	}

	if len(allowlists) > 0 {
		env.Allowed = intersectAllowlists(allowlists)
	}
	return env
}

// merge folds contributions according to the definition's strategy. contributions are ordered
// highest precedence first and exclude the product default, which is supplied separately.
//
// # How the product default participates
//
// Strategies split into two groups, and the difference matters:
//
//   - Additive strategies (union, union_deny, append_unique, deep_merge) fold the default in
//     alongside authored values. The default in these settings is a baseline that must survive:
//     dropping execution.filesystem.protected_paths because a repository added one more entry
//     would be a security regression.
//   - Selective strategies (override, most_restrictive, minimum, maximum, intersection) use the
//     default only when no scope authored a value. Folding it in would turn every default into a
//     hard bound — an organization could never raise a cost cap above the shipped default, and a
//     mode whose default is auto-review could never be set to unrestricted by anyone. Hard bounds
//     are expressed through policy constraints (Ceiling, Min, Max, Allowed), not through defaults.
func (r *Resolver) merge(def Definition, values []any, contributions []authoredValue, defaultValue any) (any, Scope, *Diagnostic) {
	if len(values) == 0 {
		return defaultValue, ScopeProductDefault, nil
	}
	winner := func(v any) Scope {
		for _, c := range contributions {
			if valuesEqual(c.value, v) {
				return c.scope
			}
		}
		return ScopeProductDefault
	}

	switch def.Merge {
	case MergeOverride:
		return values[0], contributions[0].scope, nil

	case MergeMostRestrictive:
		best := values[0]
		bestIdx, ok := def.restrictiveIndex(best)
		if !ok {
			bestIdx = len(def.RestrictiveOrder)
		}
		for _, v := range values[1:] {
			idx, found := def.restrictiveIndex(v)
			if !found {
				continue
			}
			if idx < bestIdx {
				bestIdx, best = idx, v
			}
		}
		return best, winner(best), nil

	case MergeMinimum:
		best := values[0]
		for _, v := range values[1:] {
			if compareNumeric(v, best) < 0 {
				best = v
			}
		}
		return best, winner(best), nil

	case MergeMaximum:
		best := values[0]
		for _, v := range values[1:] {
			if compareNumeric(v, best) > 0 {
				best = v
			}
		}
		return best, winner(best), nil

	case MergeAppendUnique:
		combined := make([]string, 0, 16)
		for _, v := range values {
			combined = append(combined, toStrings(v)...)
		}
		combined = append(combined, toStrings(defaultValue)...)
		return dedupePreservingOrder(combined), contributions[0].scope, nil

	case MergeUnion, MergeUnionDeny:
		combined := append([]string{}, toStrings(defaultValue)...)
		for _, v := range values {
			combined = append(combined, toStrings(v)...)
		}
		return sortedUnique(combined), contributions[0].scope, nil

	case MergeIntersection:
		lists := make([][]string, 0, len(values))
		for _, v := range values {
			lists = append(lists, toStrings(v))
		}
		return intersectAllowlists(lists), contributions[0].scope, nil

	case MergeDeepMerge:
		objects := make([]map[string]any, 0, len(values)+1)
		for _, v := range values {
			if obj, ok := v.(map[string]any); ok {
				objects = append(objects, obj)
			}
		}
		if d, ok := defaultValue.(map[string]any); ok {
			objects = append(objects, d)
		}
		return deepMergeObjects(objects), contributions[0].scope, nil

	case MergeCustom:
		merger := r.registry.mergers[def.Key]
		out, err := merger.Merge(def, values)
		if err != nil {
			// SET-2: a failed custom merge is reported, never a silent fall back to the default.
			return defaultValue, ScopeProductDefault, &Diagnostic{
				Key: def.Key, Scope: contributions[0].scope, Severity: SeverityError,
				Code: DiagCustomMergeFailed, Message: "custom merger failed; the product default applies",
			}
		}
		return out, contributions[0].scope, nil
	}
	return values[0], contributions[0].scope, nil
}

func toStrings(v any) []string {
	if list, ok := v.([]string); ok {
		return list
	}
	return nil
}

func compareNumeric(a, b any) int {
	af, aok := asFloat64(a)
	bf, bok := asFloat64(b)
	switch {
	case !aok || !bok:
		return 0
	case af < bf:
		return -1
	case af > bf:
		return 1
	default:
		return 0
	}
}

// clampToEnvelope narrows a merged value to fit the compiled envelope and reports every narrowing.
//
// Clamping is what makes the envelope real: without it, a permissive preference from a closer scope
// would win over a restrictive organization policy (INV-9).
func clampToEnvelope(def Definition, value any, env Envelope) (any, []Diagnostic) {
	var diags []Diagnostic
	add := func(scope Scope, msg string) {
		if scope == "" {
			scope = ScopeProductSafety
		}
		diags = append(diags, Diagnostic{
			Key: def.Key, Scope: scope, Severity: SeverityWarning, Code: DiagPolicyClamped, Message: msg,
		})
	}

	switch v := value.(type) {
	case []string:
		out := v
		if len(env.Allowed) > 0 && !containsWildcard(env.Allowed) {
			out = intersectAllowlists([][]string{out, env.Allowed})
			if len(out) != len(v) {
				add(env.AllowedFrom, "entries removed because policy restricts the allowed set")
			}
		}
		if len(env.Denied) > 0 {
			before := len(out)
			out = removeAll(out, env.Denied)
			if len(out) != before {
				add(env.DeniedFrom, "entries removed because policy denies them")
			}
		}
		return out, diags

	case string:
		out := v
		if len(env.Allowed) > 0 && !containsWildcard(env.Allowed) && !containsString(env.Allowed, out) {
			out = mostRestrictiveOf(def, env.Allowed)
			add(env.AllowedFrom, fmt.Sprintf("value %q is not permitted by policy; narrowed to %q", v, out))
		}
		if containsString(env.Denied, out) {
			narrowed := mostRestrictivePermitted(def, env)
			add(env.DeniedFrom, fmt.Sprintf("value %q is denied by policy; narrowed to %q", out, narrowed))
			out = narrowed
		}
		if env.Ceiling != nil {
			ceilIdx, ceilOK := def.restrictiveIndex(env.Ceiling)
			curIdx, curOK := def.restrictiveIndex(out)
			if ceilOK && curOK && curIdx > ceilIdx {
				add(env.CeilingFrom, fmt.Sprintf("value %q exceeds the policy ceiling; narrowed to %v", out, env.Ceiling))
				out, _ = env.Ceiling.(string)
			}
		}
		return out, diags

	case bool:
		out := v
		if env.Ceiling != nil {
			ceilIdx, ceilOK := def.restrictiveIndex(env.Ceiling)
			curIdx, curOK := def.restrictiveIndex(out)
			if ceilOK && curOK && curIdx > ceilIdx {
				add(env.CeilingFrom, fmt.Sprintf("value %t exceeds the policy ceiling; narrowed to %v", out, env.Ceiling))
				out, _ = env.Ceiling.(bool)
			}
		}
		return out, diags

	case int64:
		out := v
		if env.Min != nil && out < *env.Min {
			add(env.MinFrom, fmt.Sprintf("value %d is below the policy minimum; raised to %d", out, *env.Min))
			out = *env.Min
		}
		if env.Max != nil && out > *env.Max {
			add(env.MaxFrom, fmt.Sprintf("value %d exceeds the policy maximum; lowered to %d", out, *env.Max))
			out = *env.Max
		}
		return out, diags

	case float64:
		out := v
		if env.Min != nil && out < float64(*env.Min) {
			add(env.MinFrom, fmt.Sprintf("value %v is below the policy minimum; raised to %d", out, *env.Min))
			out = float64(*env.Min)
		}
		if env.Max != nil && out > float64(*env.Max) {
			add(env.MaxFrom, fmt.Sprintf("value %v exceeds the policy maximum; lowered to %d", out, *env.Max))
			out = float64(*env.Max)
		}
		return out, diags
	}
	return value, diags
}

// mostRestrictiveOf returns the entry in candidates that is earliest in RestrictiveOrder, or the
// first candidate when the setting declares no ordering.
func mostRestrictiveOf(def Definition, candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}
	best, bestIdx := candidates[0], -1
	for _, c := range candidates {
		idx, ok := def.restrictiveIndex(c)
		if !ok {
			continue
		}
		if bestIdx < 0 || idx < bestIdx {
			best, bestIdx = c, idx
		}
	}
	return best
}

// mostRestrictivePermitted returns the tightest value that satisfies both the allowlist and the
// denylist. It fails closed: when nothing satisfies the envelope it returns the empty string rather
// than a permissive value.
func mostRestrictivePermitted(def Definition, env Envelope) string {
	candidates := def.Enum
	if len(env.Allowed) > 0 && !containsWildcard(env.Allowed) {
		candidates = env.Allowed
	}
	permitted := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if !containsString(env.Denied, c) {
			permitted = append(permitted, c)
		}
	}
	return mostRestrictiveOf(def, permitted)
}

func removeAll(values, remove []string) []string {
	denied := make(map[string]struct{}, len(remove))
	for _, v := range remove {
		denied[v] = struct{}{}
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, blocked := denied[v]; blocked {
			continue
		}
		out = append(out, v)
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func errMessage(err error) string {
	var e *modberr.Error
	if modbitErr, ok := modberr.As(err); ok {
		e = modbitErr
		return e.Message()
	}
	return err.Error()
}

func sortDiagnostics(diags []Diagnostic) {
	sort.SliceStable(diags, func(i, j int) bool {
		if diags[i].Key != diags[j].Key {
			return diags[i].Key < diags[j].Key
		}
		return diags[i].Code < diags[j].Code
	})
}
