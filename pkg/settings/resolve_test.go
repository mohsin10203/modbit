package settings_test

import (
	"errors"
	"testing"

	"github.com/modbit/modbit/pkg/settings"
)

// testRegistry exercises every merge strategy and type without depending on the shipped contracts,
// so a contract edit cannot silently change what these tests assert.
func testRegistry(t *testing.T) *settings.Registry {
	t.Helper()
	max100 := int64(100)
	min0 := int64(0)
	defs := []settings.Definition{
		{
			Key: "t.override", Namespace: "t", SchemaVersion: 1, Type: settings.TypeString,
			Default: "product", Merge: settings.MergeOverride,
			Scopes:       []settings.Scope{settings.ScopeOrganization, settings.ScopeTeam, settings.ScopeUser, settings.ScopeSession},
			ChangeEffect: settings.EffectImmediate, SecurityClass: settings.SecurityLow,
			Description: "override",
		},
		{
			Key: "t.mode", Namespace: "t", SchemaVersion: 1, Type: settings.TypeEnum,
			Enum: []string{"manual", "allowlist", "auto", "unrestricted"}, Default: "auto",
			Merge:            settings.MergeMostRestrictive,
			RestrictiveOrder: []any{"manual", "allowlist", "auto", "unrestricted"},
			Scopes:           []settings.Scope{settings.ScopeOrganization, settings.ScopeTeam, settings.ScopeUser, settings.ScopeSession},
			ChangeEffect:     settings.EffectNextToolCall, SecurityClass: settings.SecurityHigh,
			Description: "mode",
		},
		{
			Key: "t.cap", Namespace: "t", SchemaVersion: 1, Type: settings.TypeInt,
			Default: int64(50), Min: &min0, Max: &max100, Merge: settings.MergeMinimum,
			Scopes:       []settings.Scope{settings.ScopeOrganization, settings.ScopeTeam, settings.ScopeUser},
			ChangeEffect: settings.EffectNextRun, SecurityClass: settings.SecurityMedium,
			Description: "cap",
		},
		{
			Key: "t.floor", Namespace: "t", SchemaVersion: 1, Type: settings.TypeInt,
			Default: int64(1), Merge: settings.MergeMaximum,
			Scopes:       []settings.Scope{settings.ScopeOrganization, settings.ScopeUser},
			ChangeEffect: settings.EffectNextRun, SecurityClass: settings.SecurityMedium,
			Description: "floor",
		},
		{
			Key: "t.allowed", Namespace: "t", SchemaVersion: 1, Type: settings.TypeStringList,
			Default: []string{"*"}, Merge: settings.MergeIntersection,
			Scopes:       []settings.Scope{settings.ScopeOrganization, settings.ScopeTeam, settings.ScopeUser},
			ChangeEffect: settings.EffectNextRun, SecurityClass: settings.SecurityCritical,
			Description: "allowed",
		},
		{
			Key: "t.denied", Namespace: "t", SchemaVersion: 1, Type: settings.TypeStringList,
			Default: []string{}, Merge: settings.MergeUnionDeny,
			Scopes:       []settings.Scope{settings.ScopeOrganization, settings.ScopeTeam, settings.ScopeUser},
			ChangeEffect: settings.EffectNextRun, SecurityClass: settings.SecurityCritical,
			Description: "denied",
		},
		{
			Key: "t.appended", Namespace: "t", SchemaVersion: 1, Type: settings.TypeStringList,
			Default: []string{"base"}, Merge: settings.MergeAppendUnique,
			Scopes:       []settings.Scope{settings.ScopeOrganization, settings.ScopeUser, settings.ScopeSession},
			ChangeEffect: settings.EffectNextRun, SecurityClass: settings.SecurityLow,
			Description: "appended",
		},
		{
			Key: "t.object", Namespace: "t", SchemaVersion: 1, Type: settings.TypeObject,
			Default:      map[string]any{"a": "default", "nested": map[string]any{"x": "default"}},
			Merge:        settings.MergeDeepMerge,
			Scopes:       []settings.Scope{settings.ScopeOrganization, settings.ScopeUser},
			ChangeEffect: settings.EffectNextRun, SecurityClass: settings.SecurityLow,
			Description: "object",
		},
		{
			Key: "t.flag", Namespace: "t", SchemaVersion: 1, Type: settings.TypeBool,
			Default: true, Merge: settings.MergeMostRestrictive, RestrictiveOrder: []any{true, false},
			Scopes:       []settings.Scope{settings.ScopeOrganization, settings.ScopeUser},
			ChangeEffect: settings.EffectImmediate, SecurityClass: settings.SecurityHigh,
			Description: "flag",
		},
	}
	r, err := settings.NewRegistry(defs, nil)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func resolve(t *testing.T, r *settings.Registry, layers ...settings.Layer) settings.Result {
	t.Helper()
	resolver, err := settings.NewResolver(r)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	res, err := resolver.Resolve(layers)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res
}

func mustValue(t *testing.T, res settings.Result, key settings.Key) any {
	t.Helper()
	v, ok := res.Value(key)
	if !ok {
		t.Fatalf("no resolution for %q", key)
	}
	return v
}

func TestProductDefaultAppliesWhenNoLayerSuppliesAValue(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r)

	if got := mustValue(t, res, "t.override"); got != "product" {
		t.Errorf("value = %v, want product", got)
	}
	if src := res.Resolutions["t.override"].Source; src != settings.ScopeProductDefault {
		t.Errorf("source = %q, want product_default", src)
	}
}

func TestClosestPreferenceWinsForOverride(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeOrganization, SourceID: "org", Values: map[settings.Key]any{"t.override": "org"}},
		settings.Layer{Scope: settings.ScopeUser, SourceID: "usr", Values: map[settings.Key]any{"t.override": "user"}},
		settings.Layer{Scope: settings.ScopeSession, SourceID: "ses", Values: map[settings.Key]any{"t.override": "session"}},
	)
	if got := mustValue(t, res, "t.override"); got != "session" {
		t.Errorf("value = %v, want session (closest preference wins)", got)
	}
	if src := res.Resolutions["t.override"].Source; src != settings.ScopeSession {
		t.Errorf("source = %q, want session", src)
	}
}

// Layer order must not change the outcome; the resolver sorts by preference rank itself.
func TestLayerOrderDoesNotAffectResolution(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	org := settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.override": "org"}}
	user := settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.override": "user"}}

	forward := resolve(t, r, org, user)
	reverse := resolve(t, r, user, org)

	if mustValue(t, forward, "t.override") != mustValue(t, reverse, "t.override") {
		t.Fatalf("resolution depends on layer order: %v vs %v",
			mustValue(t, forward, "t.override"), mustValue(t, reverse, "t.override"))
	}
}

// The core INV-9 property, tested one strategy at a time: a closer, more permissive scope must
// never widen what a higher scope allowed.
func TestLowerScopeCannotWeakenHigherScope(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)

	t.Run("most_restrictive keeps the tightest enum", func(t *testing.T) {
		res := resolve(t, r,
			settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.mode": "allowlist"}},
			settings.Layer{Scope: settings.ScopeSession, Values: map[settings.Key]any{"t.mode": "unrestricted"}},
		)
		if got := mustValue(t, res, "t.mode"); got != "allowlist" {
			t.Errorf("value = %v, want allowlist", got)
		}
	})

	t.Run("minimum keeps the lowest cap", func(t *testing.T) {
		res := resolve(t, r,
			settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.cap": 10}},
			settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.cap": 90}},
		)
		if got := mustValue(t, res, "t.cap"); got != int64(10) {
			t.Errorf("value = %v, want 10", got)
		}
	})

	t.Run("intersection cannot be widened", func(t *testing.T) {
		res := resolve(t, r,
			settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.allowed": []any{"a", "b"}}},
			settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.allowed": []any{"a", "b", "c"}}},
		)
		got := mustValue(t, res, "t.allowed").([]string)
		if len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Errorf("value = %v, want [a b]", got)
		}
	})

	t.Run("union_deny accumulates denials", func(t *testing.T) {
		res := resolve(t, r,
			settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.denied": []any{"x"}}},
			settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.denied": []any{"y"}}},
		)
		got := mustValue(t, res, "t.denied").([]string)
		if len(got) != 2 || got[0] != "x" || got[1] != "y" {
			t.Errorf("value = %v, want [x y]", got)
		}
	})

	t.Run("most_restrictive bool cannot be re-enabled", func(t *testing.T) {
		res := resolve(t, r,
			settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.flag": false}},
			settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.flag": true}},
		)
		// RestrictiveOrder is [true, false], so true is the tighter value here; the organization's
		// false is the *looser* one and the user's true legitimately wins.
		if got := mustValue(t, res, "t.flag"); got != true {
			t.Errorf("value = %v, want true (the more restrictive value)", got)
		}
	})
}

func TestPolicyLockOverridesEveryPreference(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{
			Scope:       settings.ScopeOrganization,
			Constraints: map[settings.Key]settings.Constraint{"t.override": {Lock: true, Value: "locked"}},
		},
		settings.Layer{Scope: settings.ScopeSession, Values: map[settings.Key]any{"t.override": "session"}},
	)
	resolution := res.Resolutions["t.override"]
	if resolution.Value != "locked" {
		t.Errorf("value = %v, want locked", resolution.Value)
	}
	if !resolution.Locked || resolution.LockedBy != settings.ScopeOrganization {
		t.Errorf("locked = %t by %q, want true by organization", resolution.Locked, resolution.LockedBy)
	}
	if !hasDiagnostic(resolution.Diagnostics, settings.DiagLockedOverrideIgnored) {
		t.Errorf("expected a locked_override_ignored diagnostic, got %v", resolution.Diagnostics)
	}
}

func TestPolicyCeilingClampsAPermissivePreference(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{
			Scope:       settings.ScopeOrganization,
			Constraints: map[settings.Key]settings.Constraint{"t.mode": {Ceiling: "allowlist"}},
		},
		settings.Layer{Scope: settings.ScopeSession, Values: map[settings.Key]any{"t.mode": "unrestricted"}},
	)
	resolution := res.Resolutions["t.mode"]
	if resolution.Value != "allowlist" {
		t.Errorf("value = %v, want allowlist", resolution.Value)
	}
	if !hasDiagnostic(resolution.Diagnostics, settings.DiagPolicyClamped) {
		t.Errorf("expected a policy_clamped diagnostic, got %v", resolution.Diagnostics)
	}
}

func TestTightestConstraintWinsAcrossPolicyScopes(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	orgMax, teamMax := int64(80), int64(20)
	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeOrganization, Constraints: map[settings.Key]settings.Constraint{"t.cap": {Max: &orgMax}}},
		settings.Layer{Scope: settings.ScopeTeam, Constraints: map[settings.Key]settings.Constraint{"t.cap": {Max: &teamMax}}},
		settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.cap": 75}},
	)
	if got := mustValue(t, res, "t.cap"); got != int64(20) {
		t.Errorf("value = %v, want 20 (the tightest maximum)", got)
	}
}

func TestNonPolicyScopeCannotPublishConstraints(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{
			Scope:       settings.ScopeUser,
			Constraints: map[settings.Key]settings.Constraint{"t.override": {Lock: true, Value: "hijacked"}},
		},
	)
	resolution := res.Resolutions["t.override"]
	if resolution.Locked {
		t.Error("a user scope must not be able to lock a setting")
	}
	if resolution.Value != "product" {
		t.Errorf("value = %v, want the product default", resolution.Value)
	}
	if !hasDiagnostic(resolution.Diagnostics, settings.DiagConstraintIgnored) {
		t.Errorf("expected a constraint_ignored diagnostic, got %v", resolution.Diagnostics)
	}
}

// SET-1: an unknown key survives a round trip and is reported rather than deleted.
func TestUnknownKeysArePreservedAndReported(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.from_a_newer_version": "keep me"}},
	)
	preserved, ok := res.Unknown[settings.ScopeUser]["t.from_a_newer_version"]
	if !ok || preserved != "keep me" {
		t.Fatalf("unknown value was not preserved: %v", res.Unknown)
	}
	if !hasDiagnostic(res.Diagnostics, settings.DiagUnknownKey) {
		t.Errorf("expected an unknown_setting diagnostic, got %v", res.Diagnostics)
	}
}

// SET-2: an invalid value is diagnosed and the next-closest preference applies. It never silently
// becomes the default.
func TestInvalidValueIsDiagnosedAndFallsThroughVisibly(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.mode": "not-a-mode"}},
		settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.mode": "manual"}},
	)
	resolution := res.Resolutions["t.mode"]
	if resolution.Value != "manual" {
		t.Errorf("value = %v, want manual", resolution.Value)
	}
	if !hasDiagnostic(resolution.Diagnostics, settings.DiagInvalidValue) {
		t.Fatalf("expected an invalid_value diagnostic, got %v", resolution.Diagnostics)
	}
	if !resolution.HasErrors() {
		t.Error("an invalid value must produce an error-severity diagnostic")
	}
}

func TestValueAuthoredAtADisallowedScopeIsRejected(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		// t.floor does not list team among its scopes.
		settings.Layer{Scope: settings.ScopeTeam, Values: map[settings.Key]any{"t.floor": 99}},
	)
	resolution := res.Resolutions["t.floor"]
	if resolution.Value != int64(1) {
		t.Errorf("value = %v, want the product default 1", resolution.Value)
	}
	if !hasDiagnostic(resolution.Diagnostics, settings.DiagScopeNotPermitted) {
		t.Errorf("expected a scope_not_permitted diagnostic, got %v", resolution.Diagnostics)
	}
}

func TestAppendUniquePreservesPrecedenceOrderAndDropsDuplicates(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.appended": []any{"org", "shared"}}},
		settings.Layer{Scope: settings.ScopeSession, Values: map[settings.Key]any{"t.appended": []any{"session", "shared"}}},
	)
	got := mustValue(t, res, "t.appended").([]string)
	want := []string{"session", "shared", "org", "base"}
	if len(got) != len(want) {
		t.Fatalf("value = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("value = %v, want %v", got, want)
		}
	}
}

func TestDeepMergeLetsTheClosestScopeWinPerLeaf(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{
			"t.object": map[string]any{"a": "org", "b": "org-only", "nested": map[string]any{"x": "org", "y": "org"}},
		}},
		settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{
			"t.object": map[string]any{"a": "user", "nested": map[string]any{"x": "user"}},
		}},
	)
	got := mustValue(t, res, "t.object").(map[string]any)
	if got["a"] != "user" {
		t.Errorf("a = %v, want user", got["a"])
	}
	if got["b"] != "org-only" {
		t.Errorf("b = %v, want org-only (lower scope keys survive)", got["b"])
	}
	nested := got["nested"].(map[string]any)
	if nested["x"] != "user" || nested["y"] != "org" {
		t.Errorf("nested = %v, want x=user y=org", nested)
	}
}

func TestSourceMapExplainsEveryContribution(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeOrganization, SourceID: "setdoc_org", Values: map[settings.Key]any{"t.override": "org"}},
		settings.Layer{Scope: settings.ScopeUser, SourceID: "setdoc_usr", Values: map[settings.Key]any{"t.override": "user"}},
	)
	sourceMap := res.Resolutions["t.override"].SourceMap
	if len(sourceMap) != 2 {
		t.Fatalf("source map has %d entries, want 2: %+v", len(sourceMap), sourceMap)
	}
	if sourceMap[0].Scope != settings.ScopeUser || !sourceMap[0].Applied {
		t.Errorf("highest-precedence contribution = %+v, want applied user", sourceMap[0])
	}
	if sourceMap[1].Scope != settings.ScopeOrganization || sourceMap[1].Applied {
		t.Errorf("outranked contribution = %+v, want unapplied organization", sourceMap[1])
	}
	if sourceMap[1].SourceID != "setdoc_org" {
		t.Errorf("source id = %q, want setdoc_org", sourceMap[1].SourceID)
	}
}

func TestChangeEffectIsReported(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r)
	if got := res.Resolutions["t.mode"].ChangeEffect; got != settings.EffectNextToolCall {
		t.Errorf("change effect = %q, want next_tool_call", got)
	}
}

func TestDuplicateLayerScopeIsRejected(t *testing.T) {
	t.Parallel()
	resolver, err := settings.NewResolver(testRegistry(t))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	_, err = resolver.Resolve([]settings.Layer{
		{Scope: settings.ScopeUser},
		{Scope: settings.ScopeUser},
	})
	if err == nil {
		t.Fatal("expected an error for duplicate layer scopes")
	}
}

func hasDiagnostic(diags []settings.Diagnostic, code string) bool {
	for _, d := range diags {
		if d.Code == code {
			return true
		}
	}
	return false
}

// The product default is a fallback for selective strategies, not a hard bound. Treating it as a
// bound would make a shipped default unreachable from above: an organization could never raise a
// cap, and a mode whose default is mid-ladder could never be loosened by anyone. Hard bounds come
// from policy constraints instead.
func TestProductDefaultDoesNotBoundSelectiveStrategies(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)

	t.Run("most_restrictive can be loosened past the default", func(t *testing.T) {
		// Default is "auto"; "unrestricted" is looser and must be reachable.
		res := resolve(t, r,
			settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.mode": "unrestricted"}},
		)
		if got := mustValue(t, res, "t.mode"); got != "unrestricted" {
			t.Errorf("value = %v, want unrestricted", got)
		}
	})

	t.Run("minimum can be raised past the default", func(t *testing.T) {
		// Default cap is 50; an organization raising it to 90 must take effect.
		res := resolve(t, r,
			settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.cap": 90}},
		)
		if got := mustValue(t, res, "t.cap"); got != int64(90) {
			t.Errorf("value = %v, want 90", got)
		}
	})

	t.Run("intersection can name entries outside the default", func(t *testing.T) {
		res := resolve(t, r,
			settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.allowed": []any{"d", "e"}}},
		)
		got := mustValue(t, res, "t.allowed").([]string)
		if len(got) != 2 || got[0] != "d" || got[1] != "e" {
			t.Errorf("value = %v, want [d e]", got)
		}
	})

	t.Run("a policy constraint still bounds the value", func(t *testing.T) {
		max := int64(60)
		res := resolve(t, r,
			settings.Layer{Scope: settings.ScopeOrganization, Constraints: map[settings.Key]settings.Constraint{"t.cap": {Max: &max}}},
			settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.cap": 90}},
		)
		if got := mustValue(t, res, "t.cap"); got != int64(60) {
			t.Errorf("value = %v, want 60 (clamped by policy)", got)
		}
	})
}

// Additive strategies keep the default as a baseline: a repository adding one protected path must
// not drop the shipped protections.
func TestProductDefaultSurvivesAdditiveStrategies(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)

	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeOrganization, Values: map[settings.Key]any{"t.denied": []any{"extra"}}},
	)
	// t.denied's default is empty, so assert on the append_unique setting whose default is not.
	if got := mustValue(t, res, "t.denied").([]string); len(got) != 1 || got[0] != "extra" {
		t.Errorf("denied = %v, want [extra]", got)
	}

	res = resolve(t, r,
		settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.appended": []any{"mine"}}},
	)
	got := mustValue(t, res, "t.appended").([]string)
	if len(got) != 2 || got[0] != "mine" || got[1] != "base" {
		t.Errorf("appended = %v, want [mine base] (the default baseline survives)", got)
	}
}

func TestSnapshotIsContentAddressedAndVerifiable(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	layers := []settings.Layer{
		{Scope: settings.ScopeOrganization, SourceID: "org", Values: map[settings.Key]any{"t.mode": "manual"}},
	}
	resolver, err := settings.NewResolver(r)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	first, err := resolver.Resolve(layers)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	second, err := resolver.Resolve(layers)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	a, err := settings.NewSnapshot(first, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	b, err := settings.NewSnapshot(second, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}

	if a.ID == b.ID {
		t.Error("each snapshot must have its own identifier")
	}
	if a.Digest != b.Digest {
		t.Errorf("identical effective settings must share a digest: %s vs %s", a.Digest, b.Digest)
	}
	if err := a.Verify(); err != nil {
		t.Errorf("Verify on an intact snapshot: %v", err)
	}

	// Tampering with a value must be detectable, which is what lets a worker trust the settings a
	// lease was signed for.
	a.Values["t.mode"] = "unrestricted"
	if err := a.Verify(); err == nil {
		t.Error("Verify must fail after the values are altered")
	}
}

func TestSnapshotAccessorsDistinguishUnsetFromFalse(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r)
	snap, err := settings.NewSnapshot(res, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}

	if _, err := snap.Bool("t.not.registered"); err == nil {
		t.Error("an absent key must report an error, not false")
	}
	if _, err := snap.Bool("t.mode"); err == nil {
		t.Error("reading an enum as a bool must report an error")
	}
	if got, err := snap.String("t.mode"); err != nil || got != "auto" {
		t.Errorf("String = %q (%v), want auto", got, err)
	}
	if got, err := snap.Int("t.cap"); err != nil || got != 50 {
		t.Errorf("Int = %d (%v), want 50", got, err)
	}
}

// A merge strategy that cannot operate on the declared type must be rejected when the Registry is
// built. modbitgen rejects these in contract files, but a plugin registering a namespaced schema
// (SET-6) does not pass through the generator, and reaching the merge switch with a mismatched pair
// used to fail a type assertion — a panic on a request path (R-GO-08).
func TestRegistryRejectsIncompatibleMergeAndType(t *testing.T) {
	t.Parallel()
	base := settings.Definition{
		Key: "t.x", Namespace: "t", SchemaVersion: 1, Default: "value",
		Scopes: []settings.Scope{settings.ScopeUser}, ChangeEffect: settings.EffectImmediate,
		SecurityClass: settings.SecurityLow, Description: "x",
	}
	tests := []struct {
		name string
		typ  settings.Type
		def  any
		mrg  settings.MergeStrategy
	}{
		{"list strategy on a string", settings.TypeString, "value", settings.MergeUnion},
		{"deny strategy on a string", settings.TypeString, "value", settings.MergeUnionDeny},
		{"intersection on a bool", settings.TypeBool, true, settings.MergeIntersection},
		{"numeric strategy on a string", settings.TypeString, "value", settings.MergeMinimum},
		{"deep merge on a list", settings.TypeStringList, []string{}, settings.MergeDeepMerge},
		{"most_restrictive on an object", settings.TypeObject, map[string]any{}, settings.MergeMostRestrictive},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := base
			d.Type, d.Default, d.Merge = tc.typ, tc.def, tc.mrg
			if d.Merge == settings.MergeMostRestrictive {
				d.RestrictiveOrder = []any{"a", "b"}
			}
			if _, err := settings.NewRegistry([]settings.Definition{d}, nil); err == nil {
				t.Fatalf("NewRegistry accepted %s on %s", tc.mrg, tc.typ)
			}
		})
	}
}

// A clamp diagnostic must name the scope whose policy caused it. "Narrowed by policy" with no
// attribution is unactionable for whoever reads it.
func TestClampDiagnosticsNameTheResponsibleScope(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	orgMax, teamMax := int64(80), int64(20)

	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeOrganization, Constraints: map[settings.Key]settings.Constraint{"t.cap": {Max: &orgMax}}},
		settings.Layer{Scope: settings.ScopeTeam, Constraints: map[settings.Key]settings.Constraint{"t.cap": {Max: &teamMax}}},
		settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.cap": 75}},
	)
	resolution := res.Resolutions["t.cap"]
	if resolution.Value != int64(20) {
		t.Fatalf("value = %v, want 20", resolution.Value)
	}
	var clamp *settings.Diagnostic
	for i := range resolution.Diagnostics {
		if resolution.Diagnostics[i].Code == settings.DiagPolicyClamped {
			clamp = &resolution.Diagnostics[i]
		}
	}
	if clamp == nil {
		t.Fatalf("no policy_clamped diagnostic: %v", resolution.Diagnostics)
	}
	if clamp.Scope != settings.ScopeTeam {
		t.Errorf("diagnostic blames %q, want team (the scope with the tightest maximum)", clamp.Scope)
	}
	if resolution.Source != settings.ScopeTeam {
		t.Errorf("source = %q, want team", resolution.Source)
	}
}

func TestCeilingClampNamesTheResponsibleScope(t *testing.T) {
	t.Parallel()
	r := testRegistry(t)
	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeTeam, Constraints: map[settings.Key]settings.Constraint{"t.mode": {Ceiling: "allowlist"}}},
		settings.Layer{Scope: settings.ScopeSession, Values: map[settings.Key]any{"t.mode": "unrestricted"}},
	)
	for _, d := range res.Resolutions["t.mode"].Diagnostics {
		if d.Code == settings.DiagPolicyClamped && d.Scope != settings.ScopeTeam {
			t.Errorf("ceiling clamp blames %q, want team", d.Scope)
		}
	}
}

type failingMerger struct{}

func (failingMerger) Merge(settings.Definition, []any) (any, error) {
	return nil, errors.New("merger unavailable")
}

// SET-2: a failed custom merge falls back to the product default, but never silently.
func TestCustomMergerFailureIsDiagnosed(t *testing.T) {
	t.Parallel()
	def := settings.Definition{
		Key: "t.custom", Namespace: "t", SchemaVersion: 1, Type: settings.TypeString,
		Default: "product", Merge: settings.MergeCustom,
		Scopes: []settings.Scope{settings.ScopeUser}, ChangeEffect: settings.EffectImmediate,
		SecurityClass: settings.SecurityLow, Description: "custom",
	}
	r, err := settings.NewRegistry([]settings.Definition{def},
		map[settings.Key]settings.Merger{"t.custom": failingMerger{}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	res := resolve(t, r,
		settings.Layer{Scope: settings.ScopeUser, Values: map[settings.Key]any{"t.custom": "mine"}},
	)
	resolution := res.Resolutions["t.custom"]
	if resolution.Value != "product" {
		t.Errorf("value = %v, want the product default", resolution.Value)
	}
	if !hasDiagnostic(resolution.Diagnostics, settings.DiagCustomMergeFailed) {
		t.Fatalf("expected a custom_merge_failed diagnostic, got %v", resolution.Diagnostics)
	}
	if !resolution.HasErrors() {
		t.Error("a failed custom merge must be an error-severity diagnostic")
	}
}

// A custom strategy with no registered merger must be refused at construction rather than
// discovered at resolution time.
func TestCustomMergeWithoutAMergerIsRejected(t *testing.T) {
	t.Parallel()
	def := settings.Definition{
		Key: "t.custom", Namespace: "t", SchemaVersion: 1, Type: settings.TypeString,
		Default: "product", Merge: settings.MergeCustom,
		Scopes: []settings.Scope{settings.ScopeUser}, ChangeEffect: settings.EffectImmediate,
		SecurityClass: settings.SecurityLow, Description: "custom",
	}
	if _, err := settings.NewRegistry([]settings.Definition{def}, nil); err == nil {
		t.Fatal("expected NewRegistry to reject merge custom with no registered Merger")
	}
}
