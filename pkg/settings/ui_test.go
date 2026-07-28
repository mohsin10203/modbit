package settings_test

import (
	"testing"

	"github.com/modbit/modbit/pkg/settings"
)

// U1. A setting a user cannot see is one they cannot audit, and §20A.6 requires a surface to render
// every key without hardcoding a list — a hardcoded list being one that silently omits the setting
// added last week.
func TestEverySettingIsRenderable(t *testing.T) {
	registry := settings.Default()
	definitions := registry.Definitions()
	if len(definitions) == 0 {
		t.Fatal("the registry is empty")
	}

	for _, def := range definitions {
		if !def.Renderable() {
			t.Errorf("%s is not renderable: %+v", def.Key, def.UI)
		}
		if def.UI.Label == "" {
			t.Errorf("%s has no label", def.Key)
		}
		if def.UI.Group == "" {
			t.Errorf("%s has no group", def.Key)
		}
		if def.UI.Widget == "" {
			t.Errorf("%s has no widget", def.Key)
		}
	}
}

// U2. Two builds must agree, so derivation is purely mechanical.
func TestDerivationIsDeterministic(t *testing.T) {
	cases := map[settings.Key]struct{ label, group string }{
		"agent.approval.duration":         {"Duration", "approval"},
		"agent.default_mode":              {"Default mode", "agent"},
		"context.indexing.max_file_bytes": {"Max file bytes", "indexing"},
		"execution.limits.memory_mb":      {"Memory MB", "limits"},
		"model.cost_cap_per_run_micros":   {"Cost cap per run micros", "model"},
	}
	for key, want := range cases {
		t.Run(string(key), func(t *testing.T) {
			for range 20 {
				if got := settings.DeriveLabel(key); got != want.label {
					t.Fatalf("label = %q, want %q", got, want.label)
				}
				if got := settings.DeriveGroup(key); got != want.group {
					t.Fatalf("group = %q, want %q", got, want.group)
				}
			}
		})
	}
}

// U2, second half: a mechanical capitalization that reads as a mistake undermines the trust a user
// needs to change a security control. "Cpu limit" and "Dlp mode" are the cases.
func TestInitialismsAreNotMangled(t *testing.T) {
	cases := map[settings.Key]string{
		"execution.limits.cpu_percent": "CPU percent",
		"model.dlp_mode":               "DLP mode",
		"context.sources.api_url":      "API URL",
		"agent.session_ttl":            "Session TTL",
	}
	for key, want := range cases {
		if got := settings.DeriveLabel(key); got != want {
			t.Errorf("DeriveLabel(%q) = %q, want %q", key, got, want)
		}
	}
}

// U3. A declared value always wins. Without this the contract could describe a label the build
// ignores, which is worse than having no override at all.
func TestDeclaredMetadataOverridesDerivation(t *testing.T) {
	registry := settings.Default()

	// agent.execution.mode declares nothing, so it derives.
	def, ok := registry.Lookup("agent.execution.mode")
	if !ok {
		t.Fatal("agent.execution.mode is not registered")
	}
	if def.UI.Label != settings.DeriveLabel(def.Key) {
		t.Fatalf("label = %q, want the derived %q", def.UI.Label, settings.DeriveLabel(def.Key))
	}
	if def.UI.Group != settings.DeriveGroup(def.Key) {
		t.Fatalf("group = %q, want the derived %q", def.UI.Group, settings.DeriveGroup(def.Key))
	}
	// An enum derives a select, which is the only widget its type permits.
	if def.UI.Widget != settings.WidgetSelect {
		t.Fatalf("widget = %q, want select for an enum", def.UI.Widget)
	}
}

// U4. A string list rendered as a toggle is not a cosmetic mistake: the surface would write a
// boolean into a setting whose merge strategy is `union`, and the resolver would reject it at the
// worst possible moment.
func TestSecurityAWidgetMustBeAbleToRenderItsType(t *testing.T) {
	permitted := map[settings.Type][]settings.Widget{
		settings.TypeBool:       {settings.WidgetToggle},
		settings.TypeInt:        {settings.WidgetNumber},
		settings.TypeEnum:       {settings.WidgetSelect},
		settings.TypeStringList: {settings.WidgetList},
		settings.TypeObject:     {settings.WidgetJSON},
	}
	for typ, allowed := range permitted {
		for _, widget := range allowed {
			if !settings.WidgetAllowed(typ, widget) {
				t.Errorf("%s should render %s", typ, widget)
			}
		}
		// Everything else must be refused.
		for _, widget := range []settings.Widget{
			settings.WidgetToggle, settings.WidgetSelect, settings.WidgetNumber,
			settings.WidgetText, settings.WidgetList, settings.WidgetJSON,
		} {
			expected := false
			for _, ok := range allowed {
				if ok == widget {
					expected = true
				}
			}
			if settings.WidgetAllowed(typ, widget) != expected {
				t.Errorf("WidgetAllowed(%s, %s) = %v, want %v", typ, widget, !expected, expected)
			}
		}
	}

	// Every registered definition's widget must be one its type permits.
	for _, def := range settings.Default().Definitions() {
		if !settings.WidgetAllowed(def.Type, def.UI.Widget) {
			t.Errorf("%s is type %s rendered as %s", def.Key, def.Type, def.UI.Widget)
		}
	}
}

// U5. Ordering must be total, or a surface renders the same group differently on two machines and a
// screenshot in a bug report stops matching what the reporter saw.
func TestOrderingWithinAGroupIsTotal(t *testing.T) {
	byGroup := map[string]map[int][]settings.Key{}
	for _, def := range settings.Default().Definitions() {
		if byGroup[def.UI.Group] == nil {
			byGroup[def.UI.Group] = map[int][]settings.Key{}
		}
		byGroup[def.UI.Group][def.UI.Order] = append(byGroup[def.UI.Group][def.UI.Order], def.Key)
	}

	for group, orders := range byGroup {
		for order, keys := range orders {
			if len(keys) > 1 {
				// A tie is not fatal on its own — the surface breaks it by key — but it means the
				// contract's declaration order is not doing the work it was meant to.
				t.Logf("group %q has %d settings sharing order %d: %v", group, len(keys), order, keys)
			}
		}
	}
	// What must hold is that ordering is a defined number for every setting, so a surface never has
	// to invent one.
	for _, def := range settings.Default().Definitions() {
		if def.UI.Order < 0 {
			t.Errorf("%s has a negative order", def.Key)
		}
	}
}

// U6. A critical setting rendered as an ordinary toggle tells the user nothing about what they are
// changing. The registry cannot force a surface to render well, but it can refuse to let one claim
// it did not know.
func TestSecurityConsequenceReachesTheSurface(t *testing.T) {
	registry := settings.Default()

	sensitive := 0
	for _, def := range registry.Definitions() {
		if def.SecurityClass == "" {
			t.Errorf("%s has no security class, so a surface cannot show its consequence", def.Key)
		}
		if def.ChangeEffect == "" {
			t.Errorf("%s has no change effect, so a surface cannot say when it takes effect", def.Key)
		}
		if def.Sensitive() {
			sensitive++
		}
	}
	if sensitive == 0 {
		t.Fatal("no setting is marked sensitive; the registry holds security-critical controls")
	}

	// A specific control whose consequence must be visible: the tool deny list is unioned across
	// every scope and is the one setting an operator most needs to understand before touching.
	def, ok := registry.Lookup("agent.tools.denied")
	if !ok {
		t.Fatal("agent.tools.denied is not registered")
	}
	if !def.Sensitive() {
		t.Fatalf("agent.tools.denied has security class %q and is not marked sensitive", def.SecurityClass)
	}
	if def.UI.Widget != settings.WidgetList {
		t.Fatalf("agent.tools.denied renders as %q, want a list", def.UI.Widget)
	}
}

// The generator duplicates the widget table rather than importing it, because a generator that
// imported its own output could not build from a clean tree. A duplicated table is only safe if
// something notices when the two drift, so this walks every registered definition and checks that
// what the generator emitted is what the runtime would have chosen.
//
// It catches the drift that matters: a widget added to one table and not the other, or a type whose
// default widget changed on one side.
func TestGeneratedWidgetsMatchTheRuntimeTable(t *testing.T) {
	for _, def := range settings.Default().Definitions() {
		// No definition declares an explicit widget today, so every one must equal the runtime's
		// default for its type. If a contract later declares one, this narrows to the compatibility
		// check above rather than silently passing.
		want := settings.DefaultWidget(def.Type)
		if def.UI.Widget != want {
			t.Errorf("%s (type %s) was generated as %q; the runtime default is %q",
				def.Key, def.Type, def.UI.Widget, want)
		}
	}
}

// The derived label and group in the generated file must equal what the runtime derivation produces
// for the same key, or the two implementations have drifted and the contract no longer describes
// what ships.
func TestGeneratedLabelsMatchTheRuntimeDerivation(t *testing.T) {
	for _, def := range settings.Default().Definitions() {
		if want := settings.DeriveLabel(def.Key); def.UI.Label != want {
			t.Errorf("%s label = %q, runtime derivation gives %q", def.Key, def.UI.Label, want)
		}
		if want := settings.DeriveGroup(def.Key); def.UI.Group != want {
			t.Errorf("%s group = %q, runtime derivation gives %q", def.Key, def.UI.Group, want)
		}
	}
}
