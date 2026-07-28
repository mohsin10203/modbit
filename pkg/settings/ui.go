package settings

import "strings"

// UI metadata (U1–U6).
//
// PRD §20A.6: a settings surface has to render every key without hardcoding a list, because a
// hardcoded list is one that silently omits the setting added last week. So every definition carries
// presentation metadata, and it is generated from the same contract as everything else rather than
// living in a second document that can disagree about which keys exist.
//
// Most of it is derived. A label, a group, and a widget follow from the key and the type, and
// deriving them means a new setting is renderable the moment it is declared — the alternative is 54
// hand-written labels, of which some fraction is wrong within a release. Only what derivation cannot
// know is declared: whether a setting belongs behind an "advanced" disclosure, and any label a human
// would write differently from the mechanical one.
//
// One test each in ui_test.go. A test without a U-number, or a U-number without a test, is a gap.
//
//	U1 Every definition has renderable metadata; there is no unrenderable setting.
//	U2 Derivation is deterministic: one key and type always give one label, group, and widget.
//	U3 A declared value always wins over a derived one.
//	U4 A widget is compatible with the type it renders.
//	U5 Ordering within a group is total and stable.
//	U6 Security class and change effect reach the surface, so a critical control cannot render as an
//	   ordinary toggle.

// Widget is how a surface should render a setting.
type Widget string

const (
	WidgetToggle Widget = "toggle"
	WidgetSelect Widget = "select"
	WidgetNumber Widget = "number"
	WidgetText   Widget = "text"
	WidgetList   Widget = "list"
	WidgetJSON   Widget = "json"
)

// widgetsForType is the closed set of widgets each type may be rendered with.
//
// U4. A declaration outside this set is refused at generation. A string list rendered as a toggle is
// not a cosmetic mistake: the surface would write a boolean into a setting whose merge strategy is
// `union`, and the resolver would reject it at the worst possible moment.
var widgetsForType = map[Type][]Widget{
	TypeBool:       {WidgetToggle},
	TypeInt:        {WidgetNumber},
	TypeNumber:     {WidgetNumber},
	TypeString:     {WidgetText, WidgetSelect},
	TypeEnum:       {WidgetSelect},
	TypeStringList: {WidgetList},
	TypeObject:     {WidgetJSON},
}

// WidgetAllowed reports whether a widget may render a type.
func WidgetAllowed(t Type, w Widget) bool {
	for _, allowed := range widgetsForType[t] {
		if allowed == w {
			return true
		}
	}
	return false
}

// DefaultWidget returns the widget a type renders with when none is declared.
func DefaultWidget(t Type) Widget {
	if allowed := widgetsForType[t]; len(allowed) > 0 {
		return allowed[0]
	}
	// U1. An unknown type still renders, as raw JSON, rather than disappearing from the surface. A
	// setting a user cannot see is one they cannot audit.
	return WidgetJSON
}

// UI is a definition's presentation metadata.
type UI struct {
	// Label is the human name. Derived from the key's last segment unless declared.
	Label string `json:"label"`
	// Group is the section the setting appears under. Derived from the key's middle segment, or its
	// namespace when the key has only two segments.
	Group string `json:"group"`
	// Order positions the setting within its group. Declaration order in the contract file, which is
	// already a reviewed sequence.
	Order int `json:"order"`
	// Widget is how to render the value.
	Widget Widget `json:"widget"`
	// Advanced marks a setting a basic surface should keep behind a disclosure. Not derivable —
	// whether a control is routine or expert is a product judgement, not a property of its key.
	Advanced bool `json:"advanced,omitempty"`
}

// DeriveLabel turns a key into a human label.
//
// U2. Purely mechanical, so two builds agree: the last dot-segment, underscores to spaces, first
// letter capitalized. Known initialisms are upper-cased because "Cpu limit" and "Dlp mode" read as
// mistakes to the person who has to trust the setting.
func DeriveLabel(k Key) string {
	segments := strings.Split(string(k), ".")
	last := segments[len(segments)-1]
	words := strings.Split(last, "_")
	for i, word := range words {
		if word == "" {
			continue
		}
		if upper, ok := initialisms[word]; ok {
			words[i] = upper
			continue
		}
		if i == 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

// initialisms are the words whose mechanical capitalization reads as a mistake.
var initialisms = map[string]string{
	"api": "API", "cpu": "CPU", "dlp": "DLP", "gpu": "GPU", "id": "ID",
	"ide": "IDE", "mb": "MB", "mcp": "MCP", "sso": "SSO", "ttl": "TTL",
	"ui": "UI", "url": "URL", "vcs": "VCS",
}

// DeriveGroup returns the section a key belongs to.
//
// `agent.approval.duration` groups under "approval"; `agent.default_mode` has no middle segment and
// groups under its namespace. Grouping by the middle segment is what makes a generated surface look
// organized rather than like a flat list of 54 rows.
func DeriveGroup(k Key) string {
	segments := strings.Split(string(k), ".")
	if len(segments) >= 3 {
		return segments[1]
	}
	return segments[0]
}

// Renderable reports whether a definition carries everything a surface needs.
//
// U1. Used by the generator's own tests: a definition that cannot be rendered is one a user cannot
// see, and a setting a user cannot see is one they cannot audit.
func (d Definition) Renderable() bool {
	return d.UI.Label != "" && d.UI.Group != "" && d.UI.Widget != "" &&
		WidgetAllowed(d.Type, d.UI.Widget)
}

// Sensitive reports whether a surface must show this setting's security consequence.
//
// U6. A `critical` or `high` setting rendered as an ordinary toggle tells the user nothing about
// what they are changing. The registry cannot force a surface to render well, but it can refuse to
// let one claim it did not know.
func (d Definition) Sensitive() bool {
	return d.SecurityClass == SecurityCritical || d.SecurityClass == SecurityHigh
}
