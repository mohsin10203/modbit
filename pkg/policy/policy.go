// Package policy evaluates whether a tool operation may proceed, and under what approval class.
//
// Boundary: the side-effect taxonomy, the approval ladder, and the decision function that combines
// settings, taint state, and plan declarations. It does not store decisions, request approvals, or
// execute anything; the Approval service and the worker do that. It reads a frozen settings
// snapshot and never mutates one.
//
// Requirements: PRD v5.1 §12.2 (SFX-1..SFX-5), §12A (TNT-3, TNT-4), §18.3 (approval requirements);
// rules.md INV-7 (every mutating tool call is policy evaluated and classified), R-SEC-04..06.
package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/settings"
	"github.com/modbit/modbit/pkg/taint"
)

// SideEffectClass is the declared blast radius of an operation (PRD §12.2).
//
// SFX-1 requires every tool operation to declare its class before execution. The zero value is
// deliberately invalid so that an undeclared operation cannot be evaluated as harmless.
type SideEffectClass uint8

const (
	// SideEffectUndeclared is the zero value. Evaluating it is an error, not a permissive default.
	SideEffectUndeclared SideEffectClass = iota
	// PureReadOnly covers search and file reads. Allowed under workspace policy.
	PureReadOnly
	// WorkspaceReversible covers file edits inside a worktree. Snapshot and allow.
	WorkspaceReversible
	// LocallyDestructive covers deleting generated data or resetting a branch. Approval and backup.
	LocallyDestructive
	// ExternallyCompensatable covers creating an issue or posting a comment. Policy plus
	// compensation metadata — never described as guaranteed rollback (INV-15, SFX-5).
	ExternallyCompensatable
	// ExternallyIrreversible covers publishing a package or deleting a cloud resource. Strong
	// approval and a constrained profile.
	ExternallyIrreversible
)

var sideEffectNames = map[SideEffectClass]string{
	SideEffectUndeclared:    "undeclared",
	PureReadOnly:            "pure_read_only",
	WorkspaceReversible:     "workspace_reversible",
	LocallyDestructive:      "locally_destructive",
	ExternallyCompensatable: "externally_compensatable",
	ExternallyIrreversible:  "externally_irreversible",
}

var sideEffectByName = func() map[string]SideEffectClass {
	out := make(map[string]SideEffectClass, len(sideEffectNames))
	for c, n := range sideEffectNames {
		out[n] = c
	}
	return out
}()

// String returns the canonical name.
func (c SideEffectClass) String() string {
	if n, ok := sideEffectNames[c]; ok {
		return n
	}
	return "undeclared"
}

// Declared reports whether c is a real class rather than the zero value.
func (c SideEffectClass) Declared() bool {
	return c != SideEffectUndeclared && sideEffectNames[c] != ""
}

// External reports whether the operation reaches outside the workspace.
func (c SideEffectClass) External() bool {
	return c == ExternallyCompensatable || c == ExternallyIrreversible
}

// ParseSideEffectClass resolves a class name. An unknown name is an error rather than a default,
// because guessing a side-effect class is exactly the mistake SFX-1 exists to prevent.
func ParseSideEffectClass(name string) (SideEffectClass, error) {
	if c, ok := sideEffectByName[strings.ToLower(strings.TrimSpace(name))]; ok && c.Declared() {
		return c, nil
	}
	return SideEffectUndeclared, modberr.Newf(modberr.CodeInvalidArgument,
		"unrecognized side-effect class %q", name).WithDetail("field", "side_effect_class")
}

// ApprovalClass is the human authorization required before an operation may run. Values ascend in
// strictness so that escalation is an increment.
//
// The ladder has exactly three rungs, and deliberately does not include a "notify" rung. TNT-4
// escalates by one class, so every rung must be a materially stronger gate than the one below it.
// A notify rung would let an escalation resolve to "run it anyway, but mention it" — under
// unrestricted mode an externally compensatable operation sits at ApprovalNone, and escalating it
// into a non-gating class would make taint confinement decorative exactly where it matters most.
// Completion and activity notifications are a separate concern in the agent.* namespace.
type ApprovalClass uint8

const (
	// ApprovalNone permits the operation without human interaction. It still produces an audit
	// record; "no approval" is not "no trace".
	ApprovalNone ApprovalClass = iota
	// ApprovalSingle requires one human approver.
	ApprovalSingle
	// ApprovalTwoPerson requires two distinct human approvers.
	ApprovalTwoPerson
)

var approvalNames = map[ApprovalClass]string{
	ApprovalNone:      "none",
	ApprovalSingle:    "single_approver",
	ApprovalTwoPerson: "two_person",
}

// String returns the canonical name.
func (a ApprovalClass) String() string {
	if n, ok := approvalNames[a]; ok {
		return n
	}
	return "two_person" // an unnameable class fails closed to the strictest
}

// escalate returns the next stricter class, saturating at the top of the ladder.
func (a ApprovalClass) escalate() ApprovalClass {
	if a >= ApprovalTwoPerson {
		return ApprovalTwoPerson
	}
	return a + 1
}

// Effect is the outcome of an evaluation.
type Effect string

const (
	// EffectAllow permits the operation immediately.
	EffectAllow Effect = "allow"
	// EffectRequireApproval permits the operation once the stated approval class is satisfied.
	EffectRequireApproval Effect = "require_approval"
	// EffectDeny refuses the operation outright.
	EffectDeny Effect = "deny"
)

// Operation is the request being evaluated.
type Operation struct {
	// Tool is the tool identifier, matched against the allow and deny settings.
	Tool string
	// SideEffect is the declared class. An undeclared class is refused (SFX-1).
	SideEffect SideEffectClass
	// Hash binds an approval to this exact operation. A changed operation invalidates a prior
	// approval (SFX-3, SFX-4), so callers must derive it from the full intended effect, not the
	// tool name alone.
	Hash string
	// Scope narrows an approval to a repository, path, or resource.
	Scope string
	// Sink is the destination this operation sends content to. It is a policy dimension separate
	// from the approval ladder: some content must not reach some destinations at any approval
	// class. See sink.go.
	Sink Sink
	// FenceEpoch is the lease epoch the operation executes under, binding an approval to the
	// worker that holds the lease. Zero means the operation holds no lease.
	FenceEpoch uint64
}

// PlanDeclaration is an operation the user approved as part of a plan.
//
// DeclaredAt is what makes the TNT-4 carve-out decidable: only a declaration recorded *before* the
// taint entered exempts an operation from escalation. Without the timestamp the carve-out would let
// injected content request a plan amendment and then use it.
type PlanDeclaration struct {
	Hash       string
	DeclaredAt time.Time
}

// Request carries everything an evaluation needs. Every field is an input the PRD names as a policy
// dimension, so a caller that omits one gets a conservative result rather than a wrong one.
type Request struct {
	Operation Operation
	// Settings is the run's frozen settings snapshot (INV-6).
	Settings settings.Snapshot
	// Taint is the run's current provenance state (TNT-3).
	Taint taint.Set
	// TaintEnteredAt maps each present class to when it first entered, used for the TNT-4 carve-out.
	TaintEnteredAt map[taint.Class]time.Time
	// PlanDeclarations lists operations the approved plan already covers.
	PlanDeclarations []PlanDeclaration
	// Approval is a granted approval offered against this operation, if any. A binding that
	// satisfies the required class resolves the decision to allow.
	Approval *ApprovalBinding
	// Now is the evaluation time. Injected so decisions are reproducible in tests (R-TST-03).
	Now time.Time
}

// Reason explains one contribution to a decision. Reasons are ordered as they were applied, so the
// approval card can show the user why the class is what it is.
type Reason struct {
	Code    string
	Message string
}

// Reason codes surfaced in decisions and approval cards.
const (
	ReasonUndeclaredSideEffect = "undeclared_side_effect"
	ReasonToolDenied           = "tool_denied"
	ReasonToolNotAllowed       = "tool_not_allowed"
	ReasonBaseApprovalMode     = "base_approval_mode"
	ReasonTaintEscalation      = "taint_escalation"
	ReasonPlanDeclared         = "plan_declared"
	ReasonTwoPersonThreshold   = "two_person_threshold"
	ReasonTaintDisabled        = "taint_enforcement_disabled"
	ReasonSecretAtSink         = "secret_at_sink"
	ReasonApprovalSatisfied    = "approval_satisfied"
	ReasonApprovalInvalid      = "approval_invalid"
)

// Decision is the result of an evaluation.
type Decision struct {
	ID            id.ID
	Effect        Effect
	ApprovalClass ApprovalClass
	// EscalatedFrom records the pre-escalation class when taint raised the requirement, so the UI
	// can show what changed and why (TNT-5).
	EscalatedFrom *ApprovalClass
	SideEffect    SideEffectClass
	Sink          Sink
	FenceEpoch    uint64
	TaintClasses  taint.Set
	Reasons       []Reason
	DecidedAt     time.Time
}

// Err returns the error a caller should surface for a non-allow decision, or nil for an allow.
//
// Taint escalation reports MODBIT_TAINT_ESCALATION_REQUIRED rather than a generic approval error so
// that a client can explain the provenance cause instead of showing an unexplained extra prompt.
func (d Decision) Err() error {
	switch d.Effect {
	case EffectAllow:
		return nil
	case EffectDeny:
		return modberr.New(modberr.CodePolicyDenied, "operation denied by policy").
			WithDetail("policy_decision_id", d.ID.String()).
			WithDetail("rule_id", primaryReason(d.Reasons)).
			WithDetail("side_effect_class", d.SideEffect.String())
	case EffectRequireApproval:
		if d.EscalatedFrom != nil {
			return modberr.New(modberr.CodeTaintEscalationRequired,
				"operation requires elevated approval because untrusted content entered this run").
				WithDetail("policy_decision_id", d.ID.String()).
				WithDetail("approval_class", d.ApprovalClass.String()).
				WithDetail("escalated_from", d.EscalatedFrom.String()).
				WithDetail("taint_classes", d.TaintClasses.String()).
				WithDetail("side_effect_class", d.SideEffect.String())
		}
		return modberr.New(modberr.CodeApprovalRequired, "operation requires approval").
			WithDetail("policy_decision_id", d.ID.String()).
			WithDetail("approval_class", d.ApprovalClass.String()).
			WithDetail("side_effect_class", d.SideEffect.String())
	}
	return modberr.New(modberr.CodeInternal, "unrecognized policy effect")
}

func primaryReason(reasons []Reason) string {
	if len(reasons) == 0 {
		return ""
	}
	return reasons[0].Code
}

// Engine evaluates operations against settings and taint state.
//
// It holds no run or tenant state and is safe for concurrent use (R-GO-06).
type Engine struct {
	generator *id.Generator
}

// NewEngine returns an Engine. A nil generator means the process CSPRNG.
func NewEngine(generator *id.Generator) *Engine {
	if generator == nil {
		generator = id.NewGenerator(nil)
	}
	return &Engine{generator: generator}
}

// Evaluate decides whether the operation may proceed.
//
// Evaluation order is deliberate: denials are absolute and are checked before anything can relax
// them; the base approval class then comes from settings; taint escalation applies last so it can
// only ever raise the requirement, never lower it.
func (e *Engine) Evaluate(ctx context.Context, req Request) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, modberr.Wrap(err, modberr.CodeCancelled, "policy evaluation cancelled")
	}

	decisionID, err := e.generator.New(id.PolicyDecision)
	if err != nil {
		return Decision{}, modberr.Wrap(err, modberr.CodeInternal, "allocate policy decision identifier")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	d := Decision{
		ID:           decisionID,
		SideEffect:   req.Operation.SideEffect,
		Sink:         req.Operation.Sink,
		FenceEpoch:   req.Operation.FenceEpoch,
		TaintClasses: req.Taint,
		DecidedAt:    now.UTC(),
	}
	add := func(code, format string, args ...any) {
		d.Reasons = append(d.Reasons, Reason{Code: code, Message: fmt.Sprintf(format, args...)})
	}

	// SFX-1: an operation that has not declared its class cannot be evaluated. Denying is the only
	// safe answer, because the classes differ by orders of magnitude in consequence.
	if !req.Operation.SideEffect.Declared() {
		add(ReasonUndeclaredSideEffect, "operation did not declare a side-effect class")
		d.Effect = EffectDeny
		d.ApprovalClass = ApprovalTwoPerson
		return d, nil
	}

	// A destination refusal precedes the approval ladder: no approval class makes a detected
	// credential in a commit acceptable.
	if reason, blocked := checkSink(req.Operation, req.Taint); blocked {
		d.Reasons = append(d.Reasons, reason)
		d.Effect = EffectDeny
		d.ApprovalClass = ApprovalTwoPerson
		return d, nil
	}

	denied, err := req.Settings.StringList(settings.KeyAgentToolsDenied)
	if err != nil {
		return Decision{}, err
	}
	if matchesTool(denied, req.Operation.Tool) {
		add(ReasonToolDenied, "tool %q is denied by policy", req.Operation.Tool)
		d.Effect = EffectDeny
		d.ApprovalClass = ApprovalTwoPerson
		return d, nil
	}

	allowed, err := req.Settings.StringList(settings.KeyAgentToolsAllowed)
	if err != nil {
		return Decision{}, err
	}
	if !matchesTool(allowed, req.Operation.Tool) {
		add(ReasonToolNotAllowed, "tool %q is not in the allowed set", req.Operation.Tool)
		d.Effect = EffectDeny
		d.ApprovalClass = ApprovalTwoPerson
		return d, nil
	}

	mode, err := req.Settings.String(settings.KeyAgentExecutionMode)
	if err != nil {
		return Decision{}, err
	}
	base := baseApprovalClass(mode, req.Operation.SideEffect)
	add(ReasonBaseApprovalMode, "execution mode %q sets approval %q for a %s operation",
		mode, base, req.Operation.SideEffect)

	// The two-person threshold is a floor, not an alternative: it can only raise the class.
	threshold, err := req.Settings.String(settings.KeyAgentApprovalTwoPersonThreshold)
	if err != nil {
		return Decision{}, err
	}
	if requiresTwoPerson(threshold, req.Operation.SideEffect) && base < ApprovalTwoPerson {
		add(ReasonTwoPersonThreshold, "side-effect class %s meets the two-person threshold %q",
			req.Operation.SideEffect, threshold)
		base = ApprovalTwoPerson
	}

	final, escalatedFrom, escalationReasons, err := e.applyTaint(req, base)
	if err != nil {
		return Decision{}, err
	}
	d.Reasons = append(d.Reasons, escalationReasons...)
	d.ApprovalClass = final
	d.EscalatedFrom = escalatedFrom

	if final == ApprovalNone {
		d.Effect = EffectAllow
		return d, nil
	}

	if req.Approval != nil {
		if err := req.Approval.Check(req.Operation, now); err != nil {
			// A presented-but-invalid approval is reported rather than ignored: silently falling
			// back to "approval required" would hide that a stale grant was attempted.
			add(ReasonApprovalInvalid, "the presented approval does not bind: %s", errMessage(err))
		} else if req.Approval.ApprovalClass >= final {
			add(ReasonApprovalSatisfied,
				"a %s approval covers this operation", req.Approval.ApprovalClass)
			d.Effect = EffectAllow
			return d, nil
		} else {
			add(ReasonApprovalInvalid,
				"the presented %s approval is below the required %s",
				req.Approval.ApprovalClass, final)
		}
	}

	d.Effect = EffectRequireApproval
	return d, nil
}

func errMessage(err error) string {
	if e, ok := modberr.As(err); ok {
		return e.Message()
	}
	return "invalid"
}

// applyTaint implements TNT-3 and TNT-4.
//
// It returns the possibly escalated class, the pre-escalation class when escalation applied, and
// the reasons to record.
func (e *Engine) applyTaint(req Request, base ApprovalClass) (ApprovalClass, *ApprovalClass, []Reason, error) {
	var reasons []Reason
	add := func(code, format string, args ...any) {
		reasons = append(reasons, Reason{Code: code, Message: fmt.Sprintf(format, args...)})
	}

	enforced, err := req.Settings.Bool(settings.KeyTaintEnforcementEnabled)
	if err != nil {
		return base, nil, nil, err
	}
	if !enforced {
		// Recorded rather than skipped silently: a run that executed without taint enforcement must
		// be identifiable afterwards (R-ERR-05).
		add(ReasonTaintDisabled, "taint enforcement is disabled by policy for this run")
		return base, nil, reasons, nil
	}

	subjectClasses, err := configuredSideEffectClasses(req.Settings)
	if err != nil {
		return base, nil, nil, err
	}
	if !subjectClasses[req.Operation.SideEffect] {
		return base, nil, nil, nil
	}

	triggers, err := configuredTriggerClasses(req.Settings)
	if err != nil {
		return base, nil, nil, err
	}
	if !req.Taint.ContainsAny(triggers...) {
		return base, nil, nil, nil
	}

	exemptEnabled, err := req.Settings.Bool(settings.KeyTaintPlanDeclarationExemptsEscalation)
	if err != nil {
		return base, nil, nil, err
	}
	if exemptEnabled {
		if when, ok := earliestTrigger(req.TaintEnteredAt, triggers); ok {
			if declaredBefore(req.PlanDeclarations, req.Operation.Hash, when) {
				add(ReasonPlanDeclared,
					"operation was declared in the approved plan before %s content entered the run",
					presentTriggers(req.Taint, triggers))
				return base, nil, reasons, nil
			}
		}
		// A missing entry time means the ledger could not tell us when the taint arrived. The
		// carve-out requires proof that the declaration came first, so absence of proof denies the
		// exemption rather than granting it.
	}

	escalated := base.escalate()
	if escalated == base {
		add(ReasonTaintEscalation, "approval is already at the strictest class; %s content in context",
			presentTriggers(req.Taint, triggers))
		return base, nil, reasons, nil
	}
	add(ReasonTaintEscalation, "%s content entered the run; %s approval escalated to %s",
		presentTriggers(req.Taint, triggers), base, escalated)
	from := base
	return escalated, &from, reasons, nil
}

// baseApprovalClass maps the execution mode and side-effect class to the approval class before
// taint is considered (PRD §18.3, §20A.10 "Permissions and approvals").
//
// Note that unrestricted mode still requires two-person approval for irreversible operations. Auto
// Mode does not bypass policy, and no mode makes an irreversible external action unattended.
func baseApprovalClass(mode string, class SideEffectClass) ApprovalClass {
	switch mode {
	case "manual":
		switch class {
		case PureReadOnly:
			return ApprovalNone
		default:
			return ApprovalSingle
		}
	case "allowlist":
		switch class {
		case PureReadOnly, WorkspaceReversible:
			return ApprovalNone
		default:
			return ApprovalSingle
		}
	case "auto-review":
		switch class {
		case PureReadOnly, WorkspaceReversible:
			return ApprovalNone
		case LocallyDestructive, ExternallyCompensatable:
			// PRD §12.2 default handling for locally destructive work is "approval and backup",
			// so it gates here rather than merely notifying.
			return ApprovalSingle
		default:
			return ApprovalTwoPerson
		}
	case "unrestricted":
		switch class {
		case ExternallyIrreversible:
			return ApprovalTwoPerson
		default:
			return ApprovalNone
		}
	}
	// An unrecognized mode fails closed. This is reachable only if the settings contract gains a
	// mode that this function has not been taught, which must not silently become permissive.
	return ApprovalTwoPerson
}

// requiresTwoPerson reports whether class meets the configured two-person threshold. The threshold
// names the *lowest* class that requires two approvers, so anything at or above it qualifies.
func requiresTwoPerson(threshold string, class SideEffectClass) bool {
	if threshold == "never" || threshold == "" {
		return false
	}
	floor, err := ParseSideEffectClass(threshold)
	if err != nil {
		// An unparseable threshold is treated as the strictest interpretation rather than as "never".
		return class.External()
	}
	return class >= floor
}

func configuredTriggerClasses(snapshot settings.Snapshot) ([]taint.Class, error) {
	names, err := snapshot.StringList(settings.KeyTaintEscalationTriggerClasses)
	if err != nil {
		return nil, err
	}
	out := make([]taint.Class, 0, len(names))
	for _, n := range names {
		// ParseClass fails closed to the highest-risk class, so an unrecognized configured trigger
		// widens the trigger set rather than disabling it.
		c, _ := taint.ParseClass(n)
		out = append(out, c)
	}
	return out, nil
}

func configuredSideEffectClasses(snapshot settings.Snapshot) (map[SideEffectClass]bool, error) {
	names, err := snapshot.StringList(settings.KeyTaintEscalationSideEffectClasses)
	if err != nil {
		return nil, err
	}
	out := make(map[SideEffectClass]bool, len(names))
	for _, n := range names {
		c, err := ParseSideEffectClass(n)
		if err != nil {
			continue
		}
		out[c] = true
	}
	return out, nil
}

func earliestTrigger(entered map[taint.Class]time.Time, triggers []taint.Class) (time.Time, bool) {
	var earliest time.Time
	found := false
	for _, c := range triggers {
		t, ok := entered[c]
		if !ok {
			continue
		}
		if !found || t.Before(earliest) {
			earliest, found = t, true
		}
	}
	return earliest, found
}

// declaredBefore reports whether hash was declared in the approved plan strictly before cutoff.
// A declaration made at the same instant as the taint entering does not qualify: ties resolve
// against the exemption.
func declaredBefore(declarations []PlanDeclaration, hash string, cutoff time.Time) bool {
	if hash == "" {
		return false
	}
	for _, decl := range declarations {
		if decl.Hash == hash && decl.DeclaredAt.Before(cutoff) {
			return true
		}
	}
	return false
}

func presentTriggers(set taint.Set, triggers []taint.Class) string {
	names := make([]string, 0, len(triggers))
	for _, c := range triggers {
		if set.Contains(c) {
			names = append(names, c.String())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "untrusted"
	}
	return strings.Join(names, " and ")
}

// matchesTool reports whether tool is covered by patterns. A "*" entry matches everything, and a
// trailing "*" matches a namespace prefix such as "mcp.*".
func matchesTool(patterns []string, tool string) bool {
	for _, p := range patterns {
		switch {
		case p == settings.Wildcard:
			return true
		case strings.HasSuffix(p, ".*"):
			if strings.HasPrefix(tool, strings.TrimSuffix(p, "*")) {
				return true
			}
		case p == tool:
			return true
		}
	}
	return false
}
