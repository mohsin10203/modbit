package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/policy"
	"github.com/modbit/modbit/pkg/settings"
	"github.com/modbit/modbit/pkg/taint"
)

// Tool invariants (T1–T9).
//
// TLS-1 through TLS-7. This is where the policy engine, the taint lattice, and the side-effect
// ladder meet a real caller for the first time: every one of them was built against tests, and a
// tool call is the first thing that actually drives all three together.
//
// One test each in tool_test.go. A test without a T-number, or a T-number without a test, is a gap.
//
//	T1 A tool with no declared side-effect class cannot be registered.
//	T2 Input is validated before policy is evaluated.
//	T3 A tool cannot receive a provider credential.
//	T4 Every call produces a record carrying actor, policy decision, timing, and result hash.
//	T5 A tool error is a structured value, never prose.
//	T6 Tool output is untrusted; a result is at least tool_result provenance.
//	T7 Oversized output is truncated with a handle, never silently dropped.
//	T8 A denied decision means the tool is never invoked.
//	T9 A schema is versioned, and input is validated against the version being invoked.

// Definition is a tool's typed, versioned contract (TLS-1, TLS-6).
type Definition struct {
	// Name is the stable tool identifier matched against the allow and deny settings.
	Name string `json:"name"`
	// Version is the schema version. TLS-1 makes schemas versioned so a changed input shape is a new
	// version rather than a silent reinterpretation of the old one.
	Version     int    `json:"version"`
	Description string `json:"description"`
	// InputSchema is a JSON Schema object describing the accepted input.
	InputSchema json.RawMessage `json:"input_schema"`
	// SideEffect is the declared blast radius (TLS-6, SFX-1). An undeclared class is refused at
	// registration, not at call time: a tool nobody classified is one nobody decided the risk of,
	// and discovering that mid-run means discovering it after the plan was approved.
	SideEffect policy.SideEffectClass `json:"side_effect"`
	// Sink is the destination this tool sends content to, if any. It is a policy dimension separate
	// from the approval ladder (decision 21).
	Sink policy.Sink `json:"sink,omitempty"`
}

// Qualified renders the versioned identity a call is bound to.
func (d Definition) Qualified() string { return d.Name + "@v" + strconv.Itoa(d.Version) }

// Tool is a capability the agent may invoke.
//
// T3, TLS-7. Invoke takes an input document and nothing else. There is no parameter, field, or
// context value through which a provider credential could reach a tool — the credential boundary
// (INV-2) is an explicit argument on adapter methods precisely so that every place one travels is
// visible, and a tool is not one of those places.
type Tool interface {
	Definition() Definition
	Invoke(ctx context.Context, input json.RawMessage) (Output, error)
}

// Output is what a tool produces.
type Output struct {
	// Body is the tool's textual result.
	Body string
	// Provenance is the class of the body. It is raised to at least tool_result on recording (T6),
	// so a tool cannot declare its own output more trusted than it is.
	Provenance taint.Class
}

// ToolError is a structured tool failure (TLS-3).
//
// T5. A tool that failed by returning prose forces every caller to pattern-match English to decide
// whether to retry, and that pattern match silently breaks when the wording changes. The code is
// what a caller branches on; the message is for a human.
type ToolError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *ToolError) Error() string { return e.Code + ": " + e.Message }

// MaxOutputBytes bounds a recorded tool result.
//
// TLS-5: large outputs truncate and expose an artifact handle. The bound is a constant rather than a
// setting because it protects the run's own context budget and the event log, neither of which is an
// operator preference — and a configurable limit is one somebody raises to make a symptom go away.
const MaxOutputBytes = 32 << 10

// Record is the immutable evidence of one tool call (TLS-4).
type Record struct {
	ID    id.ID  `json:"id"`
	RunID id.ID  `json:"run_id"`
	Tool  string `json:"tool"`
	// SchemaVersion is the version the input was validated against (T9).
	SchemaVersion int `json:"schema_version"`
	// Actor is who the call was made on behalf of.
	Actor string `json:"actor"`
	// PolicyDecisionID names the decision that permitted the call (INV-7).
	PolicyDecisionID id.ID         `json:"policy_decision_id"`
	Effect           policy.Effect `json:"effect"`
	SideEffect       string        `json:"side_effect"`
	StartedAt        time.Time     `json:"started_at"`
	Duration         time.Duration `json:"duration"`
	// ResultHash covers the full, untruncated output, so a truncated record still proves what was
	// produced.
	ResultHash string `json:"result_hash"`
	// Truncated and ArtifactRef expose the rest of an oversized output (TLS-5).
	Truncated   bool   `json:"truncated"`
	ArtifactRef id.ID  `json:"artifact_ref,omitempty"`
	Output      string `json:"output"`
	// Provenance is the class the result carries forward (T6, INV-13).
	Provenance taint.Class `json:"provenance"`
	// Err is set when the tool failed. It is a structured value (TLS-3).
	Err *ToolError `json:"error,omitempty"`
}

// ArtifactStore persists an oversized tool output and returns a handle.
//
// It is a port because storing an artifact is somebody else's durability concern, and because a
// registry that wrote files itself would be a second, unpoliced filesystem writer inside a package
// whose whole job is policing what tools may do.
type ArtifactStore interface {
	Put(ctx context.Context, runID id.ID, body string) (id.ID, error)
}

// SchemaValidator checks a tool input against its schema (TLS-2).
//
// A port because full JSON Schema is a specification, not a function, and adopting a validator is a
// dependency decision under R-GO-09. BasicValidator covers the subset tool schemas actually use —
// object type, required properties, and property types — and refuses anything it cannot check rather
// than passing it.
type SchemaValidator interface {
	Validate(schema json.RawMessage, input json.RawMessage) error
}

// Call is a request to invoke a tool.
type Call struct {
	Tool  string
	Input json.RawMessage
	// Actor is who the call is made on behalf of, recorded on the evidence (TLS-4).
	Actor string
	// Scope narrows an approval to a repository, path, or resource.
	Scope string
	// FenceEpoch is the lease epoch the call executes under.
	FenceEpoch uint64
}

// Registry holds the tools a run may invoke and enforces the path every call takes.
type Registry struct {
	tools     map[string]Tool
	engine    *policy.Engine
	validator SchemaValidator
	artifacts ArtifactStore
}

// NewRegistry returns an empty registry.
func NewRegistry(engine *policy.Engine, validator SchemaValidator, artifacts ArtifactStore) (*Registry, error) {
	bad := func(msg, field string) (*Registry, error) {
		return nil, modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", field)
	}
	if engine == nil {
		// A registry with no policy engine is not a permissive registry; it is one where SFX-1
		// through SFX-5 do not exist, which is a different product.
		return bad("a tool registry requires a policy engine", "engine")
	}
	if validator == nil {
		return bad("a tool registry requires a schema validator", "validator")
	}
	if artifacts == nil {
		// Without a store, an oversized output would have to be dropped rather than handed over,
		// which is the silent loss TLS-5 exists to prevent.
		return bad("a tool registry requires an artifact store", "artifacts")
	}
	return &Registry{
		tools: make(map[string]Tool), engine: engine,
		validator: validator, artifacts: artifacts,
	}, nil
}

// Register adds a tool.
//
// T1. An undeclared side-effect class is refused here rather than at call time: a tool nobody
// classified is one nobody decided the risk of, and discovering that mid-run means discovering it
// after the plan was approved.
func (r *Registry) Register(t Tool) error {
	if t == nil {
		return modberr.New(modberr.CodeInvalidArgument, "cannot register a nil tool").
			WithDetail("field", "tool")
	}
	def := t.Definition()
	bad := func(msg string) error {
		return modberr.New(modberr.CodeInvalidArgument, msg).
			WithDetail("field", "definition").WithDetail("tool", def.Name)
	}
	if def.Name == "" {
		return bad("a tool requires a name")
	}
	if def.Version < 1 {
		return bad("a tool requires a schema version of at least 1")
	}
	if !def.SideEffect.Declared() {
		return bad("a tool must declare its side-effect class")
	}
	if len(def.InputSchema) == 0 {
		return bad("a tool requires an input schema")
	}
	if def.Sink != "" && !def.Sink.Valid() {
		return bad("a tool's sink must be a known destination")
	}
	if _, exists := r.tools[def.Name]; exists {
		// Silently replacing would let a later registration change what an already-approved plan
		// authorized, under the same name.
		return modberr.Newf(modberr.CodeConflict, "tool %q is already registered", def.Name).
			WithDetail("tool", def.Name)
	}
	r.tools[def.Name] = t
	return nil
}

// Definitions returns every registered definition, ordered by name so a prompt built from them is
// reproducible.
func (r *Registry) Definitions() []Definition {
	out := make([]Definition, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t.Definition())
	}
	slices.SortFunc(out, func(a, b Definition) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out
}

// InvokeOptions carries the run state a policy decision needs.
type InvokeOptions struct {
	RunID    id.ID
	Settings settings.Snapshot
	// Taint is the run's current provenance state (TNT-3).
	Taint          taint.Set
	TaintEnteredAt map[taint.Class]time.Time
	// PlanDeclarations lists operations the approved plan already covers.
	PlanDeclarations []policy.PlanDeclaration
	// Approval is a granted approval offered against this operation, if any.
	Approval *policy.ApprovalBinding
	Now      time.Time
}

// Invoke runs a tool through the full path: validate, evaluate, invoke, record.
//
// The order is the contract. TLS-2 puts validation before policy evaluation, and T8 puts the
// decision before the invocation; neither is an implementation detail, and both are asserted rather
// than assumed.
func (r *Registry) Invoke(ctx context.Context, call Call, opts InvokeOptions) (Record, error) {
	tool, ok := r.tools[call.Tool]
	if !ok {
		return Record{}, modberr.Newf(modberr.CodeNotFound, "no tool named %q is registered", call.Tool).
			WithDetail("tool", call.Tool)
	}
	def := tool.Definition()

	// T2, T9. Validating first means an invalid input never produces a policy decision — a decision
	// is an audited artifact (INV-7), and minting one for a call that was never going to run
	// pollutes the record with authorizations nothing acted on.
	if err := r.validator.Validate(def.InputSchema, call.Input); err != nil {
		return Record{}, modberr.Wrap(err, modberr.CodeInvalidArgument, "tool input failed schema validation").
			WithDetail("tool", def.Name).
			WithDetail("constraint", def.Qualified())
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	decision, err := r.engine.Evaluate(ctx, policy.Request{
		Operation: policy.Operation{
			Tool:       def.Name,
			SideEffect: def.SideEffect,
			Hash:       operationHash(def, call.Input),
			Scope:      call.Scope,
			Sink:       def.Sink,
			FenceEpoch: call.FenceEpoch,
		},
		Settings:         opts.Settings,
		Taint:            opts.Taint,
		TaintEnteredAt:   opts.TaintEnteredAt,
		PlanDeclarations: opts.PlanDeclarations,
		Approval:         opts.Approval,
		Now:              now,
	})
	if err != nil {
		return Record{}, err
	}

	record := Record{
		RunID:            opts.RunID,
		Tool:             def.Name,
		SchemaVersion:    def.Version,
		Actor:            call.Actor,
		PolicyDecisionID: decision.ID,
		Effect:           decision.Effect,
		SideEffect:       def.SideEffect.String(),
		StartedAt:        now,
	}

	// T8. A denied or approval-pending decision returns before the tool is reached. There is no
	// path from here to Invoke that skips this.
	if decision.Effect != policy.EffectAllow {
		return record, decision.Err()
	}

	recordID, err := id.New(id.RunStep)
	if err != nil {
		return Record{}, modberr.Wrap(err, modberr.CodeInternal, "allocate tool record id")
	}
	record.ID = recordID

	started := time.Now()
	output, invokeErr := tool.Invoke(ctx, call.Input)
	record.Duration = time.Since(started)

	if invokeErr != nil {
		// T5. A structured error passes through; anything else is wrapped into one, so a caller
		// never has to pattern-match prose to decide whether to retry.
		var structured *ToolError
		if errors.As(invokeErr, &structured) {
			record.Err = structured
		} else {
			record.Err = &ToolError{
				Code:      string(modberr.CodeOf(invokeErr)),
				Message:   invokeErr.Error(),
				Retryable: modberr.IsRetryable(invokeErr),
			}
		}
		record.Provenance = taint.ToolResult
		record.ResultHash = hashOf("")
		return record, nil
	}

	// T6, INV-13. Tool output is untrusted input. A tool declaring its own result user_trusted would
	// launder whatever it read — a file, an HTTP response, a subprocess's stdout — into the class the
	// agent acts on without question. The recorded class is raised, never lowered.
	record.Provenance = output.Provenance
	if record.Provenance < taint.ToolResult {
		record.Provenance = taint.ToolResult
	}

	// T7. The hash covers the full output, so a truncated record still proves what was produced.
	record.ResultHash = hashOf(output.Body)
	if len(output.Body) > MaxOutputBytes {
		ref, err := r.artifacts.Put(ctx, opts.RunID, output.Body)
		if err != nil {
			// Dropping the overflow silently is the loss TLS-5 exists to prevent, so a store failure
			// fails the call rather than returning a quietly incomplete result.
			return record, modberr.Wrap(err, modberr.CodeUnavailable,
				"oversized tool output could not be stored")
		}
		record.Truncated = true
		record.ArtifactRef = ref
		record.Output = output.Body[:MaxOutputBytes]
	} else {
		record.Output = output.Body
	}
	return record, nil
}

// operationHash binds an approval to this exact call (SFX-3, SFX-4).
//
// It covers the tool's versioned identity and the input, so changing either invalidates a prior
// approval. Hashing the name alone would let an approved "run tests" become an approved "run
// anything" the moment the arguments changed.
func operationHash(def Definition, input json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(def.Qualified()))
	h.Write([]byte{0})
	h.Write(input)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func hashOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(sum[:])
}
