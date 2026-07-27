// Package inference defines Modbit's canonical, provider-neutral inference representation.
//
// Boundary: the intermediate representation, its validation, and the declaration of lossy
// translation. It does not call providers, hold credentials, route, or apply DLP — all of that
// lives inside the Model Gateway, which is the only egress boundary (INV-1, INV-2).
//
// Requirements: PRD v5.1 §14.1.1. ADP-1 (provider formats terminate at the adapter boundary),
// ADP-2 (no branching on provider or model names), ADP-3 (adapters declare lossy translation),
// ADP-4 (new model tiers are configuration, not harness code), ADP-5/ADP-6 (conformance).
//
// # Why a closed tagged union
//
// Content parts are a struct with a Kind discriminator rather than an interface. An interface would
// let an adapter receive a part it does not recognize and drop it silently, which is how a prompt
// quietly loses an image or a tool result and the model answers the wrong question. A closed union
// forces every adapter to switch exhaustively, and Part.Validate rejects a part whose payload does
// not match its kind, so a malformed part cannot reach a provider at all.
//
// # Why media is always by reference
//
// No part carries bytes. Images, audio, and files are object-store references with a digest. Prompt
// payloads are metadata-only by default (INV-4), and a representation that could hold megabytes of
// inline base64 would make that promise unenforceable the first time a request is traced.
package inference

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Version is the canonical IR version. Adapters declare the versions they accept; a mismatch is
// MODBIT_UNSUPPORTED_VERSION rather than a best-effort translation.
const Version = 1

// Role identifies the author of a message.
type Role string

const (
	// RoleSystem carries platform instructions. It is assembled by the Instruction Service and is
	// never authored from repository or tool content.
	RoleSystem Role = "system"
	// RoleDeveloper carries Agent Profile and Rule instructions resolved into the Instruction
	// Manifest.
	RoleDeveloper Role = "developer"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	// RoleTool carries tool results returned to the model.
	RoleTool Role = "tool"
)

var validRoles = map[Role]bool{
	RoleSystem: true, RoleDeveloper: true, RoleUser: true, RoleAssistant: true, RoleTool: true,
}

// PartKind discriminates the content union.
type PartKind string

const (
	PartText       PartKind = "text"
	PartImage      PartKind = "image"
	PartAudio      PartKind = "audio"
	PartFile       PartKind = "file"
	PartToolCall   PartKind = "tool_call"
	PartToolResult PartKind = "tool_result"
	// PartReasoning carries provider reasoning summaries where the provider exposes them and policy
	// permits their capture.
	PartReasoning PartKind = "reasoning"
	// PartRefusal carries a provider safety refusal as structured data rather than as prose the
	// harness would have to pattern match.
	PartRefusal PartKind = "refusal"
)

// MediaRef points at an immutable object-store payload. Bytes never travel in the IR.
type MediaRef struct {
	// ObjectRef is the artifact-service reference.
	ObjectRef id.ID `json:"object_ref"`
	// MediaType is the IANA media type, used by adapters to pick a provider encoding.
	MediaType string `json:"media_type"`
	// Digest is "sha256:<64 hex>", so a worker can verify what it fetched.
	Digest string `json:"digest"`
	// Bytes is the payload size, used for capability checks before a fetch is attempted.
	Bytes int64 `json:"bytes"`
}

// ToolCall is a model request to invoke a tool.
type ToolCall struct {
	// ID correlates the call with its result. It is provider-neutral; adapters map it to and from
	// whatever the provider uses.
	ID string `json:"id"`
	// Name is the Modbit tool identifier, matched against policy allow and deny lists.
	Name string `json:"name"`
	// Input is the validated argument object.
	Input json.RawMessage `json:"input"`
}

// ToolResult is the outcome of a tool invocation returned to the model.
type ToolResult struct {
	// CallID matches the originating ToolCall.
	CallID string `json:"call_id"`
	// Parts carries the result content. Tool output is untrusted input (INV-13), so every part
	// carries its provenance class.
	Parts []Part `json:"parts"`
	// IsError marks a failed invocation. It is a field rather than an error string in the text so
	// the harness never has to infer failure from prose.
	IsError bool `json:"is_error"`
}

// Reasoning carries a provider reasoning summary.
type Reasoning struct {
	Summary string `json:"summary"`
	// Redacted marks reasoning the provider returned in an opaque form.
	Redacted bool `json:"redacted"`
}

// CacheHint requests provider prompt caching for a part. Adapters that cannot honour it declare
// the omission as a Loss rather than ignoring it.
type CacheHint string

const (
	CacheNone      CacheHint = ""
	CacheEphemeral CacheHint = "ephemeral"
	CachePersist   CacheHint = "persist"
)

// Part is one unit of message content.
//
// Exactly one payload field is populated, selected by Kind. Validate enforces that.
type Part struct {
	Kind PartKind `json:"kind"`

	Text       string      `json:"text,omitempty"`
	Media      *MediaRef   `json:"media,omitempty"`
	ToolCall   *ToolCall   `json:"tool_call,omitempty"`
	ToolResult *ToolResult `json:"tool_result,omitempty"`
	Reasoning  *Reasoning  `json:"reasoning,omitempty"`
	Refusal    string      `json:"refusal,omitempty"`

	// Provenance is the part's taint class (TNT-1). The zero value is taint.UserTrusted, so a part
	// assembled without classification would claim to be trusted; NewPart and the context plane set
	// this explicitly, and Request.Validate rejects unclassifiable content.
	Provenance taint.Class `json:"provenance"`
	CacheHint  CacheHint   `json:"cache_hint,omitempty"`
}

// Validate reports whether the part's payload matches its kind.
func (p Part) Validate() error {
	bad := func(reason string) error {
		return modberr.Newf(modberr.CodeInvalidArgument, "content part %q: %s", p.Kind, reason).
			WithDetail("field", "part").
			WithDetail("constraint", string(p.Kind))
	}
	populated := 0
	for _, set := range []bool{
		p.Text != "", p.Media != nil, p.ToolCall != nil,
		p.ToolResult != nil, p.Reasoning != nil, p.Refusal != "",
	} {
		if set {
			populated++
		}
	}
	if populated > 1 {
		return bad("exactly one payload field may be populated")
	}

	switch p.Kind {
	case PartText:
		if p.Text == "" {
			return bad("text is required")
		}
	case PartImage, PartAudio, PartFile:
		if p.Media == nil {
			return bad("a media reference is required")
		}
		if !p.Media.ObjectRef.HasPrefix(id.ObjectRef) {
			return bad("media object_ref must be an obj_ identifier")
		}
		if p.Media.MediaType == "" {
			return bad("media_type is required")
		}
		if !strings.HasPrefix(p.Media.Digest, "sha256:") || len(p.Media.Digest) != 71 {
			return bad("digest must be sha256:<64 hex characters>")
		}
	case PartToolCall:
		if p.ToolCall == nil {
			return bad("a tool call is required")
		}
		if p.ToolCall.ID == "" || p.ToolCall.Name == "" {
			return bad("tool call requires an id and a name")
		}
		if len(p.ToolCall.Input) == 0 {
			return bad("tool call requires an input object, use {} for none")
		}
		if !json.Valid(p.ToolCall.Input) {
			return bad("tool call input is not valid JSON")
		}
	case PartToolResult:
		if p.ToolResult == nil {
			return bad("a tool result is required")
		}
		if p.ToolResult.CallID == "" {
			return bad("tool result requires the originating call id")
		}
		for i, nested := range p.ToolResult.Parts {
			if nested.Kind == PartToolResult || nested.Kind == PartToolCall {
				return bad(fmt.Sprintf("tool result part %d may not nest a tool call or result", i))
			}
			if err := nested.Validate(); err != nil {
				return err
			}
		}
	case PartReasoning:
		if p.Reasoning == nil {
			return bad("reasoning is required")
		}
	case PartRefusal:
		if p.Refusal == "" {
			return bad("refusal text is required")
		}
	default:
		return bad("unknown content part kind")
	}

	if !p.Provenance.Valid() {
		return bad("provenance class is not registered")
	}
	return nil
}

// Message is one turn of the conversation.
type Message struct {
	Role  Role   `json:"role"`
	Parts []Part `json:"parts"`
}

// Validate checks the role and every part.
func (m Message) Validate() error {
	if !validRoles[m.Role] {
		return modberr.Newf(modberr.CodeInvalidArgument, "unknown message role %q", m.Role).
			WithDetail("field", "role")
	}
	if len(m.Parts) == 0 {
		return modberr.New(modberr.CodeInvalidArgument, "message requires at least one content part").
			WithDetail("field", "parts")
	}
	for _, p := range m.Parts {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	// Tool results belong to the tool role and nowhere else: accepting them elsewhere would let an
	// adapter place untrusted output where a provider treats it as assistant reasoning.
	for _, p := range m.Parts {
		if p.Kind == PartToolResult && m.Role != RoleTool {
			return modberr.Newf(modberr.CodeInvalidArgument,
				"tool results may only appear in a %q message, got %q", RoleTool, m.Role).
				WithDetail("field", "role")
		}
		if p.Kind == PartToolCall && m.Role != RoleAssistant {
			return modberr.Newf(modberr.CodeInvalidArgument,
				"tool calls may only appear in an %q message, got %q", RoleAssistant, m.Role).
				WithDetail("field", "role")
		}
	}
	return nil
}

// Taint returns the highest-risk provenance class present in the message (TNT-2).
func (m Message) Taint() taint.Class {
	classes := make([]taint.Class, 0, len(m.Parts))
	for _, p := range m.Parts {
		classes = append(classes, p.Taint())
	}
	return taint.Propagate(classes...)
}

// Taint returns the part's provenance, folding in nested tool-result parts.
func (p Part) Taint() taint.Class {
	if p.Kind != PartToolResult || p.ToolResult == nil {
		return p.Provenance
	}
	classes := make([]taint.Class, 0, len(p.ToolResult.Parts)+1)
	classes = append(classes, p.Provenance)
	for _, nested := range p.ToolResult.Parts {
		classes = append(classes, nested.Taint())
	}
	return taint.Propagate(classes...)
}

// ToolDefinition describes a tool offered to the model.
type ToolDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// InputSchema is a JSON Schema object. Adapters translate it into the provider's tool-schema
	// dialect and declare a Loss when the dialect cannot express a construct.
	InputSchema json.RawMessage `json:"input_schema"`
}

// ToolChoice constrains how the model may use tools.
type ToolChoice struct {
	// Mode is auto, none, required, or specific.
	Mode ToolChoiceMode `json:"mode"`
	// Name selects a tool when Mode is ToolChoiceSpecific.
	Name string `json:"name,omitempty"`
}

// ToolChoiceMode enumerates tool-choice behaviour.
type ToolChoiceMode string

const (
	ToolChoiceAuto     ToolChoiceMode = "auto"
	ToolChoiceNone     ToolChoiceMode = "none"
	ToolChoiceRequired ToolChoiceMode = "required"
	ToolChoiceSpecific ToolChoiceMode = "specific"
)

// StructuredOutput constrains the response to a schema.
type StructuredOutput struct {
	// SchemaID references a Structured Output Contract in the registry.
	SchemaID string          `json:"schema_id"`
	Version  int             `json:"schema_version"`
	Schema   json.RawMessage `json:"schema"`
	// Strict requires the provider to enforce the schema. An adapter whose provider only supports
	// best-effort shaping declares a Loss rather than silently downgrading.
	Strict bool `json:"strict"`
}

// ReasoningEffort requests provider reasoning depth where exposed.
type ReasoningEffort string

const (
	ReasoningNone   ReasoningEffort = "none"
	ReasoningLow    ReasoningEffort = "low"
	ReasoningMedium ReasoningEffort = "medium"
	ReasoningHigh   ReasoningEffort = "high"
)

// Request is a canonical inference request.
//
// It names a capability Alias, never a provider or model name (ADP-2). Route selection belongs to
// the Model Gateway, and a new model tier is a capability-registry entry rather than a code change
// here (ADP-4).
type Request struct {
	// IRVersion pins the representation version.
	IRVersion int `json:"ir_version"`
	// Alias is the model capability alias, resolved to a concrete route by the gateway.
	Alias string `json:"alias"`
	// System and Developer instructions come from the Instruction Manifest.
	System    []Part    `json:"system,omitempty"`
	Developer []Part    `json:"developer,omitempty"`
	Messages  []Message `json:"messages"`

	Tools            []ToolDefinition  `json:"tools,omitempty"`
	ToolChoice       *ToolChoice       `json:"tool_choice,omitempty"`
	StructuredOutput *StructuredOutput `json:"structured_output,omitempty"`
	Reasoning        ReasoningEffort   `json:"reasoning,omitempty"`

	MaxOutputTokens int      `json:"max_output_tokens,omitempty"`
	StopSequences   []string `json:"stop_sequences,omitempty"`
	// Temperature is a pointer so that "unset" is distinguishable from a deliberate 0.
	Temperature *float64 `json:"temperature,omitempty"`

	// RunID and StepID attribute usage and cost. They are required: an unattributable model call
	// cannot be budgeted, audited, or joined to a Verify outcome (OBR-1).
	RunID  id.ID `json:"run_id"`
	StepID id.ID `json:"step_id"`
}

// Validate checks the request's structural integrity.
//
// It deliberately does not check capability satisfaction — that needs a resolved model, and lives
// in Capabilities.Check — so a caller can validate a request before a route exists.
func (r Request) Validate() error {
	if r.IRVersion != Version {
		return modberr.Newf(modberr.CodeUnsupportedVersion,
			"canonical IR version %d is not supported", r.IRVersion).
			WithDetail("requested_version", fmt.Sprint(r.IRVersion)).
			WithDetail("supported_versions", fmt.Sprint(Version))
	}
	if strings.TrimSpace(r.Alias) == "" {
		return modberr.New(modberr.CodeInvalidArgument, "request requires a model capability alias").
			WithDetail("field", "alias")
	}
	if !r.RunID.HasPrefix(id.Run) {
		return modberr.New(modberr.CodeInvalidArgument, "request requires a run identifier for attribution").
			WithDetail("field", "run_id")
	}
	if !r.StepID.HasPrefix(id.RunStep) {
		return modberr.New(modberr.CodeInvalidArgument, "request requires a step identifier for attribution").
			WithDetail("field", "step_id")
	}
	if len(r.Messages) == 0 {
		return modberr.New(modberr.CodeInvalidArgument, "request requires at least one message").
			WithDetail("field", "messages")
	}
	for _, group := range [][]Part{r.System, r.Developer} {
		for _, p := range group {
			if p.Kind != PartText {
				return modberr.New(modberr.CodeInvalidArgument,
					"system and developer instructions must be text parts").
					WithDetail("field", "system")
			}
			if err := p.Validate(); err != nil {
				return err
			}
		}
	}
	for _, m := range r.Messages {
		if err := m.Validate(); err != nil {
			return err
		}
	}
	if err := r.validateToolReferences(); err != nil {
		return err
	}
	if r.MaxOutputTokens < 0 {
		return modberr.New(modberr.CodeInvalidArgument, "max_output_tokens cannot be negative").
			WithDetail("field", "max_output_tokens")
	}
	return nil
}

// validateToolReferences checks that tool calls and results form matched pairs and that every call
// names a declared tool. A dangling result or an undeclared tool is a request the provider would
// either reject or, worse, silently reinterpret.
func (r Request) validateToolReferences() error {
	declared := make(map[string]struct{}, len(r.Tools))
	for _, t := range r.Tools {
		if t.Name == "" {
			return modberr.New(modberr.CodeInvalidArgument, "tool definition requires a name").
				WithDetail("field", "tools")
		}
		if len(t.InputSchema) > 0 && !json.Valid(t.InputSchema) {
			return modberr.Newf(modberr.CodeInvalidArgument, "tool %q has an invalid input schema", t.Name).
				WithDetail("field", "tools")
		}
		if _, dup := declared[t.Name]; dup {
			return modberr.Newf(modberr.CodeInvalidArgument, "tool %q is declared twice", t.Name).
				WithDetail("field", "tools")
		}
		declared[t.Name] = struct{}{}
	}

	calls := make(map[string]struct{})
	for _, m := range r.Messages {
		for _, p := range m.Parts {
			switch p.Kind {
			case PartToolCall:
				if _, ok := declared[p.ToolCall.Name]; !ok {
					return modberr.Newf(modberr.CodeInvalidArgument,
						"message calls tool %q which is not declared in this request", p.ToolCall.Name).
						WithDetail("field", "tools")
				}
				if _, dup := calls[p.ToolCall.ID]; dup {
					return modberr.Newf(modberr.CodeInvalidArgument,
						"tool call id %q appears more than once", p.ToolCall.ID).
						WithDetail("field", "messages")
				}
				calls[p.ToolCall.ID] = struct{}{}
			case PartToolResult:
				if _, ok := calls[p.ToolResult.CallID]; !ok {
					return modberr.Newf(modberr.CodeInvalidArgument,
						"tool result references call %q which no preceding message made", p.ToolResult.CallID).
						WithDetail("field", "messages")
				}
			}
		}
	}

	if r.ToolChoice != nil {
		switch r.ToolChoice.Mode {
		case ToolChoiceAuto, ToolChoiceNone, ToolChoiceRequired:
		case ToolChoiceSpecific:
			if _, ok := declared[r.ToolChoice.Name]; !ok {
				return modberr.Newf(modberr.CodeInvalidArgument,
					"tool_choice names undeclared tool %q", r.ToolChoice.Name).
					WithDetail("field", "tool_choice")
			}
		default:
			return modberr.Newf(modberr.CodeInvalidArgument,
				"unknown tool_choice mode %q", r.ToolChoice.Mode).WithDetail("field", "tool_choice")
		}
		if r.ToolChoice.Mode != ToolChoiceNone && len(r.Tools) == 0 {
			return modberr.New(modberr.CodeInvalidArgument,
				"tool_choice requires at least one declared tool").WithDetail("field", "tool_choice")
		}
	}
	return nil
}

// Taint returns the highest-risk provenance class anywhere in the request. The Model Gateway
// records it on the model-call metadata, and the policy engine consumes the run's accumulated set.
func (r Request) Taint() taint.Class {
	classes := make([]taint.Class, 0, len(r.Messages)+len(r.System)+len(r.Developer))
	for _, p := range r.System {
		classes = append(classes, p.Taint())
	}
	for _, p := range r.Developer {
		classes = append(classes, p.Taint())
	}
	for _, m := range r.Messages {
		classes = append(classes, m.Taint())
	}
	return taint.Propagate(classes...)
}

// FinishReason is the closed set of reasons a completion ended.
type FinishReason string

const (
	FinishEndTurn       FinishReason = "end_turn"
	FinishMaxTokens     FinishReason = "max_tokens"
	FinishStopSequence  FinishReason = "stop_sequence"
	FinishToolUse       FinishReason = "tool_use"
	FinishContentFilter FinishReason = "content_filter"
	FinishCancelled     FinishReason = "cancelled"
	FinishError         FinishReason = "error"
)

var validFinishReasons = map[FinishReason]bool{
	FinishEndTurn: true, FinishMaxTokens: true, FinishStopSequence: true, FinishToolUse: true,
	FinishContentFilter: true, FinishCancelled: true, FinishError: true,
}

// Usage is normalized token accounting. Cost is computed by the gateway from the model's pricing,
// not carried here, so a usage record cannot disagree with the price list it was billed against.
type Usage struct {
	InputTokens       int `json:"input_tokens"`
	CachedInputTokens int `json:"cached_input_tokens"`
	OutputTokens      int `json:"output_tokens"`
	ReasoningTokens   int `json:"reasoning_tokens"`
}

// Total returns the billable token count.
func (u Usage) Total() int {
	return u.InputTokens + u.CachedInputTokens + u.OutputTokens + u.ReasoningTokens
}

// Response is a canonical completion.
type Response struct {
	IRVersion int    `json:"ir_version"`
	Alias     string `json:"alias"`
	// ModelRevision is the concrete provider revision that served the request. It is recorded for
	// evidence and drift detection (MOD-6, OEV-1) and must not be branched on (ADP-2).
	ModelRevision string       `json:"model_revision"`
	Parts         []Part       `json:"parts"`
	FinishReason  FinishReason `json:"finish_reason"`
	Usage         Usage        `json:"usage"`
	// Losses declares every translation the adapter could not perform exactly (ADP-3).
	Losses []Loss `json:"losses,omitempty"`
}

// Validate checks the response's structural integrity.
func (r Response) Validate() error {
	if r.IRVersion != Version {
		return modberr.Newf(modberr.CodeUnsupportedVersion,
			"canonical IR version %d is not supported", r.IRVersion).
			WithDetail("requested_version", fmt.Sprint(r.IRVersion)).
			WithDetail("supported_versions", fmt.Sprint(Version))
	}
	if !validFinishReasons[r.FinishReason] {
		return modberr.Newf(modberr.CodeInvalidArgument, "unknown finish reason %q", r.FinishReason).
			WithDetail("field", "finish_reason")
	}
	if r.ModelRevision == "" {
		return modberr.New(modberr.CodeInvalidArgument,
			"response must record the provider model revision").WithDetail("field", "model_revision")
	}
	for _, p := range r.Parts {
		if err := p.Validate(); err != nil {
			return err
		}
		// Everything a model produces is `generated` at minimum; a response part claiming
		// user_trusted provenance would launder model output into the trusted class.
		if p.Provenance < taint.Generated {
			return modberr.New(modberr.CodeInvalidArgument,
				"response parts are at least generated provenance").WithDetail("field", "provenance")
		}
	}
	// A tool-use finish with no tool call is a response the harness cannot act on.
	if r.FinishReason == FinishToolUse && !r.hasToolCall() {
		return modberr.New(modberr.CodeInvalidArgument,
			"finish reason tool_use requires at least one tool call part").
			WithDetail("field", "finish_reason")
	}
	if usage := r.Usage; usage.InputTokens < 0 || usage.OutputTokens < 0 ||
		usage.CachedInputTokens < 0 || usage.ReasoningTokens < 0 {
		return modberr.New(modberr.CodeInvalidArgument, "usage counts cannot be negative").
			WithDetail("field", "usage")
	}
	return nil
}

func (r Response) hasToolCall() bool {
	for _, p := range r.Parts {
		if p.Kind == PartToolCall {
			return true
		}
	}
	return false
}

// ToolCalls returns the tool calls in the response, in order.
func (r Response) ToolCalls() []ToolCall {
	var out []ToolCall
	for _, p := range r.Parts {
		if p.Kind == PartToolCall && p.ToolCall != nil {
			out = append(out, *p.ToolCall)
		}
	}
	return out
}

// Text returns the concatenated text parts.
func (r Response) Text() string {
	var b strings.Builder
	for _, p := range r.Parts {
		if p.Kind == PartText {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}
