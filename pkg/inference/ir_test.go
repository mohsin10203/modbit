package inference_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

func textPart(text string, class taint.Class) inference.Part {
	return inference.Part{Kind: inference.PartText, Text: text, Provenance: class}
}

func mediaPart(kind inference.PartKind, mediaType string) inference.Part {
	return inference.Part{
		Kind: kind,
		Media: &inference.MediaRef{
			ObjectRef: id.MustNew(id.ObjectRef),
			MediaType: mediaType,
			Digest:    "sha256:" + strings.Repeat("a", 64),
			Bytes:     1024,
		},
		Provenance: taint.UserTrusted,
	}
}

func baseRequest() inference.Request {
	return inference.Request{
		IRVersion: inference.Version,
		Alias:     "reasoning.balanced",
		Messages: []inference.Message{
			{Role: inference.RoleUser, Parts: []inference.Part{textPart("hello", taint.UserTrusted)}},
		},
		RunID:  id.MustNew(id.Run),
		StepID: id.MustNew(id.RunStep),
	}
}

func TestValidRequestPasses(t *testing.T) {
	t.Parallel()
	if err := baseRequest().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRequestRequiresAttribution(t *testing.T) {
	t.Parallel()
	// An unattributable model call cannot be budgeted, audited, or joined to a Verify outcome
	// (OBR-1), so the identifiers are required rather than optional.
	noRun := baseRequest()
	noRun.RunID = ""
	if err := noRun.Validate(); err == nil {
		t.Error("expected an error for a request with no run identifier")
	}

	noStep := baseRequest()
	noStep.StepID = ""
	if err := noStep.Validate(); err == nil {
		t.Error("expected an error for a request with no step identifier")
	}

	wrongEntity := baseRequest()
	wrongEntity.StepID = id.MustNew(id.Approval)
	if err := wrongEntity.Validate(); err == nil {
		t.Error("expected an error when step_id carries the wrong entity prefix")
	}
}

func TestRequestRejectsAnUnsupportedIRVersion(t *testing.T) {
	t.Parallel()
	r := baseRequest()
	r.IRVersion = 99
	if err := r.Validate(); !modberr.Is(err, modberr.CodeUnsupportedVersion) {
		t.Fatalf("error = %v, want MODBIT_UNSUPPORTED_VERSION", err)
	}
}

// The union must be exactly one payload. A part carrying both text and a tool call would let an
// adapter pick whichever it recognizes and drop the other.
func TestPartUnionIsExclusiveAndTyped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		part inference.Part
	}{
		{"two payloads", inference.Part{
			Kind: inference.PartText, Text: "hi",
			ToolCall: &inference.ToolCall{ID: "1", Name: "read", Input: json.RawMessage(`{}`)},
		}},
		{"text kind with no text", inference.Part{Kind: inference.PartText}},
		{"image kind with no media", inference.Part{Kind: inference.PartImage}},
		{"tool call kind with no call", inference.Part{Kind: inference.PartToolCall}},
		{"tool call with no input", inference.Part{
			Kind: inference.PartToolCall, ToolCall: &inference.ToolCall{ID: "1", Name: "read"},
		}},
		{"tool call with invalid json input", inference.Part{
			Kind:     inference.PartToolCall,
			ToolCall: &inference.ToolCall{ID: "1", Name: "read", Input: json.RawMessage(`{bad`)},
		}},
		{"tool result with no call id", inference.Part{
			Kind: inference.PartToolResult, ToolResult: &inference.ToolResult{},
		}},
		{"reasoning kind with no reasoning", inference.Part{Kind: inference.PartReasoning}},
		{"refusal kind with no text", inference.Part{Kind: inference.PartRefusal}},
		{"unknown kind", inference.Part{Kind: "telepathy", Text: "hi"}},
		{"unregistered provenance", inference.Part{
			Kind: inference.PartText, Text: "hi", Provenance: taint.Class(200),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.part.Validate(); err == nil {
				t.Fatalf("Validate accepted a malformed part: %+v", tc.part)
			}
		})
	}
}

func TestMediaPartsRequireAVerifiableReference(t *testing.T) {
	t.Parallel()
	good := mediaPart(inference.PartImage, "image/png")
	if err := good.Validate(); err != nil {
		t.Fatalf("a well-formed media part was rejected: %v", err)
	}

	noDigest := good
	noDigest.Media = &inference.MediaRef{ObjectRef: good.Media.ObjectRef, MediaType: "image/png"}
	if err := noDigest.Validate(); err == nil {
		t.Error("a media reference without a digest is unverifiable and must be rejected")
	}

	wrongEntity := good
	wrongEntity.Media = &inference.MediaRef{
		ObjectRef: id.MustNew(id.Run), MediaType: "image/png",
		Digest: "sha256:" + strings.Repeat("a", 64),
	}
	if err := wrongEntity.Validate(); err == nil {
		t.Error("a media reference must be an obj_ identifier")
	}
}

// Tool results carry untrusted output; placing them in an assistant message would let a provider
// read them as the model's own reasoning.
func TestToolPartsAreConfinedToTheirRoles(t *testing.T) {
	t.Parallel()
	result := inference.Part{
		Kind: inference.PartToolResult,
		ToolResult: &inference.ToolResult{
			CallID: "call-1",
			Parts:  []inference.Part{textPart("output", taint.ToolResult)},
		},
		Provenance: taint.ToolResult,
	}
	if err := (inference.Message{Role: inference.RoleAssistant, Parts: []inference.Part{result}}).Validate(); err == nil {
		t.Error("a tool result must not be accepted in an assistant message")
	}
	if err := (inference.Message{Role: inference.RoleTool, Parts: []inference.Part{result}}).Validate(); err != nil {
		t.Errorf("a tool result in a tool message was rejected: %v", err)
	}

	call := inference.Part{
		Kind:       inference.PartToolCall,
		ToolCall:   &inference.ToolCall{ID: "call-1", Name: "read", Input: json.RawMessage(`{}`)},
		Provenance: taint.Generated,
	}
	if err := (inference.Message{Role: inference.RoleUser, Parts: []inference.Part{call}}).Validate(); err == nil {
		t.Error("a tool call must not be accepted in a user message")
	}
}

func TestToolResultsMayNotNestToolParts(t *testing.T) {
	t.Parallel()
	nested := inference.Part{
		Kind: inference.PartToolResult,
		ToolResult: &inference.ToolResult{
			CallID: "call-1",
			Parts: []inference.Part{{
				Kind:       inference.PartToolCall,
				ToolCall:   &inference.ToolCall{ID: "x", Name: "read", Input: json.RawMessage(`{}`)},
				Provenance: taint.ToolResult,
			}},
		},
		Provenance: taint.ToolResult,
	}
	if err := nested.Validate(); err == nil {
		t.Fatal("a tool result must not nest a tool call")
	}
}

func TestToolReferencesMustFormMatchedPairs(t *testing.T) {
	t.Parallel()
	tool := inference.ToolDefinition{Name: "read", InputSchema: json.RawMessage(`{"type":"object"}`)}
	call := func(callID string) inference.Part {
		return inference.Part{
			Kind:       inference.PartToolCall,
			ToolCall:   &inference.ToolCall{ID: callID, Name: "read", Input: json.RawMessage(`{}`)},
			Provenance: taint.Generated,
		}
	}
	result := func(callID string) inference.Part {
		return inference.Part{
			Kind: inference.PartToolResult,
			ToolResult: &inference.ToolResult{
				CallID: callID, Parts: []inference.Part{textPart("out", taint.ToolResult)},
			},
			Provenance: taint.ToolResult,
		}
	}

	t.Run("matched pair", func(t *testing.T) {
		r := baseRequest()
		r.Tools = []inference.ToolDefinition{tool}
		r.Messages = append(r.Messages,
			inference.Message{Role: inference.RoleAssistant, Parts: []inference.Part{call("c1")}},
			inference.Message{Role: inference.RoleTool, Parts: []inference.Part{result("c1")}},
		)
		if err := r.Validate(); err != nil {
			t.Fatalf("a matched call and result were rejected: %v", err)
		}
	})

	t.Run("dangling result", func(t *testing.T) {
		r := baseRequest()
		r.Tools = []inference.ToolDefinition{tool}
		r.Messages = append(r.Messages,
			inference.Message{Role: inference.RoleTool, Parts: []inference.Part{result("never-called")}},
		)
		if err := r.Validate(); err == nil {
			t.Fatal("a result referencing no preceding call must be rejected")
		}
	})

	t.Run("undeclared tool", func(t *testing.T) {
		r := baseRequest()
		r.Messages = append(r.Messages,
			inference.Message{Role: inference.RoleAssistant, Parts: []inference.Part{call("c1")}},
		)
		if err := r.Validate(); err == nil {
			t.Fatal("a call to an undeclared tool must be rejected")
		}
	})

	t.Run("duplicate call id", func(t *testing.T) {
		r := baseRequest()
		r.Tools = []inference.ToolDefinition{tool}
		r.Messages = append(r.Messages,
			inference.Message{Role: inference.RoleAssistant, Parts: []inference.Part{call("c1"), call("c1")}},
		)
		if err := r.Validate(); err == nil {
			t.Fatal("a duplicate tool call id must be rejected")
		}
	})

	t.Run("tool_choice naming an undeclared tool", func(t *testing.T) {
		r := baseRequest()
		r.Tools = []inference.ToolDefinition{tool}
		r.ToolChoice = &inference.ToolChoice{Mode: inference.ToolChoiceSpecific, Name: "write"}
		if err := r.Validate(); err == nil {
			t.Fatal("tool_choice must name a declared tool")
		}
	})

	t.Run("duplicate tool declaration", func(t *testing.T) {
		r := baseRequest()
		r.Tools = []inference.ToolDefinition{tool, tool}
		if err := r.Validate(); err == nil {
			t.Fatal("a tool declared twice must be rejected")
		}
	})
}

// TNT-2 at the prompt boundary: a request's taint is the highest-risk class anywhere in it,
// including inside a nested tool result.
func TestRequestTaintPropagatesFromNestedContent(t *testing.T) {
	t.Parallel()
	r := baseRequest()
	r.Tools = []inference.ToolDefinition{{Name: "fetch", InputSchema: json.RawMessage(`{}`)}}
	r.Messages = append(r.Messages,
		inference.Message{Role: inference.RoleAssistant, Parts: []inference.Part{{
			Kind:       inference.PartToolCall,
			ToolCall:   &inference.ToolCall{ID: "c1", Name: "fetch", Input: json.RawMessage(`{}`)},
			Provenance: taint.Generated,
		}}},
		inference.Message{Role: inference.RoleTool, Parts: []inference.Part{{
			Kind: inference.PartToolResult,
			ToolResult: &inference.ToolResult{
				CallID: "c1",
				// The tool wrapper is tool_result, but the page it fetched is web.
				Parts: []inference.Part{textPart("fetched page body", taint.Web)},
			},
			Provenance: taint.ToolResult,
		}}},
	)
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := r.Taint(); got != taint.Web {
		t.Errorf("request taint = %v, want web (inherited from the nested part)", got)
	}
}

func TestSystemAndDeveloperInstructionsMustBeText(t *testing.T) {
	t.Parallel()
	r := baseRequest()
	r.System = []inference.Part{mediaPart(inference.PartImage, "image/png")}
	if err := r.Validate(); err == nil {
		t.Fatal("instructions must be text parts")
	}
}

func TestResponseValidation(t *testing.T) {
	t.Parallel()
	valid := inference.Response{
		IRVersion:     inference.Version,
		Alias:         "reasoning.balanced",
		ModelRevision: "rev-2026-07-01",
		Parts:         []inference.Part{textPart("answer", taint.Generated)},
		FinishReason:  inference.FinishEndTurn,
		Usage:         inference.Usage{InputTokens: 10, OutputTokens: 5},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid response was rejected: %v", err)
	}

	t.Run("revision is required for drift detection", func(t *testing.T) {
		r := valid
		r.ModelRevision = ""
		if err := r.Validate(); err == nil {
			t.Error("expected an error for a response with no model revision")
		}
	})

	t.Run("model output cannot claim trusted provenance", func(t *testing.T) {
		r := valid
		r.Parts = []inference.Part{textPart("answer", taint.UserTrusted)}
		if err := r.Validate(); err == nil {
			t.Error("a response part claiming user_trusted would launder model output")
		}
	})

	t.Run("tool_use finish requires a tool call", func(t *testing.T) {
		r := valid
		r.FinishReason = inference.FinishToolUse
		if err := r.Validate(); err == nil {
			t.Error("a tool_use finish with no tool call is unactionable and must be rejected")
		}
	})

	t.Run("unknown finish reason", func(t *testing.T) {
		r := valid
		r.FinishReason = "gave_up"
		if err := r.Validate(); err == nil {
			t.Error("expected an error for an unknown finish reason")
		}
	})

	t.Run("negative usage", func(t *testing.T) {
		r := valid
		r.Usage = inference.Usage{InputTokens: -1}
		if err := r.Validate(); err == nil {
			t.Error("expected an error for negative usage")
		}
	})
}

func TestResponseAccessors(t *testing.T) {
	t.Parallel()
	r := inference.Response{
		IRVersion:     inference.Version,
		ModelRevision: "rev-1",
		FinishReason:  inference.FinishToolUse,
		Parts: []inference.Part{
			textPart("thinking about it. ", taint.Generated),
			{
				Kind:       inference.PartToolCall,
				ToolCall:   &inference.ToolCall{ID: "c1", Name: "read", Input: json.RawMessage(`{"path":"a"}`)},
				Provenance: taint.Generated,
			},
			textPart("done.", taint.Generated),
		},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := r.Text(); got != "thinking about it. done." {
		t.Errorf("Text = %q", got)
	}
	calls := r.ToolCalls()
	if len(calls) != 1 || calls[0].Name != "read" {
		t.Errorf("ToolCalls = %+v", calls)
	}
}

func TestJSONRoundTripPreservesTheUnion(t *testing.T) {
	t.Parallel()
	original := baseRequest()
	original.Tools = []inference.ToolDefinition{{Name: "read", InputSchema: json.RawMessage(`{"type":"object"}`)}}
	original.Messages = append(original.Messages,
		inference.Message{Role: inference.RoleAssistant, Parts: []inference.Part{{
			Kind:       inference.PartToolCall,
			ToolCall:   &inference.ToolCall{ID: "c1", Name: "read", Input: json.RawMessage(`{"path":"a"}`)},
			Provenance: taint.Generated,
		}}},
		inference.Message{Role: inference.RoleTool, Parts: []inference.Part{{
			Kind: inference.PartToolResult,
			ToolResult: &inference.ToolResult{
				CallID: "c1", Parts: []inference.Part{textPart("contents", taint.RepositoryUntrusted)},
			},
			Provenance: taint.ToolResult,
		}}},
	)

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var restored inference.Request
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatalf("round-tripped request failed validation: %v", err)
	}
	if restored.Taint() != original.Taint() {
		t.Errorf("round trip changed taint: %v -> %v", original.Taint(), restored.Taint())
	}
	// Provenance must survive as a name, not an integer, so a hand-inspected payload is readable
	// and a class renumbering cannot silently reinterpret stored requests.
	if !strings.Contains(string(encoded), `"provenance":"repository_untrusted"`) {
		t.Errorf("provenance is not serialized by name: %s", encoded)
	}
}
