// Package openai is an adapter for the OpenAI chat-completions protocol.
//
// One adapter covers two cases that matter to Modbit: hosted providers speaking that protocol, and
// the local endpoints — Ollama, vLLM, LM Studio — that reimplement it. They differ in what they
// support, not in how they are addressed, and capability records already carry the difference
// (§14.2), so a second adapter would only duplicate the translation.
//
// # Invariants (O1–O10)
//
// One test each in openai_test.go. A test without an O-number, or an O-number without a test, is a
// gap.
//
//	O1  The adapter never builds its own HTTP client; egress control belongs to the caller's transport.
//	O2  A credential reaches the Authorization header and nothing else — never a URL, error, or log.
//	O3  Every provider failure maps to a stable Modbit code, carrying no upstream body content.
//	O4  A capability gap is a refusal or a declared Loss, never a silent drop.
//	O5  A stream closes exactly once and carries exactly one terminal event.
//	O6  Cancellation abandons the request rather than draining it.
//	O7  A tool call round-trips: id, name, and arguments survive both translations.
//	O8  Media is never inlined without a resolver; without one the part is refused.
//	O9  A token count says whether it is exact or estimated.
//	O10 The observed model revision comes from the response, never from the request.
package openai

import "encoding/json"

// The wire types below are the OpenAI chat-completions shapes. They are deliberately private: the
// canonical IR is the only thing that crosses this package's boundary, so a provider's field naming
// cannot leak into the harness (ADP-1).

type chatRequest struct {
	Model            string          `json:"model"`
	Messages         []chatMessage   `json:"messages"`
	MaxTokens        int             `json:"max_completion_tokens,omitempty"`
	Temperature      *float64        `json:"temperature,omitempty"`
	Stop             []string        `json:"stop,omitempty"`
	Stream           bool            `json:"stream,omitempty"`
	StreamOptions    *streamOptions  `json:"stream_options,omitempty"`
	Tools            []chatTool      `json:"tools,omitempty"`
	ToolChoice       any             `json:"tool_choice,omitempty"`
	ResponseFormat   *responseFormat `json:"response_format,omitempty"`
	ReasoningEffort  string          `json:"reasoning_effort,omitempty"`
	ParallelToolCall *bool           `json:"parallel_tool_calls,omitempty"`
}

// streamOptions asks for a usage block on the final chunk. Without it most implementations stream
// deltas and never report token counts, which would leave every streamed call unbillable.
type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content,omitempty"`
	// ToolCalls is set on an assistant message replaying a previous tool request.
	ToolCalls []chatToolCall `json:"tool_calls,omitempty"`
	// ToolCallID is set on a tool-role message carrying a result.
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// contentPart is the multimodal content shape. A message with only text sends a plain string
// instead, because several local implementations reject the array form.
type contentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *imageURL `json:"image_url,omitempty"`
}

type imageURL struct {
	URL string `json:"url"`
}

type chatTool struct {
	Type     string       `json:"type"`
	Function chatFunction `json:"function"`
}

type chatFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      bool            `json:"strict,omitempty"`
}

type chatToolCall struct {
	Index    *int             `json:"index,omitempty"`
	ID       string           `json:"id,omitempty"`
	Type     string           `json:"type,omitempty"`
	Function chatFunctionCall `json:"function"`
}

type chatFunctionCall struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type responseFormat struct {
	Type       string      `json:"type"`
	JSONSchema *jsonSchema `json:"json_schema,omitempty"`
}

type jsonSchema struct {
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
	Strict bool            `json:"strict"`
}

type chatResponse struct {
	ID      string       `json:"id"`
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	Usage   *chatUsage   `json:"usage"`
	Error   *chatError   `json:"error"`
}

type chatChoice struct {
	Index        int          `json:"index"`
	Message      *chatMessage `json:"message"`
	Delta        *chatDelta   `json:"delta"`
	FinishReason string       `json:"finish_reason"`
}

type chatDelta struct {
	Role      string         `json:"role,omitempty"`
	Content   string         `json:"content,omitempty"`
	Reasoning string         `json:"reasoning_content,omitempty"`
	Refusal   string         `json:"refusal,omitempty"`
	ToolCalls []chatToolCall `json:"tool_calls,omitempty"`
}

type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
	PromptDetails    *struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionDetails *struct {
		ReasoningTokens int `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

type chatError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    any    `json:"code"`
}

// assistantMessage extracts the message from a non-streaming choice, tolerating implementations that
// return the delta shape for a non-streamed call.
func (c chatChoice) assistantMessage() *chatMessage {
	if c.Message != nil {
		return c.Message
	}
	if c.Delta == nil {
		return nil
	}
	return &chatMessage{Role: c.Delta.Role, Content: c.Delta.Content, ToolCalls: c.Delta.ToolCalls}
}

// text flattens a content field, which may be a string or an array of typed parts.
func (m chatMessage) text() string {
	switch v := m.Content.(type) {
	case string:
		return v
	case []any:
		var out string
		for _, item := range v {
			part, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if s, ok := part["text"].(string); ok {
				out += s
			}
		}
		return out
	default:
		return ""
	}
}
