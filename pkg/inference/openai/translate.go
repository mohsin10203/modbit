package openai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// MediaResolver fetches the bytes behind a media reference.
//
// O8. The canonical IR carries references and never bytes (MOD-A01 decision 2), because a
// representation that could hold inline base64 makes "prompt bodies are metadata-only" unenforceable
// the first time a request is traced. But an OpenAI-compatible provider needs the bytes, so
// somebody has to fetch them — and it must be an explicit collaborator rather than something the
// adapter does for itself. Without a resolver a media part is refused, not dropped: silently sending
// a prompt with the image missing produces a confident answer to a question nobody asked.
type MediaResolver interface {
	// Resolve returns the payload for a reference. Implementations must verify the digest.
	Resolve(ctx context.Context, ref inference.MediaRef) ([]byte, error)
}

// translateRequest converts canonical IR into a chat-completions request.
//
// Losses are accumulated and returned rather than logged (ADP-3): the gateway records them on
// immutable model-call metadata, so a Verify workflow can refuse to treat a completion as evidence
// when a loss touched the property it was meant to prove.
func (a *Adapter) translateRequest(ctx context.Context, req inference.Request, model inference.Capabilities, stream bool) (chatRequest, []inference.Loss, error) {
	var losses []inference.Loss
	out := chatRequest{
		Model:       model.ModelID,
		MaxTokens:   req.MaxOutputTokens,
		Temperature: req.Temperature,
		Stop:        req.StopSequences,
		Stream:      stream,
	}
	if stream {
		out.StreamOptions = &streamOptions{IncludeUsage: true}
	}

	// System and developer instructions become system messages. The protocol has no developer role,
	// so merging them is a reshape rather than a clean mapping and is declared as one — a reader of
	// the metadata must be able to tell that the two tiers were flattened.
	if instructions := append(append([]inference.Part{}, req.System...), req.Developer...); len(instructions) > 0 {
		text, partLosses, err := a.flattenParts(ctx, instructions, model, "instructions")
		if err != nil {
			return chatRequest{}, nil, err
		}
		losses = append(losses, partLosses...)
		if text != "" {
			out.Messages = append(out.Messages, chatMessage{Role: "system", Content: text})
		}
		if len(req.Developer) > 0 {
			losses = append(losses, inference.Loss{
				Kind:    inference.LossReshaped,
				Feature: "messages.developer",
				Detail:  "developer instructions merged into the system message; the protocol has no developer role",
			})
		}
	}

	for _, msg := range req.Messages {
		converted, msgLosses, err := a.translateMessage(ctx, msg, model)
		if err != nil {
			return chatRequest{}, nil, err
		}
		losses = append(losses, msgLosses...)
		out.Messages = append(out.Messages, converted...)
	}

	if len(req.Tools) > 0 {
		if !model.SupportsTools {
			// O4. Unsupported is a refusal, not a loss: running a tool-shaped request against a model
			// that cannot call tools produces prose describing what it would have done, which a
			// harness cannot distinguish from a real answer (MOD-A01 decision 4).
			return chatRequest{}, nil, modberr.New(modberr.CodeCapabilityUnavailable,
				"model does not support tools").WithDetail("capability", "tools")
		}
		for _, tool := range req.Tools {
			out.Tools = append(out.Tools, chatTool{
				Type: "function",
				Function: chatFunction{
					Name:        tool.Name,
					Description: tool.Description,
					Parameters:  tool.InputSchema,
				},
			})
		}
		if len(req.Tools) > 1 && !model.SupportsParallelToolCall {
			no := false
			out.ParallelToolCall = &no
		}
	}

	if req.ToolChoice != nil {
		choice, loss := translateToolChoice(*req.ToolChoice)
		out.ToolChoice = choice
		if loss != nil {
			losses = append(losses, *loss)
		}
	}

	if req.StructuredOutput != nil {
		format, loss, err := translateStructuredOutput(*req.StructuredOutput, model)
		if err != nil {
			return chatRequest{}, nil, err
		}
		out.ResponseFormat = format
		if loss != nil {
			losses = append(losses, *loss)
		}
	}

	if req.Reasoning != "" && req.Reasoning != inference.ReasoningNone {
		if supportsEffort(model, req.Reasoning) {
			out.ReasoningEffort = string(req.Reasoning)
		} else if len(model.ReasoningEfforts) == 0 {
			losses = append(losses, inference.Loss{
				Kind:    inference.LossUnsupported,
				Feature: "reasoning",
				Detail:  "model exposes no reasoning effort control; the request proceeds without one",
			})
		} else {
			// Downgrading to the nearest supported effort beats refusing: the completion is still
			// useful, and the loss records that it was not the effort asked for.
			nearest := model.ReasoningEfforts[len(model.ReasoningEfforts)-1]
			out.ReasoningEffort = string(nearest)
			losses = append(losses, inference.Loss{
				Kind:    inference.LossDowngraded,
				Feature: "reasoning",
				Detail:  "requested effort " + string(req.Reasoning) + " downgraded to " + string(nearest),
			})
		}
	}

	return out, losses, nil
}

func supportsEffort(model inference.Capabilities, want inference.ReasoningEffort) bool {
	for _, e := range model.ReasoningEfforts {
		if e == want {
			return true
		}
	}
	return false
}

func translateToolChoice(choice inference.ToolChoice) (any, *inference.Loss) {
	switch choice.Mode {
	case inference.ToolChoiceAuto:
		return "auto", nil
	case inference.ToolChoiceNone:
		return "none", nil
	case inference.ToolChoiceRequired:
		return "required", nil
	case inference.ToolChoiceSpecific:
		return map[string]any{
			"type":     "function",
			"function": map[string]string{"name": choice.Name},
		}, nil
	default:
		return "auto", &inference.Loss{
			Kind:    inference.LossReshaped,
			Feature: "tool_choice",
			Detail:  "unrecognized tool-choice mode sent as auto",
		}
	}
}

func translateStructuredOutput(so inference.StructuredOutput, model inference.Capabilities) (*responseFormat, *inference.Loss, error) {
	if !model.SupportsStructuredOutput {
		return nil, nil, modberr.New(modberr.CodeCapabilityUnavailable,
			"model does not support structured output").WithDetail("capability", "structured_output")
	}
	name := so.SchemaID
	if name == "" {
		name = "response"
	}
	// A provider-side schema name must be a bare identifier. Sanitizing rather than refusing keeps a
	// dotted contract id like "review.finding.v2" usable.
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, name)

	format := &responseFormat{
		Type:       "json_schema",
		JSONSchema: &jsonSchema{Name: name, Schema: so.Schema, Strict: so.Strict},
	}
	if so.Strict && !model.SupportsStrictSchema {
		// O4. Best-effort shaping is a real downgrade: the response may not validate, and a caller
		// treating it as guaranteed would parse it without checking.
		format.JSONSchema.Strict = false
		return format, &inference.Loss{
			Kind:    inference.LossDowngraded,
			Feature: "structured_output.strict",
			Detail:  "provider shapes output best-effort; strict schema enforcement is unavailable",
		}, nil
	}
	return format, nil, nil
}

// translateMessage converts one canonical message. A tool-result message becomes one wire message
// per result, because the protocol carries a single tool_call_id per message.
func (a *Adapter) translateMessage(ctx context.Context, msg inference.Message, model inference.Capabilities) ([]chatMessage, []inference.Loss, error) {
	var (
		out    []chatMessage
		losses []inference.Loss
	)

	if msg.Role == inference.RoleTool {
		for _, part := range msg.Parts {
			if part.Kind != inference.PartToolResult || part.ToolResult == nil {
				continue
			}
			text, partLosses, err := a.flattenParts(ctx, part.ToolResult.Parts, model, "tool_result")
			if err != nil {
				return nil, nil, err
			}
			losses = append(losses, partLosses...)
			out = append(out, chatMessage{
				Role:       "tool",
				ToolCallID: part.ToolResult.CallID,
				Content:    text,
			})
		}
		return out, losses, nil
	}

	role := string(msg.Role)
	if msg.Role == inference.RoleDeveloper {
		role = "system"
	}

	var (
		content   []contentPart
		toolCalls []chatToolCall
		textOnly  = true
	)
	for _, part := range msg.Parts {
		switch part.Kind {
		case inference.PartText:
			content = append(content, contentPart{Type: "text", Text: part.Text})

		case inference.PartRefusal:
			// A refusal replayed to the provider is prose; keeping it as structured data has no wire
			// representation, so the reshape is declared.
			content = append(content, contentPart{Type: "text", Text: part.Refusal})
			losses = append(losses, inference.Loss{
				Kind:    inference.LossReshaped,
				Feature: "parts.refusal",
				Detail:  "refusal replayed as text; the protocol has no refusal content type",
			})

		case inference.PartReasoning:
			// Reasoning is not replayed. Providers reject or ignore prior reasoning blocks, and
			// sending them risks presenting model-authored analysis as user intent.
			losses = append(losses, inference.Loss{
				Kind:    inference.LossUnsupported,
				Feature: "parts.reasoning",
				Detail:  "prior reasoning is not replayed to the provider",
			})

		case inference.PartToolCall:
			if part.ToolCall == nil {
				continue
			}
			// O7. Id, name, and arguments all survive; the gateway pairs calls with results on the id.
			toolCalls = append(toolCalls, chatToolCall{
				ID:   part.ToolCall.ID,
				Type: "function",
				Function: chatFunctionCall{
					Name:      part.ToolCall.Name,
					Arguments: string(part.ToolCall.Input),
				},
			})

		case inference.PartImage, inference.PartAudio, inference.PartFile:
			encoded, loss, err := a.encodeMedia(ctx, part, model)
			if err != nil {
				return nil, nil, err
			}
			if loss != nil {
				losses = append(losses, *loss)
				continue
			}
			content = append(content, *encoded)
			textOnly = false

		case inference.PartToolResult:
			return nil, nil, modberr.New(modberr.CodeInvalidArgument,
				"a tool result belongs to a tool-role message").WithDetail("field", "parts")
		}
	}

	if len(content) == 0 && len(toolCalls) == 0 {
		return out, losses, nil
	}

	message := chatMessage{Role: role, ToolCalls: toolCalls}
	switch {
	case len(content) == 0:
		// An assistant message that only requests tools carries no content.
	case textOnly:
		// Several local implementations reject the array form for plain text, so a text-only message
		// sends a string. This is the difference between working against Ollama and not.
		var sb strings.Builder
		for _, c := range content {
			sb.WriteString(c.Text)
		}
		message.Content = sb.String()
	default:
		message.Content = content
	}
	out = append(out, message)
	return out, losses, nil
}

// encodeMedia turns a media part into a data URL, or returns a Loss when the model cannot take it.
func (a *Adapter) encodeMedia(ctx context.Context, part inference.Part, model inference.Capabilities) (*contentPart, *inference.Loss, error) {
	supported := map[inference.PartKind]bool{
		inference.PartImage: model.SupportsVision,
		inference.PartAudio: model.SupportsAudio,
		inference.PartFile:  model.SupportsFiles,
	}
	if !supported[part.Kind] {
		// O4. A refusal, not a Loss — MOD-A01 decision 4's "unsupported" side.
		//
		// This was a declared Loss until the shared conformance suite refused it, and the suite was
		// right. Omitting a modality is not a downgrade of the answer, it is the removal of the
		// question: a user asking what is wrong in a screenshot gets a fluent answer about the text
		// that accompanied it, and the completion looks entirely successful. The Loss would be
		// recorded truthfully and read by nobody in time.
		//
		// Routing should never send an image to a model without vision, so reaching here means
		// something upstream is already wrong. That is exactly when the adapter has to hold the line
		// rather than paper over it (ADP-5.content_types).
		return nil, nil, modberr.Newf(modberr.CodeCapabilityUnavailable,
			"model does not accept %s content", part.Kind).
			WithDetail("capability", string(part.Kind))
	}
	if part.Media == nil {
		return nil, nil, modberr.New(modberr.CodeInvalidArgument,
			"a media part requires a reference").WithDetail("field", "media")
	}
	if a.media == nil {
		// O8. Refusing beats dropping: a prompt sent without its image gets a confident answer to a
		// question nobody asked, and nothing downstream can tell.
		return nil, nil, modberr.New(modberr.CodeCapabilityUnavailable,
			"media content requires a resolver; the adapter was built without one").
			WithDetail("capability", "media")
	}
	payload, err := a.media.Resolve(ctx, *part.Media)
	if err != nil {
		return nil, nil, modberr.Wrap(err, modberr.CodeUnavailable, "media reference could not be resolved")
	}
	mediaType := part.Media.MediaType
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	return &contentPart{
		Type:     "image_url",
		ImageURL: &imageURL{URL: "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(payload)},
	}, nil, nil
}

// flattenParts renders parts as plain text for the positions the protocol only accepts text in.
func (a *Adapter) flattenParts(ctx context.Context, parts []inference.Part, model inference.Capabilities, feature string) (string, []inference.Loss, error) {
	var (
		sb     strings.Builder
		losses []inference.Loss
	)
	for _, part := range parts {
		switch part.Kind {
		case inference.PartText:
			sb.WriteString(part.Text)
		case inference.PartRefusal:
			sb.WriteString(part.Refusal)
		default:
			losses = append(losses, inference.Loss{
				Kind:    inference.LossUnsupported,
				Feature: feature + "." + string(part.Kind),
				Detail:  "only text is representable in this position",
			})
		}
	}
	return sb.String(), losses, nil
}

// translateResponse converts a chat-completions response back into canonical IR.
func translateResponse(req inference.Request, model inference.Capabilities, raw chatResponse, losses []inference.Loss) (inference.Response, error) {
	if len(raw.Choices) == 0 {
		return inference.Response{}, modberr.New(modberr.CodeProviderUnavailable,
			"provider returned no choices")
	}
	choice := raw.Choices[0]
	message := choice.assistantMessage()
	if message == nil {
		return inference.Response{}, modberr.New(modberr.CodeProviderUnavailable,
			"provider returned a choice with no message")
	}

	var parts []inference.Part
	if text := message.text(); text != "" {
		parts = append(parts, inference.Part{
			Kind: inference.PartText, Text: text, Provenance: taint.Generated,
		})
	}
	for _, call := range message.ToolCalls {
		input := json.RawMessage(call.Function.Arguments)
		if len(input) == 0 {
			// An empty argument string is not valid JSON, and a downstream validator would reject
			// the whole call rather than reporting an empty object.
			input = json.RawMessage("{}")
		}
		parts = append(parts, inference.Part{
			Kind:       inference.PartToolCall,
			ToolCall:   &inference.ToolCall{ID: call.ID, Name: call.Function.Name, Input: input},
			Provenance: taint.Generated,
		})
	}
	if len(parts) == 0 {
		// A completion with neither text nor a tool call is not an empty answer, it is a protocol
		// surprise. Returning it as a valid empty response would let it pass as a real one.
		return inference.Response{}, modberr.New(modberr.CodeProviderUnavailable,
			"provider returned a completion with no content")
	}

	// O10. The revision comes from what answered, not from what was asked for. Their divergence is
	// what makes a silent provider model change detectable (MOD-6).
	revision := raw.Model
	if revision == "" {
		revision = model.Revision
		losses = append(losses, inference.Loss{
			Kind:    inference.LossUnsupported,
			Feature: "model_revision",
			Detail:  "provider did not report the serving model; the declared revision was recorded",
		})
	}

	return inference.Response{
		IRVersion:     req.IRVersion,
		Alias:         req.Alias,
		ModelRevision: revision,
		Parts:         parts,
		FinishReason:  translateFinishReason(choice.FinishReason, message),
		Usage:         translateUsage(raw.Usage),
		Losses:        losses,
	}, nil
}

func translateFinishReason(reason string, message *chatMessage) inference.FinishReason {
	switch reason {
	case "stop":
		return inference.FinishEndTurn
	case "length":
		return inference.FinishMaxTokens
	case "tool_calls", "function_call":
		return inference.FinishToolUse
	case "content_filter":
		return inference.FinishContentFilter
	case "":
		// Several local implementations omit the field. Inferring from the payload beats reporting
		// an error for a completion that plainly succeeded.
		if message != nil && len(message.ToolCalls) > 0 {
			return inference.FinishToolUse
		}
		return inference.FinishEndTurn
	default:
		return inference.FinishEndTurn
	}
}

func translateUsage(u *chatUsage) inference.Usage {
	if u == nil {
		return inference.Usage{}
	}
	usage := inference.Usage{
		InputTokens:  u.PromptTokens,
		OutputTokens: u.CompletionTokens,
	}
	if u.PromptDetails != nil {
		// The protocol reports cached tokens as a subset of prompt_tokens, while the canonical Usage
		// keeps them separate and sums both. Subtracting here is what stops a cached call being
		// billed twice for the same tokens.
		usage.CachedInputTokens = u.PromptDetails.CachedTokens
		usage.InputTokens -= u.PromptDetails.CachedTokens
		if usage.InputTokens < 0 {
			usage.InputTokens = 0
		}
	}
	if u.CompletionDetails != nil {
		usage.ReasoningTokens = u.CompletionDetails.ReasoningTokens
		usage.OutputTokens -= u.CompletionDetails.ReasoningTokens
		if usage.OutputTokens < 0 {
			usage.OutputTokens = 0
		}
	}
	return usage
}
