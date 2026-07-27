package inference

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/modberr"
)

// LossKind classifies a translation the adapter could not perform exactly.
type LossKind string

const (
	// LossUnsupported means the capability was requested and the provider cannot do it at all.
	LossUnsupported LossKind = "unsupported"
	// LossDowngraded means the capability was honoured in a weaker form, such as best-effort
	// structured output where strict was requested.
	LossDowngraded LossKind = "downgraded"
	// LossTruncated means content was dropped to fit a provider limit.
	LossTruncated LossKind = "truncated"
	// LossReshaped means the content survived but its structure changed, such as merging
	// consecutive system parts a provider accepts only once.
	LossReshaped LossKind = "reshaped"
)

// Loss is a declared translation gap (ADP-3).
//
// A Loss is a returned value rather than a log line on purpose. The Model Gateway records it on the
// immutable model-call metadata, and a Verify workflow can refuse to treat a completion as evidence
// when a loss touched the property it was meant to prove. A gap written only to a log would be
// invisible to both.
type Loss struct {
	Kind LossKind `json:"kind"`
	// Feature names the IR feature affected, for example "structured_output.strict" or
	// "parts.image".
	Feature string `json:"feature"`
	// Detail is a short operator-facing explanation. It never contains prompt content.
	Detail string `json:"detail"`
}

func (l Loss) String() string { return fmt.Sprintf("%s: %s (%s)", l.Kind, l.Feature, l.Detail) }

// ToolSchemaDialect names the tool-schema flavour a provider accepts.
type ToolSchemaDialect string

const (
	DialectJSONSchemaDraft202012 ToolSchemaDialect = "json_schema_2020_12"
	DialectJSONSchemaDraft7      ToolSchemaDialect = "json_schema_draft_7"
	// DialectOpenAPI31Subset covers providers accepting only an OpenAPI-flavoured subset.
	DialectOpenAPI31Subset ToolSchemaDialect = "openapi_3_1_subset"
)

// SafetyFilterBehavior describes what a provider does when its safety filter triggers.
type SafetyFilterBehavior string

const (
	// SafetyRefusalPart means the provider returns a structured refusal the adapter maps to
	// PartRefusal.
	SafetyRefusalPart SafetyFilterBehavior = "refusal_part"
	// SafetyFinishReason means the provider signals it only through a finish reason.
	SafetyFinishReason SafetyFilterBehavior = "finish_reason"
	// SafetySilentTruncation means the provider truncates without a distinguishable signal. A model
	// with this behaviour cannot be used where a completion contract requires proof of completeness.
	SafetySilentTruncation SafetyFilterBehavior = "silent_truncation"
)

// Money is an amount in micro-units of a currency. Costs are integers so that accumulating a
// million call costs cannot drift, and the currency travels with the amount (R-ID-04).
type Money struct {
	Micros   int64  `json:"micros"`
	Currency string `json:"currency"`
}

// Pricing is per-million-token cost by token class.
type Pricing struct {
	InputPerMillion       Money `json:"input_per_million"`
	CachedInputPerMillion Money `json:"cached_input_per_million"`
	OutputPerMillion      Money `json:"output_per_million"`
	ReasoningPerMillion   Money `json:"reasoning_per_million"`
}

// Capabilities is the normalized model capability schema (PRD v5.1 §14.2).
//
// Every field the PRD enumerates is present, including the governance fields — residency,
// retention, training policy, customer-managed-key eligibility — because routing has to satisfy
// them inside the policy envelope, not merely record them afterwards.
type Capabilities struct {
	// ProviderID and ModelID identify the concrete route. Harness code must not branch on them
	// (ADP-2); they exist for routing, evidence, and drift detection.
	ProviderID string `json:"provider_id"`
	ModelID    string `json:"model_id"`
	// Revision is the provider's model revision, fingerprinted for OEV-1 drift detection.
	Revision    string    `json:"revision"`
	ReleaseDate time.Time `json:"release_date"`
	// Aliases lists the capability aliases this model can serve.
	Aliases []string `json:"aliases"`

	// Limits.
	MaxContextTokens int `json:"max_context_tokens"`
	MaxOutputTokens  int `json:"max_output_tokens"`

	// Modality and feature support.
	SupportsTools            bool              `json:"supports_tools"`
	SupportsParallelToolCall bool              `json:"supports_parallel_tool_calls"`
	ToolSchemaDialect        ToolSchemaDialect `json:"tool_schema_dialect"`
	SupportsStructuredOutput bool              `json:"supports_structured_output"`
	SupportsStrictSchema     bool              `json:"supports_strict_schema"`
	SupportsVision           bool              `json:"supports_vision"`
	SupportsAudio            bool              `json:"supports_audio"`
	SupportsFiles            bool              `json:"supports_files"`
	SupportsComputerUse      bool              `json:"supports_computer_use"`
	SupportsStreaming        bool              `json:"supports_streaming"`
	SupportsCancellation     bool              `json:"supports_cancellation"`
	// ReasoningEfforts lists the efforts the provider exposes. An empty list means no reasoning
	// control is available.
	ReasoningEfforts []ReasoningEffort `json:"reasoning_efforts"`
	// StreamEventKinds lists the delta kinds the provider emits, so the gateway can normalize
	// without probing.
	StreamEventKinds []string `json:"stream_event_kinds"`

	// Prompt caching.
	SupportsPromptCache bool          `json:"supports_prompt_cache"`
	PromptCacheTTL      time.Duration `json:"prompt_cache_ttl"`

	// Governance. These participate in routing because a route that violates them is not a
	// degraded route, it is a policy breach (MOD-1, INV-9).
	Regions                    []string `json:"regions"`
	ProviderRetentionDays      int      `json:"provider_retention_days"`
	TrainsOnCustomerData       bool     `json:"trains_on_customer_data"`
	CustomerManagedKeyEligible bool     `json:"customer_managed_key_eligible"`

	// Operational profile.
	RequestsPerMinute int           `json:"requests_per_minute"`
	TokensPerMinute   int           `json:"tokens_per_minute"`
	MaxConcurrency    int           `json:"max_concurrency"`
	TypicalLatency    time.Duration `json:"typical_latency"`
	// ReliabilityScore is a 0..1 availability estimate maintained from observed outcomes.
	ReliabilityScore float64 `json:"reliability_score"`

	Pricing              Pricing              `json:"pricing"`
	SafetyFilterBehavior SafetyFilterBehavior `json:"safety_filter_behavior"`
}

// Validate checks the capability record for internal consistency. A malformed record would let the
// gateway route to a model whose limits it cannot honour.
func (c Capabilities) Validate() error {
	bad := func(field, reason string) error {
		return modberr.Newf(modberr.CodeInvalidArgument, "model capabilities: %s", reason).
			WithDetail("field", field)
	}
	switch {
	case c.ProviderID == "":
		return bad("provider_id", "provider_id is required")
	case c.ModelID == "":
		return bad("model_id", "model_id is required")
	case c.Revision == "":
		return bad("revision", "revision is required for drift detection")
	case len(c.Aliases) == 0:
		return bad("aliases", "at least one capability alias is required")
	case c.MaxContextTokens <= 0:
		return bad("max_context_tokens", "max_context_tokens must be positive")
	case c.MaxOutputTokens <= 0:
		return bad("max_output_tokens", "max_output_tokens must be positive")
	case c.MaxOutputTokens > c.MaxContextTokens:
		return bad("max_output_tokens", "max_output_tokens cannot exceed max_context_tokens")
	case c.SupportsTools && c.ToolSchemaDialect == "":
		return bad("tool_schema_dialect", "a tool-capable model must declare its schema dialect")
	case c.SupportsStrictSchema && !c.SupportsStructuredOutput:
		return bad("supports_strict_schema", "strict schema requires structured-output support")
	case c.SupportsPromptCache && c.PromptCacheTTL <= 0:
		return bad("prompt_cache_ttl", "a cache-capable model must declare a positive TTL")
	case c.ReliabilityScore < 0 || c.ReliabilityScore > 1:
		return bad("reliability_score", "reliability_score must be between 0 and 1")
	case c.ProviderRetentionDays < 0:
		return bad("provider_retention_days", "retention cannot be negative")
	case c.SafetyFilterBehavior == "":
		return bad("safety_filter_behavior", "safety filter behaviour must be declared")
	}
	return nil
}

// ServesAlias reports whether this model can serve the capability alias.
func (c Capabilities) ServesAlias(alias string) bool {
	for _, a := range c.Aliases {
		if strings.EqualFold(a, alias) {
			return true
		}
	}
	return false
}

// SupportsReasoning reports whether the model exposes the requested effort.
func (c Capabilities) SupportsReasoning(effort ReasoningEffort) bool {
	if effort == "" || effort == ReasoningNone {
		return true
	}
	for _, e := range c.ReasoningEfforts {
		if e == effort {
			return true
		}
	}
	return false
}

// EstimateCost returns the cost of a usage record under this model's pricing.
//
// It rounds up so an estimate never understates spend: a budget check that rounds down would let a
// run creep past its cap one fractional token at a time.
func (c Capabilities) EstimateCost(u Usage) Money {
	currency := c.Pricing.InputPerMillion.Currency
	perMillion := func(tokens int, price Money) int64 {
		if tokens <= 0 || price.Micros <= 0 {
			return 0
		}
		product := int64(tokens) * price.Micros
		const million = 1_000_000
		if product%million == 0 {
			return product / million
		}
		return product/million + 1
	}
	total := perMillion(u.InputTokens, c.Pricing.InputPerMillion) +
		perMillion(u.CachedInputTokens, c.Pricing.CachedInputPerMillion) +
		perMillion(u.OutputTokens, c.Pricing.OutputPerMillion) +
		perMillion(u.ReasoningTokens, c.Pricing.ReasoningPerMillion)
	return Money{Micros: total, Currency: currency}
}

// Check reports whether the model can serve the request, and what would be lost if it did.
//
// The split matters. An `error` means the request must not be sent to this model: the result would
// be wrong, not merely weaker. A Loss means the request can proceed with a declared gap the gateway
// records and a Verify workflow can weigh. Collapsing the two would either block routes
// unnecessarily or let a silent downgrade pass as a clean completion.
func (c Capabilities) Check(r Request) ([]Loss, error) {
	unsupported := func(feature, detail string) error {
		return modberr.Newf(modberr.CodeNoEligibleRoute,
			"model cannot satisfy required capability %q: %s", feature, detail).
			WithDetail("required_capabilities", feature)
	}

	if !c.ServesAlias(r.Alias) {
		return nil, unsupported("alias", "model does not serve this capability alias")
	}
	if r.MaxOutputTokens > c.MaxOutputTokens {
		return nil, unsupported("max_output_tokens",
			fmt.Sprintf("requested %d, model supports %d", r.MaxOutputTokens, c.MaxOutputTokens))
	}

	var losses []Loss
	add := func(kind LossKind, feature, detail string) {
		losses = append(losses, Loss{Kind: kind, Feature: feature, Detail: detail})
	}

	if len(r.Tools) > 0 && !c.SupportsTools {
		return nil, unsupported("tools", "model does not support tool use")
	}
	if r.ToolChoice != nil && r.ToolChoice.Mode == ToolChoiceRequired && !c.SupportsTools {
		return nil, unsupported("tool_choice.required", "model does not support tool use")
	}

	// Structured output is a correctness requirement when strict, and a declared downgrade when the
	// provider only shapes best-effort.
	if r.StructuredOutput != nil {
		switch {
		case !c.SupportsStructuredOutput:
			return nil, unsupported("structured_output", "model does not support structured output")
		case r.StructuredOutput.Strict && !c.SupportsStrictSchema:
			add(LossDowngraded, "structured_output.strict",
				"provider shapes output best-effort; the artifact still passes contract validation before it is accepted")
		}
	}

	if !c.SupportsReasoning(r.Reasoning) {
		add(LossUnsupported, "reasoning",
			fmt.Sprintf("model does not expose reasoning effort %q; the request proceeds without it", r.Reasoning))
	}

	// Modality checks walk every part so the caller learns about all missing modalities at once
	// rather than one per retry.
	var sawImage, sawAudio, sawFile, sawCache bool
	for _, m := range r.Messages {
		for _, p := range m.Parts {
			switch p.Kind {
			case PartImage:
				sawImage = true
			case PartAudio:
				sawAudio = true
			case PartFile:
				sawFile = true
			}
			if p.CacheHint != CacheNone {
				sawCache = true
			}
		}
	}
	if sawImage && !c.SupportsVision {
		return nil, unsupported("parts.image", "model does not accept images")
	}
	if sawAudio && !c.SupportsAudio {
		return nil, unsupported("parts.audio", "model does not accept audio")
	}
	if sawFile && !c.SupportsFiles {
		return nil, unsupported("parts.file", "model does not accept file references")
	}
	if sawCache && !c.SupportsPromptCache {
		add(LossUnsupported, "cache_hint", "model does not support prompt caching; hints are ignored")
	}

	sort.Slice(losses, func(i, j int) bool { return losses[i].Feature < losses[j].Feature })
	return losses, nil
}

// SatisfiesGovernance reports whether the model meets the run's residency and retention policy.
//
// It is separate from Check because these are policy constraints, not capability gaps: a model that
// fails them is ineligible regardless of what the request asks for, and there is no "declared loss"
// version of exceeding a retention limit.
func (c Capabilities) SatisfiesGovernance(requiredRegions []string, maxRetentionDays int) error {
	if len(requiredRegions) > 0 {
		var matched bool
		for _, required := range requiredRegions {
			for _, available := range c.Regions {
				if strings.EqualFold(required, available) {
					matched = true
				}
			}
		}
		if !matched {
			return modberr.New(modberr.CodeNoEligibleRoute,
				"model is not available in a required region").
				WithDetail("required_capabilities", "residency")
		}
	}
	if c.ProviderRetentionDays > maxRetentionDays {
		return modberr.Newf(modberr.CodeNoEligibleRoute,
			"provider retains data for %d days, policy permits %d",
			c.ProviderRetentionDays, maxRetentionDays).
			WithDetail("required_capabilities", "retention")
	}
	// NG1: foundation models are never trained on customer data. This is a product invariant, not a
	// tunable, so a model declaring otherwise is ineligible for every route.
	if c.TrainsOnCustomerData {
		return modberr.New(modberr.CodeNoEligibleRoute,
			"model trains on customer data and is ineligible for any Modbit route").
			WithDetail("required_capabilities", "no_training_on_customer_data")
	}
	return nil
}
