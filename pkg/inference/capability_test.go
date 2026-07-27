package inference_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

func fullCapabilities() inference.Capabilities {
	return inference.Capabilities{
		ProviderID:               "acme",
		ModelID:                  "acme-large",
		Revision:                 "2026-07-01",
		ReleaseDate:              time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Aliases:                  []string{"reasoning.balanced", "code.default"},
		MaxContextTokens:         200000,
		MaxOutputTokens:          16384,
		SupportsTools:            true,
		SupportsParallelToolCall: true,
		ToolSchemaDialect:        inference.DialectJSONSchemaDraft202012,
		SupportsStructuredOutput: true,
		SupportsStrictSchema:     true,
		SupportsVision:           true,
		SupportsStreaming:        true,
		SupportsCancellation:     true,
		ReasoningEfforts:         []inference.ReasoningEffort{inference.ReasoningLow, inference.ReasoningMedium},
		SupportsPromptCache:      true,
		PromptCacheTTL:           5 * time.Minute,
		Regions:                  []string{"us-east", "eu-west"},
		ProviderRetentionDays:    0,
		TrainsOnCustomerData:     false,
		RequestsPerMinute:        1000,
		MaxConcurrency:           50,
		TypicalLatency:           2 * time.Second,
		ReliabilityScore:         0.99,
		Pricing: inference.Pricing{
			InputPerMillion:  inference.Money{Micros: 3_000_000, Currency: "USD"},
			OutputPerMillion: inference.Money{Micros: 15_000_000, Currency: "USD"},
		},
		SafetyFilterBehavior: inference.SafetyRefusalPart,
	}
}

func TestCapabilitiesValidation(t *testing.T) {
	t.Parallel()
	if err := fullCapabilities().Validate(); err != nil {
		t.Fatalf("a complete record was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*inference.Capabilities)
	}{
		{"no revision", func(c *inference.Capabilities) { c.Revision = "" }},
		{"no aliases", func(c *inference.Capabilities) { c.Aliases = nil }},
		{"output exceeds context", func(c *inference.Capabilities) { c.MaxOutputTokens = c.MaxContextTokens + 1 }},
		{"tools without a dialect", func(c *inference.Capabilities) { c.ToolSchemaDialect = "" }},
		{"strict without structured output", func(c *inference.Capabilities) { c.SupportsStructuredOutput = false }},
		{"cache without a ttl", func(c *inference.Capabilities) { c.PromptCacheTTL = 0 }},
		{"reliability out of range", func(c *inference.Capabilities) { c.ReliabilityScore = 1.5 }},
		{"no safety behaviour", func(c *inference.Capabilities) { c.SafetyFilterBehavior = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := fullCapabilities()
			tc.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate accepted an inconsistent record: %s", tc.name)
			}
		})
	}
}

// ADP-3 in practice: a capability the model cannot do at all is an error, and one it can do more
// weakly is a declared Loss. Collapsing the two would either block routes needlessly or let a
// silent downgrade pass as a clean completion.
func TestCheckDistinguishesUnsupportedFromDowngraded(t *testing.T) {
	t.Parallel()

	t.Run("clean route reports no losses", func(t *testing.T) {
		losses, err := fullCapabilities().Check(baseRequest())
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(losses) != 0 {
			t.Errorf("losses = %+v, want none", losses)
		}
	})

	t.Run("wrong alias is an error", func(t *testing.T) {
		r := baseRequest()
		r.Alias = "vision.fast"
		if _, err := fullCapabilities().Check(r); !modberr.Is(err, modberr.CodeNoEligibleRoute) {
			t.Fatalf("error = %v, want MODBIT_NO_ELIGIBLE_ROUTE", err)
		}
	})

	t.Run("images on a text-only model are an error", func(t *testing.T) {
		c := fullCapabilities()
		c.SupportsVision = false
		r := baseRequest()
		r.Messages[0].Parts = append(r.Messages[0].Parts, mediaPart(inference.PartImage, "image/png"))
		if _, err := c.Check(r); err == nil {
			t.Fatal("sending an image to a text-only model must be refused, not downgraded")
		}
	})

	t.Run("strict schema on a best-effort model is a declared loss", func(t *testing.T) {
		c := fullCapabilities()
		c.SupportsStrictSchema = false
		r := baseRequest()
		r.StructuredOutput = &inference.StructuredOutput{SchemaID: "modbit.plan", Version: 1, Strict: true}
		losses, err := c.Check(r)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(losses) != 1 || losses[0].Kind != inference.LossDowngraded {
			t.Fatalf("losses = %+v, want one downgraded loss", losses)
		}
	})

	t.Run("no structured output at all is an error", func(t *testing.T) {
		c := fullCapabilities()
		c.SupportsStructuredOutput = false
		c.SupportsStrictSchema = false
		r := baseRequest()
		r.StructuredOutput = &inference.StructuredOutput{SchemaID: "modbit.plan", Version: 1}
		if _, err := c.Check(r); err == nil {
			t.Fatal("a required structured artifact cannot be produced; this must be an error")
		}
	})

	t.Run("unsupported reasoning effort is a declared loss", func(t *testing.T) {
		r := baseRequest()
		r.Reasoning = inference.ReasoningHigh
		losses, err := fullCapabilities().Check(r)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(losses) != 1 || losses[0].Feature != "reasoning" {
			t.Fatalf("losses = %+v, want a reasoning loss", losses)
		}
	})

	t.Run("cache hints on a cacheless model are a declared loss", func(t *testing.T) {
		c := fullCapabilities()
		c.SupportsPromptCache = false
		c.PromptCacheTTL = 0
		r := baseRequest()
		r.Messages[0].Parts[0].CacheHint = inference.CacheEphemeral
		losses, err := c.Check(r)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(losses) != 1 || losses[0].Feature != "cache_hint" {
			t.Fatalf("losses = %+v, want a cache_hint loss", losses)
		}
	})

	t.Run("tools on a tool-less model are an error", func(t *testing.T) {
		c := fullCapabilities()
		c.SupportsTools = false
		c.ToolSchemaDialect = ""
		r := baseRequest()
		r.Tools = []inference.ToolDefinition{{Name: "read", InputSchema: []byte(`{}`)}}
		if _, err := c.Check(r); err == nil {
			t.Fatal("declaring tools to a tool-less model must be refused")
		}
	})

	t.Run("output budget beyond the model limit is an error", func(t *testing.T) {
		r := baseRequest()
		r.MaxOutputTokens = 999999
		if _, err := fullCapabilities().Check(r); err == nil {
			t.Fatal("an unsatisfiable output budget must be refused")
		}
	})
}

func TestLossesAreOrderedDeterministically(t *testing.T) {
	t.Parallel()
	c := fullCapabilities()
	c.SupportsStrictSchema = false
	c.SupportsPromptCache = false
	c.PromptCacheTTL = 0

	r := baseRequest()
	r.Reasoning = inference.ReasoningHigh
	r.StructuredOutput = &inference.StructuredOutput{SchemaID: "modbit.plan", Version: 1, Strict: true}
	r.Messages[0].Parts[0].CacheHint = inference.CacheEphemeral

	first, err := c.Check(r)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("losses = %+v, want three", first)
	}
	for i := 0; i < 20; i++ {
		again, err := c.Check(r)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("loss order is nondeterministic: %+v then %+v", first, again)
			}
		}
	}
}

// Governance constraints are ineligibility, not degradation: there is no "declared loss" version
// of exceeding a retention limit.
func TestGovernanceConstraints(t *testing.T) {
	t.Parallel()
	c := fullCapabilities()

	if err := c.SatisfiesGovernance([]string{"eu-west"}, 0); err != nil {
		t.Errorf("a compliant model was rejected: %v", err)
	}
	if err := c.SatisfiesGovernance([]string{"ap-south"}, 0); err == nil {
		t.Error("a model outside the required region must be ineligible")
	}
	if err := c.SatisfiesGovernance(nil, 0); err != nil {
		t.Errorf("no residency requirement should not reject: %v", err)
	}

	retaining := c
	retaining.ProviderRetentionDays = 30
	if err := retaining.SatisfiesGovernance(nil, 0); err == nil {
		t.Error("a model retaining data beyond policy must be ineligible")
	}
	if err := retaining.SatisfiesGovernance(nil, 30); err != nil {
		t.Errorf("retention within policy was rejected: %v", err)
	}

	// NG1 is a product invariant, not a tunable: a model that trains on customer data is
	// ineligible for every route regardless of other constraints.
	training := c
	training.TrainsOnCustomerData = true
	if err := training.SatisfiesGovernance(nil, 3650); err == nil {
		t.Error("a model training on customer data must be ineligible for any route")
	}
}

func TestEstimateCostRoundsUp(t *testing.T) {
	t.Parallel()
	c := fullCapabilities()

	// 1M input tokens at 3.00 USD per million.
	full := c.EstimateCost(inference.Usage{InputTokens: 1_000_000})
	if full.Micros != 3_000_000 || full.Currency != "USD" {
		t.Errorf("cost = %+v, want 3000000 USD micros", full)
	}

	// Exact division stays exact: 1 token at 3 micros per token is 3 micros.
	if exact := c.EstimateCost(inference.Usage{InputTokens: 1}); exact.Micros != 3 {
		t.Errorf("cost = %d micros, want 3", exact.Micros)
	}

	// A fractional cost must round up. Rounding down lets a run creep past its cap one fractional
	// token at a time, and a budget that can be exceeded by rounding is not a budget.
	cheap := c
	cheap.Pricing.InputPerMillion = inference.Money{Micros: 500_000, Currency: "USD"}
	if partial := cheap.EstimateCost(inference.Usage{InputTokens: 1}); partial.Micros != 1 {
		t.Errorf("cost = %d micros, want 1 (rounded up from 0.5)", partial.Micros)
	}
	if three := cheap.EstimateCost(inference.Usage{InputTokens: 5}); three.Micros != 3 {
		t.Errorf("cost = %d micros, want 3 (rounded up from 2.5)", three.Micros)
	}

	if zero := c.EstimateCost(inference.Usage{}); zero.Micros != 0 {
		t.Errorf("cost = %d, want 0", zero.Micros)
	}
}

func TestUsageTotal(t *testing.T) {
	t.Parallel()
	u := inference.Usage{InputTokens: 10, CachedInputTokens: 5, OutputTokens: 3, ReasoningTokens: 2}
	if u.Total() != 20 {
		t.Errorf("Total = %d, want 20", u.Total())
	}
}

// stubAdapter satisfies the Adapter interface for registry tests. It performs no I/O.
type stubAdapter struct{ provider string }

func (s stubAdapter) Provider() string { return s.provider }
func (s stubAdapter) Capabilities(context.Context) ([]inference.Capabilities, error) {
	return nil, nil
}
func (s stubAdapter) Complete(context.Context, inference.Request, inference.Capabilities, inference.Credential) (inference.Response, error) {
	return inference.Response{}, nil
}
func (s stubAdapter) Stream(context.Context, inference.Request, inference.Capabilities, inference.Credential) (<-chan inference.StreamEvent, error) {
	ch := make(chan inference.StreamEvent)
	close(ch)
	return ch, nil
}
func (s stubAdapter) CountTokens(context.Context, inference.Request, inference.Capabilities) (inference.TokenCount, error) {
	return inference.TokenCount{}, nil
}
func (s stubAdapter) Health(context.Context) error { return nil }

func TestRegistryRejectsInconsistentRegistration(t *testing.T) {
	t.Parallel()

	if _, err := inference.NewRegistry([]inference.Adapter{stubAdapter{"acme"}, stubAdapter{"acme"}}, nil); err == nil {
		t.Error("two adapters for the same provider must be rejected")
	}
	if _, err := inference.NewRegistry(nil, []inference.Capabilities{fullCapabilities()}); err == nil {
		t.Error("a model naming a provider with no adapter must be rejected")
	}
	if _, err := inference.NewRegistry([]inference.Adapter{stubAdapter{"acme"}},
		[]inference.Capabilities{fullCapabilities(), fullCapabilities()}); err == nil {
		t.Error("a duplicate model record must be rejected")
	}
}

func TestCandidatesRespectThePolicyEnvelope(t *testing.T) {
	t.Parallel()
	cheap := fullCapabilities()
	cheap.ProviderID, cheap.ModelID = "budget", "budget-small"
	cheap.SupportsStrictSchema = false // will incur a loss on a strict request
	cheap.Regions = []string{"us-east"}

	registry, err := inference.NewRegistry(
		[]inference.Adapter{stubAdapter{"acme"}, stubAdapter{"budget"}},
		[]inference.Capabilities{fullCapabilities(), cheap},
	)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	t.Run("both models serve a plain request", func(t *testing.T) {
		got, err := registry.Candidates(baseRequest(), inference.Constraints{MaxRetentionDays: 0})
		if err != nil {
			t.Fatalf("Candidates: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("candidates = %d, want 2", len(got))
		}
	})

	t.Run("provider allowlist narrows the set", func(t *testing.T) {
		got, err := registry.Candidates(baseRequest(), inference.Constraints{
			AllowedProviders: []string{"acme"}, MaxRetentionDays: 0,
		})
		if err != nil {
			t.Fatalf("Candidates: %v", err)
		}
		if len(got) != 1 || got[0].Model.ProviderID != "acme" {
			t.Fatalf("candidates = %+v, want only acme", got)
		}
	})

	t.Run("residency narrows the set", func(t *testing.T) {
		got, err := registry.Candidates(baseRequest(), inference.Constraints{
			RequiredRegions: []string{"eu-west"}, MaxRetentionDays: 0,
		})
		if err != nil {
			t.Fatalf("Candidates: %v", err)
		}
		if len(got) != 1 || got[0].Model.ProviderID != "acme" {
			t.Fatalf("candidates = %+v, want only the eu-west model", got)
		}
	})

	t.Run("lossless candidates rank first", func(t *testing.T) {
		r := baseRequest()
		r.StructuredOutput = &inference.StructuredOutput{SchemaID: "modbit.plan", Version: 1, Strict: true}
		got, err := registry.Candidates(r, inference.Constraints{MaxRetentionDays: 0})
		if err != nil {
			t.Fatalf("Candidates: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("candidates = %d, want 2", len(got))
		}
		if len(got[0].Losses) != 0 || got[0].Model.ProviderID != "acme" {
			t.Errorf("first candidate = %+v, want the lossless acme model", got[0].Model.ModelID)
		}
		if len(got[1].Losses) != 1 {
			t.Errorf("second candidate should declare its downgrade: %+v", got[1].Losses)
		}
	})

	t.Run("an empty envelope explains itself", func(t *testing.T) {
		_, err := registry.Candidates(baseRequest(), inference.Constraints{
			AllowedProviders: []string{"nobody"}, MaxRetentionDays: 0,
		})
		if !modberr.Is(err, modberr.CodeNoEligibleRoute) {
			t.Fatalf("error = %v, want MODBIT_NO_ELIGIBLE_ROUTE", err)
		}
		e, _ := modberr.As(err)
		rejected := e.Details()["rejected_models"]
		if !strings.Contains(rejected, "acme-large") || !strings.Contains(rejected, "budget-small") {
			t.Errorf("rejection detail = %q, want both models named", rejected)
		}
		if dropped, present := e.Details()["unregistered_detail_keys"]; present {
			t.Errorf("route error attached unallowlisted detail keys: %s", dropped)
		}
	})
}

// Candidate ordering feeds a recorded routing decision. Two gateway replicas given the same inputs
// must propose the same route, so the order cannot depend on map iteration.
func TestCandidateOrderIsDeterministic(t *testing.T) {
	t.Parallel()
	var models []inference.Capabilities
	var adapters []inference.Adapter
	for _, name := range []string{"zeta", "alpha", "mid"} {
		c := fullCapabilities()
		c.ProviderID, c.ModelID = name, name+"-model"
		models = append(models, c)
		adapters = append(adapters, stubAdapter{name})
	}
	registry, err := inference.NewRegistry(adapters, models)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	first, err := registry.Candidates(baseRequest(), inference.Constraints{MaxRetentionDays: 0})
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	for i := 0; i < 25; i++ {
		again, err := registry.Candidates(baseRequest(), inference.Constraints{MaxRetentionDays: 0})
		if err != nil {
			t.Fatalf("Candidates: %v", err)
		}
		for j := range first {
			if again[j].Model.ProviderID != first[j].Model.ProviderID {
				t.Fatalf("candidate order is nondeterministic: %v then %v",
					providerNames(first), providerNames(again))
			}
		}
	}
	if got := providerNames(first); got[0] != "alpha" {
		t.Errorf("order = %v, want alphabetical among equal-loss candidates", got)
	}
}

func providerNames(candidates []inference.Candidate) []string {
	out := make([]string, len(candidates))
	for i, c := range candidates {
		out[i] = c.Model.ProviderID
	}
	return out
}

func TestCandidatesRejectAnInvalidRequest(t *testing.T) {
	t.Parallel()
	registry, err := inference.NewRegistry([]inference.Adapter{stubAdapter{"acme"}},
		[]inference.Capabilities{fullCapabilities()})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	bad := baseRequest()
	bad.Messages[0].Parts[0].Provenance = taint.Class(200)
	if _, err := registry.Candidates(bad, inference.Constraints{}); err == nil {
		t.Fatal("Candidates must validate the request before routing it")
	}
}

func TestRegistryAliases(t *testing.T) {
	t.Parallel()
	registry, err := inference.NewRegistry([]inference.Adapter{stubAdapter{"acme"}},
		[]inference.Capabilities{fullCapabilities()})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	aliases := registry.Aliases()
	if len(aliases) != 2 || aliases[0] != "code.default" || aliases[1] != "reasoning.balanced" {
		t.Errorf("aliases = %v, want a sorted list", aliases)
	}
}
