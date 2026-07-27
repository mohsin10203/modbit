package inference

import (
	"context"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Adapter is the provider boundary (PRD v5.1 §14.1).
//
// Every provider-specific format, header, error shape, and streaming quirk terminates at an
// implementation of this interface (ADP-1). The interface is declared here, at the consumer, rather
// than beside any implementation (R-ARCH-05).
//
// An Adapter never holds a credential itself. The Model Gateway leases one per call and passes it
// explicitly, so an adapter has nothing credential-shaped to leak through a struct field, and a
// reviewer can see from the signature exactly where provider material crosses the boundary (INV-2).
type Adapter interface {
	// Provider returns the stable provider identifier used in routing and evidence.
	Provider() string

	// Capabilities returns the normalized capability records for every model this adapter serves.
	// The gateway refreshes them; adapters do not cache policy decisions derived from them.
	Capabilities(ctx context.Context) ([]Capabilities, error)

	// Complete performs a non-streaming completion. The credential is valid for this call only.
	Complete(ctx context.Context, req Request, model Capabilities, cred Credential) (Response, error)

	// Stream performs a streaming completion. Implementations must close the returned channel on
	// completion, cancellation, and error, and must honour ctx cancellation promptly (R-GO-01).
	Stream(ctx context.Context, req Request, model Capabilities, cred Credential) (<-chan StreamEvent, error)

	// CountTokens returns the provider's token count for the request. Implementations that can only
	// estimate must say so through the returned TokenCount.
	CountTokens(ctx context.Context, req Request, model Capabilities) (TokenCount, error)

	// Health reports adapter reachability for circuit breaking.
	Health(ctx context.Context) error
}

// TokenCount is a token measurement with its provenance.
type TokenCount struct {
	Tokens int `json:"tokens"`
	// Exact distinguishes a provider-authoritative count from a local estimate. A budget decision
	// made on an estimate must be able to say so rather than presenting it as measured.
	Exact bool `json:"exact"`
}

// StreamEventKind discriminates normalized streaming deltas.
type StreamEventKind string

const (
	StreamMessageStart   StreamEventKind = "message_start"
	StreamTextDelta      StreamEventKind = "text_delta"
	StreamToolCallDelta  StreamEventKind = "tool_call_delta"
	StreamReasoningDelta StreamEventKind = "reasoning_delta"
	StreamMessageStop    StreamEventKind = "message_stop"
	StreamError          StreamEventKind = "error"
)

// StreamEvent is one normalized streaming delta.
//
// Providers disagree about delta granularity, indexing, and terminal events; the adapter normalizes
// all of it so the harness consumes one shape (ADP-1).
type StreamEvent struct {
	Kind StreamEventKind `json:"kind"`
	// Index identifies which content part this delta belongs to, for interleaved tool-call streams.
	Index int `json:"index"`
	// Text carries a text or reasoning delta.
	Text string `json:"text,omitempty"`
	// ToolCallID and ToolName are set on the first delta of a tool call.
	ToolCallID string `json:"tool_call_id,omitempty"`
	ToolName   string `json:"tool_name,omitempty"`
	// InputDelta carries a partial JSON fragment of a tool call's input.
	InputDelta string `json:"input_delta,omitempty"`
	// Final is populated on StreamMessageStop with the assembled response.
	Final *Response `json:"final,omitempty"`
	// Err is populated on StreamError. It always carries a stable Modbit code.
	Err error `json:"-"`
}

// Registry resolves capability aliases to concrete models across adapters.
//
// It is the mechanism behind ADP-4: adding a model tier is a capability record, not a code change.
// The registry holds no credentials and makes no policy decisions; it answers "which models could
// serve this alias", and the gateway narrows that by policy.
type Registry struct {
	byProvider map[string]Adapter
	models     []Capabilities
}

// NewRegistry validates and indexes the supplied models.
func NewRegistry(adapters []Adapter, models []Capabilities) (*Registry, error) {
	r := &Registry{byProvider: make(map[string]Adapter, len(adapters))}
	for _, a := range adapters {
		if a == nil {
			return nil, modberr.New(modberr.CodeInvalidArgument, "nil adapter in registry")
		}
		if _, dup := r.byProvider[a.Provider()]; dup {
			return nil, modberr.Newf(modberr.CodeInvalidArgument,
				"duplicate adapter for provider %q", a.Provider())
		}
		r.byProvider[a.Provider()] = a
	}
	seen := make(map[string]struct{}, len(models))
	for _, m := range models {
		if err := m.Validate(); err != nil {
			return nil, err
		}
		if _, ok := r.byProvider[m.ProviderID]; !ok {
			return nil, modberr.Newf(modberr.CodeInvalidArgument,
				"model %q names provider %q which has no registered adapter", m.ModelID, m.ProviderID)
		}
		key := m.ProviderID + "/" + m.ModelID + "@" + m.Revision
		if _, dup := seen[key]; dup {
			return nil, modberr.Newf(modberr.CodeInvalidArgument, "duplicate model record %q", key)
		}
		seen[key] = struct{}{}
		r.models = append(r.models, m)
	}
	return r, nil
}

// Candidate is a model that can serve an alias, with any losses its use would incur.
type Candidate struct {
	Model   Capabilities
	Adapter Adapter
	Losses  []Loss
}

// Constraints narrow candidate selection to the policy envelope. They come from the run's frozen
// settings snapshot; this package does not read settings itself, so a routing decision cannot
// depend on live configuration mid-run (INV-6).
type Constraints struct {
	AllowedProviders []string
	RequiredRegions  []string
	MaxRetentionDays int
}

// Candidates returns every model that can serve the request within the constraints, together with
// the losses each would incur.
//
// Models are returned in a deterministic order — fewest losses first, then by provider and model —
// so that two gateway replicas presented with the same inputs propose the same route. A map-order
// result would make routing decisions irreproducible in evidence.
func (r *Registry) Candidates(req Request, c Constraints) ([]Candidate, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(c.AllowedProviders))
	wildcard := len(c.AllowedProviders) == 0
	for _, p := range c.AllowedProviders {
		if p == "*" {
			wildcard = true
		}
		allowed[strings.ToLower(p)] = struct{}{}
	}

	var out []Candidate
	// rejections records why each model was excluded, so a "no eligible route" error can explain
	// itself instead of leaving an operator to guess.
	var rejections []string
	for _, m := range r.models {
		if !m.ServesAlias(req.Alias) {
			continue
		}
		if !wildcard {
			if _, ok := allowed[strings.ToLower(m.ProviderID)]; !ok {
				rejections = append(rejections, m.ModelID+": provider not in the allowlist")
				continue
			}
		}
		if err := m.SatisfiesGovernance(c.RequiredRegions, c.MaxRetentionDays); err != nil {
			rejections = append(rejections, m.ModelID+": "+governanceReason(err))
			continue
		}
		losses, err := m.Check(req)
		if err != nil {
			rejections = append(rejections, m.ModelID+": capability gap")
			continue
		}
		out = append(out, Candidate{Model: m, Adapter: r.byProvider[m.ProviderID], Losses: losses})
	}

	if len(out) == 0 {
		err := modberr.Newf(modberr.CodeNoEligibleRoute,
			"no model satisfies alias %q within the policy envelope", req.Alias).
			WithDetail("required_capabilities", req.Alias)
		if len(rejections) > 0 {
			sort.Strings(rejections)
			err = err.WithDetail("rejected_models", strings.Join(rejections, "; "))
		}
		return nil, err
	}

	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].Losses) != len(out[j].Losses) {
			return len(out[i].Losses) < len(out[j].Losses)
		}
		if out[i].Model.ProviderID != out[j].Model.ProviderID {
			return out[i].Model.ProviderID < out[j].Model.ProviderID
		}
		return out[i].Model.ModelID < out[j].Model.ModelID
	})
	return out, nil
}

func governanceReason(err error) string {
	if e, ok := modberr.As(err); ok {
		return e.Message()
	}
	return "governance constraint not satisfied"
}

// Aliases returns every alias any registered model can serve, sorted.
func (r *Registry) Aliases() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, m := range r.models {
		for _, a := range m.Aliases {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// Models returns a copy of the registered capability records.
func (r *Registry) Models() []Capabilities {
	out := make([]Capabilities, len(r.models))
	copy(out, r.models)
	return out
}
