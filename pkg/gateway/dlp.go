package gateway

import (
	"context"
	"regexp"
	"sort"
	"strconv"

	"github.com/modbit/modbit/pkg/inference"
	"github.com/modbit/modbit/pkg/modberr"
)

// Classification grades the sensitivity of an outbound payload (PRD v5.1 §17.5).
type Classification string

const (
	ClassificationPublic       Classification = "public"
	ClassificationInternal     Classification = "internal"
	ClassificationConfidential Classification = "confidential"
	ClassificationRestricted   Classification = "restricted"
)

// rank orders classifications so a payload's classification is the highest of its parts.
var classificationRank = map[Classification]int{
	ClassificationPublic: 0, ClassificationInternal: 1,
	ClassificationConfidential: 2, ClassificationRestricted: 3,
}

// Escalate returns the higher of two classifications.
func (c Classification) Escalate(other Classification) Classification {
	if classificationRank[other] > classificationRank[c] {
		return other
	}
	return c
}

// Decision is what DLP concluded about a payload.
type Decision string

const (
	// DecisionAllow permits the payload unchanged.
	DecisionAllow Decision = "allow"
	// DecisionRedact permits a modified payload. The redacted request is what is sent.
	DecisionRedact Decision = "redact"
	// DecisionBlock refuses egress entirely.
	DecisionBlock Decision = "block"
)

// Finding is one DLP match.
//
// It records the rule that fired and where, never what matched. A finding carrying the matched
// value would move the secret from the prompt into the audit log, which is the same disclosure with
// extra steps (INV-11, R-ERR-02).
type Finding struct {
	// RuleID is the stable identifier of the rule that fired.
	RuleID string `json:"rule_id"`
	// Location names the region of the request, for example "messages[2].parts[0]".
	Location string `json:"location"`
	// Classification is the sensitivity this rule implies.
	Classification Classification `json:"classification"`
	// Action is what the rule requires.
	Action Decision `json:"action"`
}

// Verdict is the outcome of a DLP inspection.
type Verdict struct {
	Decision       Decision
	Classification Classification
	Findings       []Finding
	// Redacted is the payload to send when Decision is DecisionRedact. It is nil otherwise.
	Redacted *inference.Request
}

// Inspector classifies and redacts an outbound payload.
//
// The interface is declared at this consumer boundary (R-ARCH-05). An implementation that cannot
// complete must return an error rather than a permissive verdict: the gateway fails closed on
// error, and an Inspector that swallowed its own failure would defeat that (SDD §10, INV-3).
type Inspector interface {
	Inspect(ctx context.Context, req inference.Request) (Verdict, error)
}

// Rule is one pattern-based DLP rule.
type Rule struct {
	ID             string
	Pattern        *regexp.Regexp
	Classification Classification
	Action         Decision
	// Replacement is substituted for a match when Action is DecisionRedact.
	Replacement string
}

// PatternInspector is a regular-expression Inspector.
//
// It is a real, if minimal, implementation: enough to enforce the boundary in local and offline
// deployments, and enough to be the reference behaviour an enterprise DLP adapter is tested
// against. It is not a substitute for a content-inspection product on a hosted deployment.
type PatternInspector struct {
	rules []Rule
	// baseline is the classification assigned to any payload, before rules escalate it.
	baseline Classification
}

// NewPatternInspector returns an Inspector over rules. A nil or empty rule set is rejected: an
// Inspector that inspects nothing is a silently disabled control, and INV-3 has no opt-out.
func NewPatternInspector(baseline Classification, rules []Rule) (*PatternInspector, error) {
	if len(rules) == 0 {
		return nil, modberr.New(modberr.CodeInvalidArgument,
			"a DLP inspector requires at least one rule; classification and DLP are not optional")
	}
	for _, r := range rules {
		if r.ID == "" || r.Pattern == nil {
			return nil, modberr.New(modberr.CodeInvalidArgument, "every DLP rule requires an id and a pattern")
		}
		if r.Action == DecisionRedact && r.Replacement == "" {
			return nil, modberr.Newf(modberr.CodeInvalidArgument,
				"redacting rule %q requires a replacement", r.ID)
		}
	}
	if baseline == "" {
		baseline = ClassificationInternal
	}
	out := &PatternInspector{baseline: baseline, rules: make([]Rule, len(rules))}
	copy(out.rules, rules)
	return out, nil
}

// DefaultRules returns Modbit's built-in credential-shaped patterns.
//
// These are deliberately conservative and deliberately *block* rather than redact. A redacted
// credential still tells an attacker the shape of what was there, and a payload containing one is
// usually a sign the caller assembled context it should not have.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID:             "private_key_block",
			Pattern:        regexp.MustCompile(`-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----`),
			Classification: ClassificationRestricted,
			Action:         DecisionBlock,
		},
		{
			ID:             "aws_access_key_id",
			Pattern:        regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
			Classification: ClassificationRestricted,
			Action:         DecisionBlock,
		},
		{
			ID:             "bearer_token_header",
			Pattern:        regexp.MustCompile(`(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}`),
			Classification: ClassificationRestricted,
			Action:         DecisionBlock,
		},
		{
			ID:             "generic_api_key_assignment",
			Pattern:        regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*['"]?[A-Za-z0-9._~+/=-]{20,}`),
			Classification: ClassificationRestricted,
			Action:         DecisionBlock,
		},
		{
			ID:             "connection_string_password",
			Pattern:        regexp.MustCompile(`(?i)://[^\s:/@]+:[^\s:/@]{6,}@`),
			Classification: ClassificationRestricted,
			Action:         DecisionRedact,
			Replacement:    "://[redacted]@",
		},
	}
}

// NewDefaultInspector returns a PatternInspector over DefaultRules.
func NewDefaultInspector() *PatternInspector {
	i, err := NewPatternInspector(ClassificationInternal, DefaultRules())
	if err != nil {
		// DefaultRules is a compile-time constant set; a failure here is a programmer error caught
		// on the first run of any binary that links this package (R-GO-08).
		panic("gateway: default DLP rules are invalid: " + err.Error())
	}
	return i
}

// Inspect classifies the request and applies redaction.
func (p *PatternInspector) Inspect(ctx context.Context, req inference.Request) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, modberr.Wrap(err, modberr.CodeCancelled, "DLP inspection cancelled")
	}

	verdict := Verdict{Decision: DecisionAllow, Classification: p.baseline}
	redacted := req
	changed := false

	// scan applies every rule to one text region and returns the possibly redacted text.
	scan := func(text, location string) string {
		for _, rule := range p.rules {
			if !rule.Pattern.MatchString(text) {
				continue
			}
			verdict.Findings = append(verdict.Findings, Finding{
				RuleID: rule.ID, Location: location,
				Classification: rule.Classification, Action: rule.Action,
			})
			verdict.Classification = verdict.Classification.Escalate(rule.Classification)
			switch rule.Action {
			case DecisionBlock:
				// A block is terminal for the payload; keep scanning so the caller learns about
				// every rule that fired rather than fixing them one at a time.
				verdict.Decision = DecisionBlock
			case DecisionRedact:
				text = rule.Pattern.ReplaceAllString(text, rule.Replacement)
				changed = true
				if verdict.Decision == DecisionAllow {
					verdict.Decision = DecisionRedact
				}
			}
		}
		return text
	}

	redacted.System = scanParts(req.System, "system", scan)
	redacted.Developer = scanParts(req.Developer, "developer", scan)
	redacted.Messages = make([]inference.Message, len(req.Messages))
	for i, m := range req.Messages {
		redacted.Messages[i] = inference.Message{
			Role:  m.Role,
			Parts: scanParts(m.Parts, "messages["+strconv.Itoa(i)+"]", scan),
		}
	}

	sort.SliceStable(verdict.Findings, func(a, b int) bool {
		if verdict.Findings[a].Location != verdict.Findings[b].Location {
			return verdict.Findings[a].Location < verdict.Findings[b].Location
		}
		return verdict.Findings[a].RuleID < verdict.Findings[b].RuleID
	})

	if verdict.Decision == DecisionRedact && changed {
		verdict.Redacted = &redacted
	}
	if verdict.Decision == DecisionBlock {
		// A blocked payload is never forwarded, so a partially redacted copy would only be a
		// confusing artifact.
		verdict.Redacted = nil
	}
	return verdict, nil
}

// scanParts applies scan to every text-bearing part, including nested tool-result parts. Tool
// results are the most common carrier of accidentally captured credentials, so skipping them would
// leave the largest hole open.
func scanParts(parts []inference.Part, prefix string, scan func(text, location string) string) []inference.Part {
	if parts == nil {
		return nil
	}
	out := make([]inference.Part, len(parts))
	copy(out, parts)
	for i := range out {
		location := prefix + ".parts[" + strconv.Itoa(i) + "]"
		switch out[i].Kind {
		case inference.PartText:
			out[i].Text = scan(out[i].Text, location)
		case inference.PartToolCall:
			if out[i].ToolCall != nil {
				call := *out[i].ToolCall
				call.Input = []byte(scan(string(call.Input), location+".input"))
				out[i].ToolCall = &call
			}
		case inference.PartToolResult:
			if out[i].ToolResult != nil {
				result := *out[i].ToolResult
				result.Parts = scanParts(result.Parts, location+".result", scan)
				out[i].ToolResult = &result
			}
		}
	}
	return out
}
