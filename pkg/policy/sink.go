package policy

import (
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Sink is the destination an operation sends content to.
//
// Adopted under docs/adr/0100 from the reference specification's sink matrix, serving TNT-3 and
// INV-11.
//
// # Why a sink dimension is needed
//
// Approval escalation alone answers "how much human sign-off does this need". It cannot answer
// "should this content reach this destination at all". Those are different questions: a credential
// pasted into a prompt does not become acceptable because two people approved the tool call. The
// sink dimension lets policy refuse a *destination* independently of the approval ladder.
type Sink string

const (
	// SinkNone marks an operation with no content destination, such as a pure read.
	SinkNone Sink = ""
	// SinkModelPrompt sends content to a model provider.
	SinkModelPrompt Sink = "model_prompt"
	// SinkToolArgument passes content as a tool or MCP argument.
	SinkToolArgument Sink = "tool_argument"
	// SinkNetworkEgress sends content to an external URL or request body.
	SinkNetworkEgress Sink = "network_egress"
	// SinkSourceControl writes content to a commit, issue, pull request, or comment.
	SinkSourceControl Sink = "source_control"
	// SinkMemoryWrite persists content into tiered memory.
	SinkMemoryWrite Sink = "memory_write"
	// SinkArtifactExport writes content into an exported artifact or evidence bundle.
	SinkArtifactExport Sink = "artifact_export"
)

var sinkNames = map[Sink]string{
	SinkNone: "none", SinkModelPrompt: "model_prompt", SinkToolArgument: "tool_argument",
	SinkNetworkEgress: "network_egress", SinkSourceControl: "source_control",
	SinkMemoryWrite: "memory_write", SinkArtifactExport: "artifact_export",
}

// String returns the canonical name.
func (s Sink) String() string {
	if n, ok := sinkNames[s]; ok {
		return n
	}
	return "unknown"
}

// Valid reports whether s is a registered sink.
func (s Sink) Valid() bool {
	_, ok := sinkNames[s]
	return ok
}

// ParseSink resolves a sink name. An unrecognized name is an error rather than a default: guessing
// a destination is how content ends up somewhere nobody authorized.
func ParseSink(name string) (Sink, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for sink, n := range sinkNames {
		if n == normalized {
			return sink, nil
		}
	}
	return SinkNone, modberr.Newf(modberr.CodeInvalidArgument, "unrecognized sink %q", name).
		WithDetail("field", "sink")
}

// secretDeniedSinks are the destinations known-secret content may never reach.
//
// This is deliberately not a setting. Every other taint control in this package is configurable
// because organizations legitimately differ on risk appetite, but "do not send a detected
// credential to a third party" is a product-safety invariant in the same class as NG1: a
// configuration surface here exists only to be turned off during an incident, which is exactly when
// it matters most.
//
// SinkToolArgument is absent on purpose. A secret reaching a tool argument is often the *point* —
// a broker handing a leased credential to the operation that needs it — and that path is governed
// by the Task Secret contract rather than by taint confinement.
var secretDeniedSinks = map[Sink]bool{
	SinkModelPrompt:    true,
	SinkNetworkEgress:  true,
	SinkSourceControl:  true,
	SinkMemoryWrite:    true,
	SinkArtifactExport: true,
}

// checkSink refuses a taint class that must not reach the operation's destination.
//
// It runs before the approval ladder and returns a denial rather than an escalation: there is no
// approval class that makes a credential in a commit acceptable.
func checkSink(op Operation, set taint.Set) (Reason, bool) {
	if !set.Contains(taint.KnownSecret) {
		return Reason{}, false
	}
	if !secretDeniedSinks[op.Sink] {
		return Reason{}, false
	}
	return Reason{
		Code: ReasonSecretAtSink,
		Message: "run context contains detected credential material, which cannot reach " +
			op.Sink.String(),
	}, true
}
