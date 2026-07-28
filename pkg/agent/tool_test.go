package agent_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/agent"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/policy"
	"github.com/modbit/modbit/pkg/settings"
	"github.com/modbit/modbit/pkg/taint"
)

// fakeTool records whether it was invoked, which is how T2 and T8 are checked: both are statements
// about what must *not* have happened yet.
type fakeTool struct {
	def      agent.Definition
	invoked  int
	output   agent.Output
	err      error
	lastSeen json.RawMessage
}

func (f *fakeTool) Definition() agent.Definition { return f.def }

func (f *fakeTool) Invoke(_ context.Context, input json.RawMessage) (agent.Output, error) {
	f.invoked++
	f.lastSeen = input
	if f.err != nil {
		return agent.Output{}, f.err
	}
	return f.output, nil
}

type fakeArtifacts struct {
	stored []string
	err    error
}

func (f *fakeArtifacts) Put(_ context.Context, _ id.ID, body string) (id.ID, error) {
	if f.err != nil {
		return "", f.err
	}
	f.stored = append(f.stored, body)
	return id.MustNew(id.Artifact), nil
}

const readSchema = `{
  "type": "object",
  "properties": {"path": {"type": "string"}},
  "required": ["path"],
  "additionalProperties": false
}`

func readTool() *fakeTool {
	return &fakeTool{
		def: agent.Definition{
			Name:        "read_file",
			Version:     1,
			Description: "reads a file",
			InputSchema: json.RawMessage(readSchema),
			SideEffect:  mustSideEffect("pure_read_only"),
		},
		output: agent.Output{Body: "package main", Provenance: taint.ToolResult},
	}
}

func mustSideEffect(name string) policy.SideEffectClass {
	c, err := policy.ParseSideEffectClass(name)
	if err != nil {
		panic(err)
	}
	return c
}

func testSettings(t *testing.T) settings.Snapshot {
	t.Helper()
	resolver, err := settings.NewResolver(settings.Default())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	result, err := resolver.Resolve(nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	snap, err := settings.NewSnapshot(result, nil)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap
}

func newRegistry(t *testing.T, tools ...agent.Tool) (*agent.Registry, *fakeArtifacts) {
	t.Helper()
	artifacts := &fakeArtifacts{}
	reg, err := agent.NewRegistry(policy.NewEngine(nil), agent.BasicValidator{}, artifacts)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	for _, tool := range tools {
		if err := reg.Register(tool); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	return reg, artifacts
}

func invokeOptions(t *testing.T) agent.InvokeOptions {
	t.Helper()
	return agent.InvokeOptions{
		RunID:    id.MustNew(id.Run),
		Settings: testSettings(t),
		Taint:    taint.NewSet(taint.UserTrusted),
		Now:      time.Unix(1700000000, 0).UTC(),
	}
}

// T1. A tool nobody classified is one nobody decided the risk of, and discovering that mid-run means
// discovering it after the plan was approved.
func TestSecurityToolsMustDeclareASideEffectClass(t *testing.T) {
	reg, _ := newRegistry(t)

	undeclared := readTool()
	undeclared.def.SideEffect = policy.SideEffectUndeclared
	if err := reg.Register(undeclared); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal for an undeclared side-effect class", err)
	}

	for name, mutate := range map[string]func(*agent.Definition){
		"no name":    func(d *agent.Definition) { d.Name = "" },
		"no version": func(d *agent.Definition) { d.Version = 0 },
		"no schema":  func(d *agent.Definition) { d.InputSchema = nil },
		"bad sink":   func(d *agent.Definition) { d.Sink = policy.Sink("nowhere") },
	} {
		t.Run(name, func(t *testing.T) {
			tool := readTool()
			mutate(&tool.def)
			if err := reg.Register(tool); !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want a refusal", err)
			}
		})
	}

	// Re-registering under one name would let a later registration change what an already-approved
	// plan authorized.
	if err := reg.Register(readTool()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(readTool()); !modberr.Is(err, modberr.CodeConflict) {
		t.Fatalf("error = %v, want a conflict on re-registration", err)
	}
}

// T2. TLS-2 puts validation before policy evaluation. A decision is an audited artifact (INV-7), so
// minting one for a call that was never going to run pollutes the record with authorizations nothing
// acted on — and the tool must not be reached either.
func TestInputIsValidatedBeforePolicyIsEvaluated(t *testing.T) {
	tool := readTool()
	reg, _ := newRegistry(t, tool)

	record, err := reg.Invoke(context.Background(), agent.Call{
		Tool:  "read_file",
		Input: json.RawMessage(`{"wrong":"shape"}`),
		Actor: "u_1",
	}, invokeOptions(t))

	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a validation refusal", err)
	}
	if tool.invoked != 0 {
		t.Fatal("the tool was invoked despite invalid input")
	}
	if record.PolicyDecisionID != "" {
		t.Fatalf("a policy decision was minted for an invalid call: %q", record.PolicyDecisionID)
	}
}

// T2, second half: the validator refuses what it cannot check rather than passing it. A constraint
// the schema author wrote and nothing enforces is worse than no constraint, because it reads as one.
func TestValidatorRefusesConstructsItCannotEnforce(t *testing.T) {
	v := agent.BasicValidator{}

	if err := v.Supports(json.RawMessage(readSchema)); err != nil {
		t.Fatalf("a supported schema was rejected: %v", err)
	}
	for name, schema := range map[string]string{
		"pattern":    `{"type":"object","properties":{"p":{"type":"string","pattern":"^a"}}}`,
		"minimum":    `{"type":"object","properties":{"n":{"type":"integer","minimum":1}}}`,
		"oneOf":      `{"type":"object","oneOf":[{"required":["a"]}]}`,
		"nested ref": `{"type":"object","properties":{"p":{"$ref":"#/defs/x"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := v.Supports(json.RawMessage(schema)); !modberr.Is(err, modberr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want a refusal for an unenforceable construct", err)
			}
		})
	}
}

// T2, third half: an undeclared property is refused. The input comes from a model, so a tool that
// quietly ignores an extra field lets a prompt injection carry an argument the schema author never
// anticipated.
func TestSecurityUndeclaredPropertiesAreRefused(t *testing.T) {
	tool := readTool()
	reg, _ := newRegistry(t, tool)

	_, err := reg.Invoke(context.Background(), agent.Call{
		Tool:  "read_file",
		Input: json.RawMessage(`{"path":"a.go","sudo":true}`),
		Actor: "u_1",
	}, invokeOptions(t))

	if !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal for an undeclared property", err)
	}
	if tool.invoked != 0 {
		t.Fatal("the tool saw an input carrying an undeclared property")
	}
}

// T3, TLS-7. Invoke takes an input document and nothing else. There is no parameter, field, or
// context value through which a provider credential could reach a tool.
func TestSecurityToolsCannotReceiveCredentials(t *testing.T) {
	tool := readTool()
	reg, _ := newRegistry(t, tool)

	if _, err := reg.Invoke(context.Background(), agent.Call{
		Tool:  "read_file",
		Input: json.RawMessage(`{"path":"a.go"}`),
		Actor: "u_1",
	}, invokeOptions(t)); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	// The tool saw exactly the validated input and nothing else. This is the observable half of a
	// guarantee whose other half is structural: the Tool interface has nowhere to put a credential.
	if string(tool.lastSeen) != `{"path":"a.go"}` {
		t.Fatalf("the tool received %s, want only the call input", tool.lastSeen)
	}
}

// T4. TLS-4: every call records actor, policy result, timing, and result hash.
func TestEveryCallProducesEvidence(t *testing.T) {
	tool := readTool()
	reg, _ := newRegistry(t, tool)
	opts := invokeOptions(t)

	record, err := reg.Invoke(context.Background(), agent.Call{
		Tool:  "read_file",
		Input: json.RawMessage(`{"path":"a.go"}`),
		Actor: "u_1",
	}, opts)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if record.Actor != "u_1" {
		t.Fatalf("actor = %q", record.Actor)
	}
	if record.RunID != opts.RunID {
		t.Fatalf("run id = %q, want %q", record.RunID, opts.RunID)
	}
	if record.PolicyDecisionID == "" {
		t.Fatal("no policy decision recorded; INV-7 needs one on anything policy evaluated")
	}
	if record.Effect != policy.EffectAllow {
		t.Fatalf("effect = %q, want allow", record.Effect)
	}
	if record.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", record.SchemaVersion)
	}
	if record.SideEffect == "" {
		t.Fatal("no side-effect class recorded")
	}
	if record.StartedAt.IsZero() {
		t.Fatal("no start time recorded")
	}
	if record.ResultHash == "" || !strings.HasPrefix(record.ResultHash, "sha256:") {
		t.Fatalf("result hash = %q, want a sha256 digest", record.ResultHash)
	}
	if record.ID == "" {
		t.Fatal("no record identifier")
	}
}

// T5. TLS-3: a tool that failed by returning prose forces every caller to pattern-match English to
// decide whether to retry, and that match silently breaks when the wording changes.
func TestToolErrorsAreStructuredValues(t *testing.T) {
	t.Run("a structured error passes through", func(t *testing.T) {
		tool := readTool()
		tool.err = &agent.ToolError{Code: "ENOENT", Message: "no such file", Retryable: false}
		reg, _ := newRegistry(t, tool)

		record, err := reg.Invoke(context.Background(), agent.Call{
			Tool: "read_file", Input: json.RawMessage(`{"path":"a.go"}`), Actor: "u_1",
		}, invokeOptions(t))
		if err != nil {
			t.Fatalf("a tool failure is a recorded outcome, not a call failure: %v", err)
		}
		if record.Err == nil || record.Err.Code != "ENOENT" {
			t.Fatalf("error = %+v, want the structured value preserved", record.Err)
		}
		if record.Err.Retryable {
			t.Fatal("retryability was not preserved")
		}
	})

	t.Run("an unstructured error is given a code", func(t *testing.T) {
		tool := readTool()
		tool.err = errors.New("something went wrong")
		reg, _ := newRegistry(t, tool)

		record, err := reg.Invoke(context.Background(), agent.Call{
			Tool: "read_file", Input: json.RawMessage(`{"path":"a.go"}`), Actor: "u_1",
		}, invokeOptions(t))
		if err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if record.Err == nil || record.Err.Code == "" {
			t.Fatalf("error = %+v, want a code a caller can branch on", record.Err)
		}
	})
}

// T6, INV-13. A tool declaring its own result user_trusted would launder whatever it read — a file,
// an HTTP response, a subprocess's stdout — into the class the agent acts on without question.
func TestSecurityToolOutputIsAlwaysAtLeastToolResult(t *testing.T) {
	for name, declared := range map[string]taint.Class{
		"user trusted": taint.UserTrusted,
		"generated":    taint.Generated,
		"unset":        taint.Class(0),
	} {
		t.Run(name, func(t *testing.T) {
			tool := readTool()
			tool.output = agent.Output{Body: "contents", Provenance: declared}
			reg, _ := newRegistry(t, tool)

			record, err := reg.Invoke(context.Background(), agent.Call{
				Tool: "read_file", Input: json.RawMessage(`{"path":"a.go"}`), Actor: "u_1",
			}, invokeOptions(t))
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if record.Provenance < taint.ToolResult {
				t.Fatalf("provenance = %v, want at least tool_result", record.Provenance)
			}
		})
	}

	// A higher class is preserved, not clamped down: a tool that knows its output is a web fetch
	// must be able to say so.
	tool := readTool()
	tool.output = agent.Output{Body: "fetched", Provenance: taint.Web}
	reg, _ := newRegistry(t, tool)
	record, err := reg.Invoke(context.Background(), agent.Call{
		Tool: "read_file", Input: json.RawMessage(`{"path":"a.go"}`), Actor: "u_1",
	}, invokeOptions(t))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if record.Provenance != taint.Web {
		t.Fatalf("provenance = %v, want web preserved", record.Provenance)
	}
}

// T7. TLS-5: oversized output truncates and exposes a handle. Dropping the overflow silently is the
// loss the requirement exists to prevent.
func TestOversizedOutputIsTruncatedWithAHandle(t *testing.T) {
	body := strings.Repeat("x", agent.MaxOutputBytes*2)
	tool := readTool()
	tool.output = agent.Output{Body: body, Provenance: taint.ToolResult}
	reg, artifacts := newRegistry(t, tool)

	record, err := reg.Invoke(context.Background(), agent.Call{
		Tool: "read_file", Input: json.RawMessage(`{"path":"a.go"}`), Actor: "u_1",
	}, invokeOptions(t))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if !record.Truncated {
		t.Fatal("an oversized output was not marked truncated")
	}
	if record.ArtifactRef == "" {
		t.Fatal("no artifact handle for the truncated remainder")
	}
	if len(record.Output) != agent.MaxOutputBytes {
		t.Fatalf("recorded output = %d bytes, want %d", len(record.Output), agent.MaxOutputBytes)
	}
	if len(artifacts.stored) != 1 || artifacts.stored[0] != body {
		t.Fatal("the full output was not handed to the artifact store")
	}
	// The hash covers the full output, so a truncated record still proves what was produced.
	whole := sha256.Sum256([]byte(body))
	if record.ResultHash != "sha256:"+hex.EncodeToString(whole[:]) {
		t.Fatal("the result hash does not cover the whole output; a truncated record would prove nothing")
	}

	// A store failure fails the call rather than returning a quietly incomplete result.
	failing := readTool()
	failing.output = agent.Output{Body: body, Provenance: taint.ToolResult}
	failingReg, artifacts2 := newRegistry(t, failing)
	artifacts2.err = errors.New("disk full")
	if _, err := failingReg.Invoke(context.Background(), agent.Call{
		Tool: "read_file", Input: json.RawMessage(`{"path":"a.go"}`), Actor: "u_1",
	}, invokeOptions(t)); err == nil {
		t.Fatal("a failed artifact store must fail the call, not silently truncate")
	}
}

// T8. A denied decision means the tool is never invoked. There is no path from the decision to
// Invoke that skips it.
func TestSecurityADeniedDecisionNeverReachesTheTool(t *testing.T) {
	tool := readTool()
	// A destructive tool under the default settings requires approval rather than allowing.
	tool.def.SideEffect = mustSideEffect("locally_destructive")
	reg, _ := newRegistry(t, tool)

	record, err := reg.Invoke(context.Background(), agent.Call{
		Tool: "read_file", Input: json.RawMessage(`{"path":"a.go"}`), Actor: "u_1",
	}, invokeOptions(t))

	if err == nil {
		t.Fatal("a destructive call with no approval must not be permitted")
	}
	if tool.invoked != 0 {
		t.Fatal("the tool ran despite a non-allow decision")
	}
	// The refusal is still evidence: the decision that produced it is recorded.
	if record.PolicyDecisionID == "" {
		t.Fatal("a refused call recorded no policy decision")
	}
	if record.Effect == policy.EffectAllow {
		t.Fatalf("effect = %q on a refused call", record.Effect)
	}
}

// T9. A changed input shape is a new version rather than a silent reinterpretation of the old one,
// and the operation hash binds an approval to the exact versioned call.
func TestSchemaVersionBindsTheCall(t *testing.T) {
	tool := readTool()
	reg, _ := newRegistry(t, tool)

	record, err := reg.Invoke(context.Background(), agent.Call{
		Tool: "read_file", Input: json.RawMessage(`{"path":"a.go"}`), Actor: "u_1",
	}, invokeOptions(t))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if record.SchemaVersion != tool.def.Version {
		t.Fatalf("recorded version = %d, want %d", record.SchemaVersion, tool.def.Version)
	}
	if got := tool.def.Qualified(); got != "read_file@v1" {
		t.Fatalf("qualified identity = %q", got)
	}

	// Two versions of one name are different identities, so an approval for one cannot cover the
	// other. The registry refuses the collision rather than letting the second shadow the first.
	v2 := readTool()
	v2.def.Version = 2
	if err := reg.Register(v2); !modberr.Is(err, modberr.CodeConflict) {
		t.Fatalf("error = %v, want a conflict; a second version must not shadow the first", err)
	}
}

// Definitions are ordered so a prompt built from them is reproducible — two runs given the same
// registry must produce the same tool list, or a recorded prompt is not reproducible evidence.
func TestDefinitionsAreOrdered(t *testing.T) {
	reg, _ := newRegistry(t)
	for _, name := range []string{"write_file", "read_file", "run_tests", "list_dir"} {
		tool := readTool()
		tool.def.Name = name
		if err := reg.Register(tool); err != nil {
			t.Fatalf("Register(%s): %v", name, err)
		}
	}

	want := []string{"list_dir", "read_file", "run_tests", "write_file"}
	for range 20 {
		got := make([]string, 0, 4)
		for _, d := range reg.Definitions() {
			got = append(got, d.Name)
		}
		if !equal(got, want) {
			t.Fatalf("definitions = %v, want %v", got, want)
		}
	}
}

// A registry assembled without its collaborators would be one where SFX-1 through SFX-5 do not
// exist, which is a different product rather than a weaker one.
func TestNewRegistryRefusesAnIncompleteConfiguration(t *testing.T) {
	if _, err := agent.NewRegistry(nil, agent.BasicValidator{}, &fakeArtifacts{}); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal with no policy engine", err)
	}
	if _, err := agent.NewRegistry(policy.NewEngine(nil), nil, &fakeArtifacts{}); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal with no validator", err)
	}
	if _, err := agent.NewRegistry(policy.NewEngine(nil), agent.BasicValidator{}, nil); !modberr.Is(err, modberr.CodeInvalidArgument) {
		t.Fatalf("error = %v, want a refusal with no artifact store", err)
	}

	reg, _ := newRegistry(t)
	if _, err := reg.Invoke(context.Background(), agent.Call{Tool: "nope"}, invokeOptions(t)); !modberr.Is(err, modberr.CodeNotFound) {
		t.Fatalf("error = %v, want not found for an unregistered tool", err)
	}
}
