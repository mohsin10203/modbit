package modberr_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

func TestCodeCarriesCatalogSemantics(t *testing.T) {
	t.Parallel()
	e := modberr.New(modberr.CodePolicyDenied, "operation denied by policy")

	if e.Code() != modberr.CodePolicyDenied {
		t.Errorf("code = %q", e.Code())
	}
	if e.Retryable() {
		t.Error("MODBIT_POLICY_DENIED must not be retryable")
	}
	if e.HTTPStatus() != 403 {
		t.Errorf("status = %d, want 403", e.HTTPStatus())
	}
	if !modberr.Is(e, modberr.CodePolicyDenied) {
		t.Error("Is should match the code")
	}
	if modberr.IsRetryable(e) {
		t.Error("IsRetryable should be false")
	}
}

func TestRetryableCodeIsMarkedRetryable(t *testing.T) {
	t.Parallel()
	e := modberr.New(modberr.CodeProviderUnavailable, "provider is unavailable")
	if !e.Retryable() || !modberr.IsRetryable(e) {
		t.Error("MODBIT_PROVIDER_UNAVAILABLE must be retryable")
	}
}

// An uncatalogued code must not reach the wire; it degrades to MODBIT_INTERNAL and the attempted
// code is recorded as a diagnostic.
func TestUncataloguedCodeDegradesToInternal(t *testing.T) {
	t.Parallel()
	e := modberr.New(modberr.Code("MODBIT_INVENTED"), "something happened")
	if e.Code() != modberr.CodeInternal {
		t.Errorf("code = %q, want MODBIT_INTERNAL", e.Code())
	}
	if got := e.Details()["uncatalogued_code"]; got != "MODBIT_INVENTED" {
		t.Errorf("diagnostic = %q, want the attempted code", got)
	}
}

func TestWrapPreservesTheCauseForErrorsIs(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("underlying driver failure")
	e := modberr.Wrap(sentinel, modberr.CodeUnavailable, "storage is unavailable")

	if !errors.Is(e, sentinel) {
		t.Error("errors.Is must find the wrapped cause")
	}
	if modberr.CodeOf(e) != modberr.CodeUnavailable {
		t.Errorf("code = %q", modberr.CodeOf(e))
	}
	if !strings.Contains(e.Error(), "underlying driver failure") {
		t.Errorf("operator view should include the cause: %s", e.Error())
	}
}

func TestWrapOfNilIsNil(t *testing.T) {
	t.Parallel()
	if e := modberr.Wrap(nil, modberr.CodeInternal, "unused"); e != nil {
		t.Errorf("Wrap(nil) = %v, want nil", e)
	}
}

// R-ERR-02: the wire view must never carry the cause chain, which routinely contains file paths,
// driver messages, and upstream response bodies.
func TestWireViewExcludesTheCauseChain(t *testing.T) {
	t.Parallel()
	secretish := errors.New("dial tcp 10.0.0.5:5432: password=hunter2 rejected")
	e := modberr.Wrap(secretish, modberr.CodeUnavailable, "storage is unavailable")

	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), "hunter2") || strings.Contains(string(encoded), "10.0.0.5") {
		t.Fatalf("wire view leaked the cause: %s", encoded)
	}
	if !strings.Contains(string(encoded), "storage is unavailable") {
		t.Errorf("wire view lost the developer message: %s", encoded)
	}
}

func TestWireShapeMatchesTheAPIContract(t *testing.T) {
	t.Parallel()
	correlation := id.MustNew(id.Correlation)
	decision := id.MustNew(id.PolicyDecision)
	e := modberr.New(modberr.CodePolicyDenied, "Operation denied by policy.").
		WithCorrelation(correlation).
		WithDetail("policy_decision_id", decision.String())

	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var envelope struct {
		Error struct {
			Code          string            `json:"code"`
			Message       string            `json:"message"`
			Retryable     bool              `json:"retryable"`
			CorrelationID string            `json:"correlation_id"`
			Details       map[string]string `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if envelope.Error.Code != "MODBIT_POLICY_DENIED" {
		t.Errorf("code = %q", envelope.Error.Code)
	}
	if envelope.Error.CorrelationID != correlation.String() {
		t.Errorf("correlation = %q", envelope.Error.CorrelationID)
	}
	if envelope.Error.Details["policy_decision_id"] != decision.String() {
		t.Errorf("details = %v", envelope.Error.Details)
	}
}

// The allowlist is the mechanical control behind R-ERR-02: an implementer cannot slip a value into
// an error by inventing a key.
func TestUnregisteredDetailKeysAreDroppedAndNamed(t *testing.T) {
	t.Parallel()
	e := modberr.New(modberr.CodePolicyDenied, "denied").
		WithDetail("policy_decision_id", "pdec_ok").
		WithDetail("provider_api_key", "sk-live-should-never-appear").
		WithDetail("raw_prompt", "the user asked about their password")

	details := e.Details()
	for k, v := range details {
		if strings.Contains(v, "sk-live") || strings.Contains(v, "password") {
			t.Fatalf("a rejected detail value was retained under %q: %q", k, v)
		}
	}
	if details["policy_decision_id"] != "pdec_ok" {
		t.Errorf("allowlisted detail was dropped: %v", details)
	}
	dropped := details["unregistered_detail_keys"]
	if !strings.Contains(dropped, "provider_api_key") || !strings.Contains(dropped, "raw_prompt") {
		t.Errorf("rejected key names = %q, want both keys named", dropped)
	}

	encoded, _ := json.Marshal(e)
	if strings.Contains(string(encoded), "sk-live") {
		t.Fatalf("rejected value reached the wire: %s", encoded)
	}
}

func TestWithDetailsIsDeterministic(t *testing.T) {
	t.Parallel()
	build := func() string {
		e := modberr.New(modberr.CodePolicyDenied, "denied").WithDetails(map[string]string{
			"zeta": "1", "alpha": "2", "policy_decision_id": "pdec_1",
		})
		return e.Details()["unregistered_detail_keys"]
	}
	first, second := build(), build()
	if first != second {
		t.Fatalf("rejected-key list is not deterministic: %q vs %q", first, second)
	}
	if first != "alpha,zeta" {
		t.Errorf("rejected keys = %q, want alpha,zeta", first)
	}
}

func TestWithMethodsDoNotMutateTheReceiver(t *testing.T) {
	t.Parallel()
	base := modberr.New(modberr.CodePolicyDenied, "denied")
	derived := base.WithDetail("policy_decision_id", "pdec_1")

	if len(base.Details()) != 0 {
		t.Errorf("receiver was mutated: %v", base.Details())
	}
	if derived.Details()["policy_decision_id"] != "pdec_1" {
		t.Errorf("derived error lost the detail: %v", derived.Details())
	}
}

func TestWithCorrelationRejectsAForeignIdentifier(t *testing.T) {
	t.Parallel()
	e := modberr.New(modberr.CodeInternal, "internal").WithCorrelation(id.MustNew(id.Run))
	if !e.CorrelationID().IsZero() {
		t.Errorf("correlation = %q, want the run identifier to be refused", e.CorrelationID())
	}
}

// R-CTR-05: an older reader must not discard a newer peer's diagnostics.
func TestUnmarshalPreservesUnknownDetails(t *testing.T) {
	t.Parallel()
	wire := `{"error":{"code":"MODBIT_POLICY_DENIED","message":"denied","retryable":false,` +
		`"details":{"policy_decision_id":"pdec_1","a_future_field":"value"}}}`

	var e modberr.Error
	if err := json.Unmarshal([]byte(wire), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.Code() != modberr.CodePolicyDenied {
		t.Errorf("code = %q", e.Code())
	}
	if e.Details()["a_future_field"] != "value" {
		t.Errorf("a newer peer's detail was discarded: %v", e.Details())
	}
}

// An unclassified failure must never be presented as a well-understood one.
func TestCodeOfAnAlienErrorIsInternal(t *testing.T) {
	t.Parallel()
	if got := modberr.CodeOf(errors.New("something from a third-party library")); got != modberr.CodeInternal {
		t.Errorf("CodeOf = %q, want MODBIT_INTERNAL", got)
	}
	if got := modberr.CodeOf(nil); got != "" {
		t.Errorf("CodeOf(nil) = %q, want the empty code", got)
	}
	if got := modberr.HTTPStatusOf(errors.New("alien")); got != 500 {
		t.Errorf("HTTPStatusOf = %d, want 500", got)
	}
}

func TestCatalogCompleteness(t *testing.T) {
	t.Parallel()
	codes := modberr.Codes()
	if len(codes) < 40 {
		t.Errorf("catalog has %d codes, want the full contract", len(codes))
	}
	// The v5.1 error codes named in api-and-events-v5.1.md must all be present.
	for _, required := range []modberr.Code{
		modberr.CodeTaintEscalationRequired,
		modberr.CodeAdequacyThresholdFailed,
		modberr.CodeCanaryHold,
		modberr.CodeCoordinationConflict,
		modberr.CodeCapabilityUnavailable,
	} {
		spec, ok := modberr.Lookup(required)
		if !ok {
			t.Errorf("catalog is missing %q", required)
			continue
		}
		if spec.Description == "" {
			t.Errorf("%q has no description", required)
		}
	}
}

// No detail key in the catalog may invite a sensitive value. The generator rejects these too; this
// asserts the generated catalog actually satisfies the rule.
func TestNoDetailKeyNamesASensitiveValue(t *testing.T) {
	t.Parallel()
	banned := []string{"secret", "token", "password", "credential", "cookie", "authorization", "prompt", "completion", "api_key"}
	for _, code := range modberr.Codes() {
		spec, _ := modberr.Lookup(code)
		for _, key := range spec.DetailKeys {
			for _, b := range banned {
				if strings.Contains(key, b) {
					t.Errorf("%s declares detail key %q containing %q", code, key, b)
				}
			}
		}
	}
}

func TestNewfFormatsTheMessage(t *testing.T) {
	t.Parallel()
	e := modberr.Newf(modberr.CodeSettingUnknown, "settings key %q is not registered", "agent.invented")
	want := fmt.Sprintf("settings key %q is not registered", "agent.invented")
	if e.Message() != want {
		t.Errorf("message = %q, want %q", e.Message(), want)
	}
}
