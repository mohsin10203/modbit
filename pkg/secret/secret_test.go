package secret_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/secret"
)

// SEC invariants (T1–T9). One test each; a test without a T-number, or a T-number without a test,
// is a gap.
//
//	T1 SEC-14: the value is unreachable through formatting, JSON, and audit rendering.
//	T2 SEC-13: a lease is valid only in its exact six-coordinate context.
//	T3 SEC-13: a mismatch discloses which coordinate differed to nobody.
//	T4 SEC-10: the use count is enforced.
//	T5 SEC-13: expiry is enforced, and a lease with no expiry is refused at mint.
//	T6 SEC-16: revocation is immediate and idempotent.
//	T7 SEC-13: a binding with any coordinate missing is refused, since absence would widen it.
//	T8 SEC-13: child inheritance is denied by default.
//	T9 SEC-17: a tool failing the injection contract is told every unmet clause.

const value = "tsk-live-DO-NOT-DISCLOSE-4417"

func binding() secret.Binding {
	return secret.Binding{
		RunID: id.MustNew(id.Run), StepID: id.MustNew(id.RunStep),
		ToolID: "shell", ExecutableIdentity: "sha256:abcd", WorkerID: "worker-1",
		EnvironmentID: "env-1",
	}
}

func lease(t *testing.T, b secret.Binding, maxUses int) *secret.Lease {
	t.Helper()
	l, err := secret.NewLease(
		id.MustNew(id.SecretLease), b, "push to the package registry", value,
		time.Now().Add(time.Hour), maxUses)
	if err != nil {
		t.Fatalf("NewLease: %v", err)
	}
	return l
}

// T1. SEC-14 lists the places a secret must not appear; they are all places a string ends up when
// somebody formats a struct, so the defence has to be that formatting cannot reach it.
func TestSecurityTheValueIsUnreachableThroughEveryRenderingPath(t *testing.T) {
	b := binding()
	l := lease(t, b, 3)

	for _, rendered := range []string{
		fmt.Sprintf("%v", l), fmt.Sprintf("%s", l), fmt.Sprintf("%+v", l), fmt.Sprintf("%#v", l),
		l.Describe(),
	} {
		if strings.Contains(rendered, value) {
			t.Fatalf("a rendering disclosed the secret: %q", rendered)
		}
	}

	encoded, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), value) {
		t.Fatalf("JSON encoding disclosed the secret: %s", encoded)
	}
	// The audit rendering must still be useful, or callers will format the struct instead.
	if !strings.Contains(l.Describe(), "shell") {
		t.Fatalf("the audit line does not identify the tool: %q", l.Describe())
	}

	// And the accessor still works, or the boundary would be safe and useless.
	got, err := l.Use(b, time.Now())
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if got != value {
		t.Fatal("the lease does not carry the minted secret")
	}
}

// T2, T3. SEC-13 binds a lease to six coordinates, and every one participates.
//
// Five agreeing means the sixth was substituted, which is the theft case rather than a near miss: a
// token that works from the wrong place produces valid-looking use that nothing distinguishes from
// correct use.
func TestSecurityEveryBindingCoordinateIsChecked(t *testing.T) {
	b := binding()

	for name, mutate := range map[string]func(*secret.Binding){
		"run":        func(x *secret.Binding) { x.RunID = id.MustNew(id.Run) },
		"step":       func(x *secret.Binding) { x.StepID = id.MustNew(id.RunStep) },
		"tool":       func(x *secret.Binding) { x.ToolID = "other-tool" },
		"executable": func(x *secret.Binding) { x.ExecutableIdentity = "sha256:0000" },
		"worker":     func(x *secret.Binding) { x.WorkerID = "worker-2" },
		"env":        func(x *secret.Binding) { x.EnvironmentID = "env-2" },
	} {
		l := lease(t, b, 5)
		wrong := b
		mutate(&wrong)

		_, err := l.Use(wrong, time.Now())
		if err == nil {
			t.Errorf("%s substituted: the lease was used in the wrong context", name)
			continue
		}
		if !modberr.Is(err, modberr.CodePolicyDenied) {
			t.Errorf("%s: err = %v, want CodePolicyDenied", name, err)
		}
		// T3: the refusal must not say which coordinate differed, or a holder of a stolen value
		// could discover the binding by probing one field at a time.
		for _, leak := range []string{
			wrong.WorkerID, wrong.EnvironmentID, wrong.ToolID, wrong.ExecutableIdentity,
			b.WorkerID, b.EnvironmentID, b.ExecutableIdentity,
		} {
			if leak != "" && strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the refusal disclosed %q: %v", name, leak, err)
			}
		}
		// A failed use must not consume one.
		if l.Remaining() != 5 {
			t.Errorf("%s: a refused use decremented the count to %d", name, l.Remaining())
		}
	}
}

// T4. SEC-10 requires a use count, and it is enforced rather than recorded.
func TestSecurityTheUseCountIsEnforced(t *testing.T) {
	b := binding()
	l := lease(t, b, 2)

	for i := 0; i < 2; i++ {
		if _, err := l.Use(b, time.Now()); err != nil {
			t.Fatalf("use %d: %v", i+1, err)
		}
	}
	if l.Remaining() != 0 {
		t.Fatalf("remaining = %d after two uses of a two-use lease", l.Remaining())
	}
	if _, err := l.Use(b, time.Now()); err == nil {
		t.Fatal("a third use of a two-use lease succeeded")
	}
	if l.Live(time.Now()) {
		t.Fatal("an exhausted lease reports itself live")
	}

	// A lease permitting no uses is refused at mint rather than minted useless.
	if _, err := secret.NewLease(id.MustNew(id.SecretLease), b, "scope", value,
		time.Now().Add(time.Hour), 0); err == nil {
		t.Fatal("a zero-use lease was minted")
	}
}

// T5. SEC-13 requires leases to be short lived; expiry is enforced and no-expiry is refused.
func TestSecurityExpiryIsEnforcedAndRequired(t *testing.T) {
	b := binding()
	expired, err := secret.NewLease(id.MustNew(id.SecretLease), b, "scope", value,
		time.Now().Add(-time.Minute), 5)
	if err != nil {
		t.Fatalf("NewLease: %v", err)
	}
	if _, err := expired.Use(b, time.Now()); err == nil {
		t.Fatal("an expired lease was used")
	}

	if _, err := secret.NewLease(id.MustNew(id.SecretLease), b, "scope", value,
		time.Time{}, 5); err == nil {
		t.Fatal("a lease with no expiry was minted; that is the one that outlives the incident")
	}
}

// T6. SEC-16: revocation is immediate and idempotent.
//
// Revocation arrives from several directions at once — cancellation, expiry, worker loss, policy
// change — so a second call failing would turn a safe duplicate into an error somebody suppresses.
func TestSecurityRevocationIsImmediateAndIdempotent(t *testing.T) {
	b := binding()
	l := lease(t, b, 10)

	l.Revoke()
	l.Revoke() // must not panic or misbehave

	if _, err := l.Use(b, time.Now()); err == nil {
		t.Fatal("a revoked lease was used")
	}
	if l.Remaining() != 0 {
		t.Fatalf("a revoked lease reports %d uses remaining", l.Remaining())
	}
	if l.Live(time.Now()) {
		t.Fatal("a revoked lease reports itself live")
	}
}

// T7. A binding with any coordinate missing is refused, because absence would widen the lease.
func TestSecurityAnIncompleteBindingIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*secret.Binding){
		"no run":        func(b *secret.Binding) { b.RunID = "" },
		"no step":       func(b *secret.Binding) { b.StepID = "" },
		"no tool":       func(b *secret.Binding) { b.ToolID = " " },
		"no executable": func(b *secret.Binding) { b.ExecutableIdentity = "" },
		"no worker":     func(b *secret.Binding) { b.WorkerID = "" },
		"no env":        func(b *secret.Binding) { b.EnvironmentID = "" },
	} {
		b := binding()
		mutate(&b)
		if err := b.Validate(); err == nil {
			t.Errorf("%s: an incomplete binding validated", name)
		}
		if _, err := secret.NewLease(id.MustNew(id.SecretLease), b, "scope", value,
			time.Now().Add(time.Hour), 1); err == nil {
			t.Errorf("%s: a lease was minted on an incomplete binding", name)
		}
	}
}

// T8. SEC-13 denies child-process inheritance by default.
//
// A secret that survives into a child survives into whatever that child spawns, at which point the
// boundary stops being describable — so the permissive case must be asked for explicitly.
func TestSecurityChildInheritanceIsDeniedByDefault(t *testing.T) {
	l := lease(t, binding(), 1)
	if l.InheritToChildren {
		t.Fatal("a freshly minted lease inherits to child processes by default")
	}
}

// T9. SEC-17: a tool that cannot meet the injection contract is told every unmet clause.
//
// SEC-11 prefers brokered use, so the answer here is "may inject" and never "must". Naming each
// unmet clause is what lets a tool author implement them rather than just being refused.
func TestTheInjectionContractNamesEveryUnmetClause(t *testing.T) {
	ok, unmet := secret.MayInject(secret.InjectionContract{})
	if ok {
		t.Fatal("an empty injection contract was accepted")
	}
	if len(unmet) != 4 {
		t.Fatalf("unmet = %d clauses, want all four named: %v", len(unmet), unmet)
	}

	full := secret.InjectionContract{
		AdministratorApproved: true, SuppressesCommandEcho: true,
		ClearsOnExit: true, DeniesChildInheritance: true,
	}
	if ok, unmet := secret.MayInject(full); !ok || len(unmet) != 0 {
		t.Fatalf("a complete contract was refused: %v", unmet)
	}

	// SEC-12's administrator gate cannot be satisfied by the technical clauses alone.
	technical := full
	technical.AdministratorApproved = false
	if ok, _ := secret.MayInject(technical); ok {
		t.Fatal("injection was permitted without administrator approval")
	}
}
