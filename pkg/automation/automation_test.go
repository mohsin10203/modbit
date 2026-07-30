package automation_test

import (
	"strings"
	"testing"
	"time"

	"github.com/modbit/modbit/pkg/automation"
	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/policy"
)

// AUT invariants (U1–U8). One test each; a test without a U-number, or a U-number without a test,
// is a gap.
//
//	U1 AUT-3: a declaration missing any required part is refused at declaration time.
//	U2 AUT-5: an irreversible operation is not retried without an idempotency key.
//	U3 AUT-5: a *first* attempt at an irreversible operation is not a retry and proceeds.
//	U4 AUT-5: a reversible or compensatable operation retries freely.
//	U5 AUT-4: external mutation without explicit policy is refused terminally.
//	U6 AUT-6: exhausting attempts dead-letters rather than disappearing.
//	U7 The undeclared side-effect class is refused, not treated as harmless.
//	U8 AUT-7: a trigger with no source event is refused.

func declaration() automation.Declaration {
	return automation.Declaration{
		ID: id.MustNew(id.Automation), ServiceIdentity: "svc-nightly",
		Permissions: []string{"repo:read", "issue:write"}, BudgetMicros: 5_000_000,
		EnvironmentID:  "env-1",
		Retry:          automation.RetryPolicy{MaxAttempts: 3, Backoff: time.Second, DeadLetter: true},
		Output:         automation.OutputContract{SchemaRef: "schemas/triage.v1.json"},
		MaxConcurrency: 2, Timeout: 10 * time.Minute,
	}
}

func trigger(attempt int, class policy.SideEffectClass) automation.Trigger {
	return automation.Trigger{
		EventID: id.MustNew(id.TraceEvent), Attempt: attempt, SideEffect: class,
	}
}

// U1. AUT-3 lists five required declarations; each absence is a configuration error, caught when
// the automation is written rather than at 3am when it first fails.
func TestAUT3RequiresEveryDeclaration(t *testing.T) {
	for name, mutate := range map[string]func(*automation.Declaration){
		"no id":          func(d *automation.Declaration) { d.ID = "" },
		"no identity":    func(d *automation.Declaration) { d.ServiceIdentity = " " },
		"no permissions": func(d *automation.Declaration) { d.Permissions = nil },
		"no budget":      func(d *automation.Declaration) { d.BudgetMicros = 0 },
		"no environment": func(d *automation.Declaration) { d.EnvironmentID = "" },
		"no retry":       func(d *automation.Declaration) { d.Retry.MaxAttempts = 0 },
		"no output":      func(d *automation.Declaration) { d.Output.SchemaRef = "" },
		"no concurrency": func(d *automation.Declaration) { d.MaxConcurrency = 0 },
		"no timeout":     func(d *automation.Declaration) { d.Timeout = 0 },
		// AUT-6 pairs retry with dead-letter: retrying without one means an exhausted run vanishes.
		"retry without dead-letter": func(d *automation.Declaration) { d.Retry.DeadLetter = false },
	} {
		d := declaration()
		mutate(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: an incomplete declaration validated", name)
		}
	}
	if err := declaration().Validate(); err != nil {
		t.Fatalf("a complete declaration was refused: %v", err)
	}
}

// U2. AUT-5: retries must not duplicate irreversible side effects.
//
// The failure that prompts a retry rarely says whether the side effect landed — a publish that
// timed out may have published. Without an idempotency key there is nothing that can make the
// second attempt the same attempt, so it is refused terminally rather than deferred: waiting will
// not produce a key.
func TestSecurityAnIrreversibleOperationIsNotRetriedWithoutAnIdempotencyKey(t *testing.T) {
	d := declaration()
	tr := trigger(2, policy.ExternallyIrreversible) // second attempt, no key

	got, err := automation.Admit(d, tr)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if got.Admit {
		t.Fatal("an irreversible operation was retried with no idempotency key")
	}
	if !got.DeadLetter {
		t.Fatal("the refusal did not dead-letter; the run would disappear rather than be recorded")
	}
	if !strings.Contains(got.Reason, "idempotency") {
		t.Fatalf("reason = %q; it must name what is missing", got.Reason)
	}

	// With a key, the retry is a resubmission the receiver can collapse.
	tr.IdempotencyKey = "evt-4417"
	got, err = automation.Admit(d, tr)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if !got.Admit {
		t.Fatalf("an irreversible retry with an idempotency key was refused: %s", got.Reason)
	}
}

// U3. A first attempt is not a retry.
//
// The rule is about duplication, so applying it to attempt 1 would forbid irreversible automations
// entirely rather than forbidding their repetition.
func TestAFirstIrreversibleAttemptIsNotARetry(t *testing.T) {
	got, err := automation.Admit(declaration(), trigger(1, policy.ExternallyIrreversible))
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if !got.Admit {
		t.Fatalf("a first irreversible attempt was refused: %s", got.Reason)
	}
}

// U4. Reversible and compensatable operations retry freely.
//
// AUT-5 names irreversible side effects specifically. Blocking a workspace edit or a compensatable
// comment would make the rule a general retry ban, which is not what it says and would remove the
// recoverability G12 asks for.
func TestReversibleAndCompensatableOperationsRetryFreely(t *testing.T) {
	for _, class := range []policy.SideEffectClass{
		policy.PureReadOnly, policy.WorkspaceReversible,
		policy.LocallyDestructive, policy.ExternallyCompensatable,
	} {
		got, err := automation.Admit(declaration(), trigger(3, class))
		if err != nil {
			t.Fatalf("%v: %v", class, err)
		}
		if !got.Admit {
			t.Errorf("%v was refused on retry: %s", class, got.Reason)
		}
		if !automation.Retryable(class, false) {
			t.Errorf("%v reported itself unretryable without a key", class)
		}
	}
	if automation.Retryable(policy.ExternallyIrreversible, false) {
		t.Error("an irreversible class reported itself retryable without a key")
	}
	if !automation.Retryable(policy.ExternallyIrreversible, true) {
		t.Error("an irreversible class with a key reported itself unretryable")
	}
}

// U5. AUT-4: external mutation requires explicit policy, and the refusal is terminal.
//
// Checked before the retry logic, because an automation that was never permitted to mutate should
// be told that rather than told about idempotency keys.
func TestSecurityExternalMutationRequiresExplicitPolicy(t *testing.T) {
	d := declaration() // ExternalMutationApproved is false
	tr := trigger(1, policy.ExternallyCompensatable)
	tr.ExternalMutation = true

	got, err := automation.Admit(d, tr)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if got.Admit {
		t.Fatal("an automation mutated external state without explicit policy")
	}
	if !strings.Contains(got.Reason, "external") {
		t.Fatalf("reason = %q; it must name the missing policy rather than idempotency", got.Reason)
	}

	d.ExternalMutationApproved = true
	if got, err := automation.Admit(d, tr); err != nil || !got.Admit {
		t.Fatalf("an approved external mutation was refused: %v %s", err, got.Reason)
	}
}

// U6. AUT-6: exhausting attempts dead-letters rather than disappearing.
func TestExhaustedAttemptsDeadLetter(t *testing.T) {
	d := declaration() // MaxAttempts 3
	got, err := automation.Admit(d, trigger(4, policy.WorkspaceReversible))
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if got.Admit {
		t.Fatal("a fourth attempt was admitted against a maximum of three")
	}
	if !got.DeadLetter {
		t.Fatal("an exhausted run was not dead-lettered; its work would be silently lost")
	}
}

// U7. The undeclared side-effect class is refused rather than evaluated as harmless.
//
// The same rule pkg/policy applies: the zero class is invalid, because a caller that forgot to set
// it would otherwise get the most permissive treatment.
func TestSecurityAnUndeclaredSideEffectIsRefused(t *testing.T) {
	if _, err := automation.Admit(declaration(), trigger(1, policy.SideEffectUndeclared)); err == nil {
		t.Fatal("a trigger with no declared side-effect class was evaluated")
	}
	if automation.Retryable(policy.SideEffectUndeclared, true) {
		t.Fatal("an undeclared class reported itself retryable even with a key")
	}
}

// U8. AUT-7: a run must link to its source event, so a trigger without one is refused.
func TestATriggerWithoutASourceEventIsRefused(t *testing.T) {
	tr := trigger(1, policy.WorkspaceReversible)
	tr.EventID = ""
	if _, err := automation.Admit(declaration(), tr); err == nil {
		t.Fatal("a trigger with no source event was admitted; the run would be unattributable")
	}

	tr = trigger(0, policy.WorkspaceReversible)
	if _, err := automation.Admit(declaration(), tr); err == nil {
		t.Fatal("a trigger with no attempt number was admitted")
	}
}
