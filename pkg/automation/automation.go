// Package automation admits event-driven automation runs (AUT-1..AUT-8).
//
// Boundary: it decides whether an automation may be declared, whether a trigger may start a run, and
// whether a failed run may be retried. It listens to no events, calls no provider, and executes
// nothing.
//
// Requirements: PRD §14 AUT-1..AUT-8, and G12's summary that event-driven workflows are
// "idempotent, budgeted, permissioned, observable, and recoverable".
//
// # The retry rule is the whole package
//
// AUT-5: "Retries must not duplicate irreversible side effects." Retry is what makes an automation
// reliable and it is also what makes it dangerous, because the failure that prompts a retry rarely
// says whether the side effect landed. A publish that timed out may have published. So the safe
// default is not "retry carefully" — it is that an operation which cannot be undone is not retried
// at all unless something external can prove the second attempt is the same attempt.
//
// That proof is the idempotency key (AUT-2). With one, a retry is a resubmission the receiver can
// collapse. Without one, a retry of an irreversible operation is a second irreversible operation,
// and no amount of care inside this process changes that.
//
// # Why the declaration is checked before anything runs
//
// AUT-3 lists five things an automation must declare. Checking them at declaration rather than at
// trigger time is the difference between a configuration error and a 3am incident: an automation
// missing its retry policy is broken when it is written, not when it first fails.
package automation

import (
	"fmt"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/policy"
)

// RetryPolicy is how an automation handles failure (AUT-3, AUT-6).
type RetryPolicy struct {
	// MaxAttempts includes the first. One means no retry.
	MaxAttempts int `json:"max_attempts"`
	// Backoff is the delay before a retry.
	Backoff time.Duration `json:"backoff"`
	// DeadLetterAfter sends a run to dead-letter state once attempts are exhausted (AUT-6). Without
	// one, an exhausted automation fails silently and its work is simply lost.
	DeadLetter bool `json:"dead_letter"`
}

// OutputContract describes what an automation produces (AUT-3).
type OutputContract struct {
	// SchemaRef names the structured output contract the result conforms to.
	SchemaRef string `json:"schema_ref"`
}

// Declaration is everything AUT-3 requires an automation to state up front.
type Declaration struct {
	ID id.ID `json:"id"`
	// ServiceIdentity is who the automation runs as (AUT-1). Automations never run as a user: a
	// human identity on an unattended run makes the audit trail claim a person did something they
	// were not present for.
	ServiceIdentity string `json:"service_identity"`
	// Permissions are the tool and scope grants the automation may use.
	Permissions []string `json:"permissions"`
	// BudgetMicros bounds model spend. Zero is invalid rather than unlimited.
	BudgetMicros int64 `json:"budget_micros"`
	// EnvironmentID names where it executes.
	EnvironmentID string         `json:"environment_id"`
	Retry         RetryPolicy    `json:"retry"`
	Output        OutputContract `json:"output"`
	// MaxConcurrency and Timeout are AUT-6's other two bounds.
	MaxConcurrency int           `json:"max_concurrency"`
	Timeout        time.Duration `json:"timeout"`
	// ExternalMutationApproved records the explicit policy AUT-4 requires before an automation may
	// mutate anything outside the workspace.
	ExternalMutationApproved bool `json:"external_mutation_approved"`
}

// Validate enforces AUT-1, AUT-3 and AUT-6 at declaration time.
func (d Declaration) Validate() error {
	switch {
	case d.ID.IsZero():
		return field("an automation has no identifier", "id")
	case strings.TrimSpace(d.ServiceIdentity) == "":
		return field("an automation names no service identity", "service_identity")
	case len(d.Permissions) == 0:
		// An automation granted nothing can do nothing, so an empty list is a declaration somebody
		// forgot rather than a deliberately powerless automation.
		return field("an automation declares no permissions", "permissions")
	case d.BudgetMicros <= 0:
		// Zero is not unlimited. An unbudgeted automation is the one that runs all night.
		return field("an automation declares no model budget", "budget_micros")
	case strings.TrimSpace(d.EnvironmentID) == "":
		return field("an automation names no execution environment", "environment_id")
	case d.Retry.MaxAttempts < 1:
		return field("an automation declares no retry policy", "retry")
	case d.Retry.MaxAttempts > 1 && !d.Retry.DeadLetter:
		// AUT-6 pairs retry with dead-letter. Retrying without one means an exhausted run disappears,
		// which is the observability half of G12 quietly absent.
		return field(
			"an automation that retries must declare a dead-letter state so exhausted runs are visible",
			"retry")
	case strings.TrimSpace(d.Output.SchemaRef) == "":
		return field("an automation declares no output contract", "output")
	case d.MaxConcurrency < 1:
		return field("an automation declares no concurrency limit", "max_concurrency")
	case d.Timeout <= 0:
		return field("an automation declares no timeout", "timeout")
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

// Trigger is one attempt to start a run from an event.
type Trigger struct {
	// EventID links the run to its source (AUT-7).
	EventID id.ID `json:"event_id"`
	// IdempotencyKey is what lets a duplicate delivery be recognised (AUT-2) and what makes a retry
	// of an irreversible operation safe (AUT-5).
	IdempotencyKey string `json:"idempotency_key"`
	// Attempt is 1 for the first delivery.
	Attempt int `json:"attempt"`
	// SideEffect is the strongest class the run may perform.
	SideEffect policy.SideEffectClass `json:"side_effect"`
	// ExternalMutation reports whether the run mutates anything outside the workspace (AUT-4).
	ExternalMutation bool `json:"external_mutation"`
}

// Decision is whether a trigger may start a run.
type Decision struct {
	Admit bool `json:"admit"`
	// DeadLetter is set when the trigger is refused terminally and the run should be recorded rather
	// than dropped (AUT-6).
	DeadLetter bool   `json:"dead_letter,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Admit decides whether a trigger may start a run.
func Admit(d Declaration, t Trigger) (Decision, error) {
	if err := d.Validate(); err != nil {
		return Decision{}, err
	}
	if t.EventID.IsZero() {
		// AUT-7 requires every run to link to its source event. Without one the run is unattributable
		// the moment it finishes.
		return Decision{}, field("a trigger names no source event", "event_id")
	}
	if t.Attempt < 1 {
		return Decision{}, field("a trigger has no attempt number", "attempt")
	}
	if t.SideEffect == policy.SideEffectUndeclared {
		// The zero class is invalid in pkg/policy for the same reason it is invalid here: an
		// undeclared operation must not be evaluated as harmless.
		return Decision{}, field("a trigger declares no side-effect class", "side_effect")
	}

	// AUT-4: external mutation needs explicit policy, and it is checked before retry logic because
	// an automation that was never allowed to mutate should be told that rather than told about
	// idempotency.
	if t.ExternalMutation && !d.ExternalMutationApproved {
		return Decision{DeadLetter: true,
			Reason: "the automation mutates external state without the explicit policy AUT-4 requires"}, nil
	}

	if t.Attempt > d.Retry.MaxAttempts {
		return Decision{DeadLetter: d.Retry.DeadLetter,
			Reason: fmt.Sprintf("attempt %d exceeds the declared maximum of %d",
				t.Attempt, d.Retry.MaxAttempts)}, nil
	}

	// AUT-5, and the reason the package exists. A first attempt is not a retry, so it proceeds on
	// the declaration alone.
	if t.Attempt > 1 && t.SideEffect == policy.ExternallyIrreversible &&
		strings.TrimSpace(t.IdempotencyKey) == "" {
		// Terminal rather than deferred: waiting will not produce a key, and the failure that
		// prompted the retry rarely says whether the first attempt landed. A publish that timed out
		// may have published.
		return Decision{DeadLetter: true,
			Reason: "an externally irreversible operation cannot be retried without an idempotency key; " +
				"the first attempt may already have succeeded"}, nil
	}

	return Decision{Admit: true}, nil
}

// Retryable reports whether a failure class may be retried at all for this side effect.
//
// Separate from Admit because a caller often needs to know before constructing a trigger — and
// because stating it once keeps a scheduler from inventing its own rule.
func Retryable(class policy.SideEffectClass, hasIdempotencyKey bool) bool {
	if class == policy.SideEffectUndeclared {
		return false
	}
	if class == policy.ExternallyIrreversible {
		return hasIdempotencyKey
	}
	return true
}
