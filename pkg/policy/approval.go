package policy

import (
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/modberr"
)

// ApprovalBinding is a granted approval bound to the exact thing it authorized.
//
// Requirements: SFX-3 (approval binds to operation hash, scope, and expiration), SFX-4 (a changed
// operation invalidates the approval). The fence epoch is adopted under docs/adr/0100.
//
// # Why a fence epoch
//
// Operation hash and scope answer "is this the same work". They cannot answer "is this still the
// same worker". A run whose lease expires and is reassigned produces a second worker that can
// legitimately compute an identical operation hash — and would then execute against an approval
// granted to its predecessor, potentially duplicating an external effect the first worker already
// performed. Binding to a monotonically increasing lease epoch makes that stale execution
// detectable rather than indistinguishable.
//
// The field is an epoch, not a token: it is a counter, and it is not secret. Bearer lease material
// never appears here or in any error (R-ERR-02).
type ApprovalBinding struct {
	ID id.ID
	// OperationHash is the hash of the full intended effect the approver was shown.
	OperationHash string
	// Scope narrows the grant to a repository, path, or resource.
	Scope string
	// ApprovalClass is the class that was actually satisfied.
	ApprovalClass ApprovalClass
	// Approvers lists the distinct actors who approved. Two-person approval requires two.
	Approvers []string
	// FenceEpoch is the lease epoch current when the approval was granted. Zero means unfenced,
	// which is permitted only for operations that hold no lease.
	FenceEpoch uint64
	// PolicyVersion pins the policy bundle the decision was made under.
	PolicyVersion string
	ExpiresAt     time.Time
}

// Check reports whether the binding authorizes op at now.
//
// Every failure mode is distinguishable, because "your approval is stale" and "the work changed
// underneath you" call for different recovery: one needs a fresh lease, the other needs a fresh
// approval showing the new effect.
func (b ApprovalBinding) Check(op Operation, now time.Time) error {
	if b.OperationHash == "" || op.Hash == "" {
		return modberr.New(modberr.CodeApprovalInvalidated,
			"approval cannot bind to an operation with no hash").
			WithDetail("approval_id", b.ID.String())
	}
	if b.OperationHash != op.Hash {
		// SFX-4. Deliberately not reporting the hashes themselves as a diff — they are opaque, and
		// the useful signal is that they differ.
		return modberr.New(modberr.CodeApprovalInvalidated,
			"the operation changed after approval").
			WithDetail("approval_id", b.ID.String()).
			WithDetail("expected_operation_hash", b.OperationHash).
			WithDetail("actual_operation_hash", op.Hash)
	}
	if b.Scope != op.Scope {
		return modberr.New(modberr.CodeApprovalInvalidated,
			"the operation scope differs from the approved scope").
			WithDetail("approval_id", b.ID.String()).
			WithDetail("approval_scope", b.Scope)
	}
	if b.FenceEpoch != op.FenceEpoch {
		return modberr.New(modberr.CodeApprovalInvalidated,
			"the approval was granted under a different lease epoch; the work was reassigned").
			WithDetail("approval_id", b.ID.String()).
			WithDetail("fence_epoch", formatUint(b.FenceEpoch))
	}
	if !b.ExpiresAt.IsZero() && !now.Before(b.ExpiresAt) {
		// An expired approval is not a denial: the operation is still permissible, it just needs
		// asking again.
		return modberr.New(modberr.CodeApprovalRequired, "the approval expired").
			WithDetail("approval_id", b.ID.String()).
			WithDetail("approval_class", b.ApprovalClass.String())
	}
	if b.ApprovalClass == ApprovalTwoPerson && distinctApprovers(b.Approvers) < 2 {
		return modberr.New(modberr.CodeApprovalInvalidated,
			"two-person approval requires two distinct approvers").
			WithDetail("approval_id", b.ID.String())
	}
	return nil
}

// Satisfies reports whether the binding covers op at the required class.
func (b ApprovalBinding) Satisfies(op Operation, required ApprovalClass, now time.Time) bool {
	if b.Check(op, now) != nil {
		return false
	}
	return b.ApprovalClass >= required
}

func distinctApprovers(approvers []string) int {
	seen := make(map[string]struct{}, len(approvers))
	for _, a := range approvers {
		if a == "" {
			continue
		}
		seen[a] = struct{}{}
	}
	return len(seen)
}

func formatUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
