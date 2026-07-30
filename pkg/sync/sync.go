// Package sync decides which settings may leave a device and how conflicts are reported
// (SYNC-1..SYNC-3).
//
// Boundary: it decides eligibility and computes a field-level diff. It encrypts nothing, transports
// nothing, and never picks a winner between two conflicting values.
//
// Requirements: PRD §20A.9 SYNC-1..SYNC-3, SET-7 (secrets are forbidden in ordinary settings
// documents), and INV-11.
//
// # Eligibility is a denylist of kinds, not a per-key opt-out
//
// SYNC-2 names what is not synced by default: device settings, repository-local settings, secrets,
// browser cookies and terminal history. Three of those are scopes the Settings Registry already has,
// which means eligibility can be decided from the definition rather than from a hand-maintained
// list of excluded keys.
//
// That distinction is the point. A list of excluded keys is correct on the day it is written and
// wrong the first time somebody adds a device setting without reading it, and the failure is a
// device-local value silently appearing on another machine. Deciding from the scope means a new
// setting is classified by what it *is*.
//
// # Why a conflict is never resolved here
//
// SYNC-3 asks for a field-level diff. It does not ask for a merge, and last-write-wins is the
// obvious implementation that satisfies neither: two devices that both changed a value have a
// disagreement their owner has to see, and a timestamp comparison is not a judgement about which
// value is right. So `Reconcile` returns agreements and conflicts, and the conflicts carry both
// sides.
package sync

import (
	"fmt"
	"sort"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/settings"
)

// Eligibility is whether a setting may be synced, and why not when it may not.
type Eligibility struct {
	Eligible bool `json:"eligible"`
	// Reason explains an ineligible setting. Required, so a user asking why a preference did not
	// follow them gets an answer rather than an absence.
	Reason string `json:"reason,omitempty"`
}

// nonSyncingScopes are the scopes SYNC-2 excludes by their nature.
//
// Device settings describe this machine and repository-local settings describe this checkout;
// carrying either to another device makes it describe something that is not there.
var nonSyncingScopes = map[settings.Scope]string{
	settings.ScopeDevice: "device settings describe one machine, so syncing one would " +
		"describe a machine the other device is not",
	settings.ScopeRepositoryLocal: "repository-local settings describe one checkout",
	settings.ScopeSession:         "session settings do not outlive the session that made them",
}

// Eligible decides whether one setting may leave the device (SYNC-2, SET-7).
func Eligible(d settings.Definition, authored settings.Scope) (Eligibility, error) {
	if d.Key == "" {
		return Eligibility{}, modberr.New(modberr.CodeInvalidArgument, "a definition has no key").
			WithDetail("field", "key")
	}
	if reason, excluded := nonSyncingScopes[authored]; excluded {
		return Eligibility{Reason: reason}, nil
	}

	// SET-7 forbids secret values in ordinary settings documents, and INV-11 forbids secrets
	// leaving in any transport. A critical-class setting is not necessarily a secret, but this is
	// the wrong place to be clever: the cost of withholding one setting from sync is a preference
	// somebody re-enters, and the cost of the opposite mistake is a secret on another machine.
	if d.SecurityClass == settings.SecurityCritical {
		return Eligibility{Reason: "settings of critical security class are not synced by default"}, nil
	}

	// A setting that cannot be authored at a syncable scope has nothing to sync, and reporting it
	// as eligible would produce an empty payload a caller reads as agreement.
	syncable := false
	for _, s := range d.Scopes {
		if _, excluded := nonSyncingScopes[s]; !excluded {
			syncable = true
			break
		}
	}
	if !syncable {
		return Eligibility{Reason: "this setting can only be authored at scopes that do not sync"}, nil
	}

	return Eligibility{Eligible: true}, nil
}

// Value is one device's value for one key.
type Value struct {
	Key   settings.Key `json:"key"`
	Value any          `json:"value"`
}

// Field is one side of a field-level diff (SYNC-3).
type Field struct {
	Key settings.Key `json:"key"`
	// Local and Remote are both carried, because a diff a user has to reconstruct is not a diff.
	Local  any `json:"local"`
	Remote any `json:"remote"`
}

// Reconciliation is the outcome of comparing two devices' settings.
type Reconciliation struct {
	// Agreed are keys both sides hold identically.
	Agreed []settings.Key `json:"agreed"`
	// LocalOnly and RemoteOnly are keys present on one side. They are not conflicts: nothing
	// disagrees, and presenting them as conflicts would make the conflict list unreadable.
	LocalOnly  []settings.Key `json:"local_only"`
	RemoteOnly []settings.Key `json:"remote_only"`
	// Conflicts are keys both sides hold differently, with both values (SYNC-3).
	Conflicts []Field `json:"conflicts"`
	// Withheld are keys that were not compared because they are ineligible, with the reason.
	Withheld map[settings.Key]string `json:"withheld,omitempty"`
}

// Resolved reports whether the reconciliation needs no human decision.
func (r Reconciliation) Resolved() bool { return len(r.Conflicts) == 0 }

// Reconcile compares two devices' values and reports the differences (SYNC-3).
//
// It resolves nothing. Last-write-wins would satisfy neither half of SYNC-3 — it produces no diff
// and it makes a judgement a timestamp cannot support — so a conflict is returned with both values
// and the caller decides.
func Reconcile(defs map[settings.Key]settings.Definition, local, remote []Value,
	authored map[settings.Key]settings.Scope) (Reconciliation, error) {

	out := Reconciliation{Withheld: map[settings.Key]string{}}
	localByKey := index(local)
	remoteByKey := index(remote)

	keys := make(map[settings.Key]bool, len(localByKey)+len(remoteByKey))
	for k := range localByKey {
		keys[k] = true
	}
	for k := range remoteByKey {
		keys[k] = true
	}

	ordered := make([]settings.Key, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	for _, k := range ordered {
		d, known := defs[k]
		if !known {
			// SET-1 preserves unknown settings and reports them. Syncing one would carry a value
			// whose meaning and security class nobody here can determine.
			out.Withheld[k] = "the setting is not in the registry, so its security class is unknown"
			continue
		}
		e, err := Eligible(d, authored[k])
		if err != nil {
			return Reconciliation{}, err
		}
		if !e.Eligible {
			out.Withheld[k] = e.Reason
			continue
		}

		lv, hasLocal := localByKey[k]
		rv, hasRemote := remoteByKey[k]
		switch {
		case hasLocal && !hasRemote:
			out.LocalOnly = append(out.LocalOnly, k)
		case !hasLocal && hasRemote:
			out.RemoteOnly = append(out.RemoteOnly, k)
		case equal(lv, rv):
			out.Agreed = append(out.Agreed, k)
		default:
			out.Conflicts = append(out.Conflicts, Field{Key: k, Local: lv, Remote: rv})
		}
	}
	return out, nil
}

func index(values []Value) map[settings.Key]any {
	out := make(map[settings.Key]any, len(values))
	for _, v := range values {
		out[v.Key] = v.Value
	}
	return out
}

// equal compares two setting values.
//
// Rendered rather than compared with ==, because a setting value is `any` and two structurally
// equal values of different dynamic types would otherwise read as a conflict — which would fill the
// diff with disagreements that are not disagreements.
func equal(a, b any) bool {
	return fmt.Sprintf("%T:%v", a, a) == fmt.Sprintf("%T:%v", b, b)
}
