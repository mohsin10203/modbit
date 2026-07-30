// Package rules resolves instruction rules deterministically and surfaces their conflicts
// (RUL-1..RUL-5).
//
// Boundary: it orders rules, decides which apply to a context, and reports where they disagree. It
// reads no files, executes nothing, and never merges two conflicting instructions into a third.
//
// Requirements: PRD §9C RUL-1..RUL-5, INV-9 (a lower scope must not weaken a higher-scope security
// policy) and INV-13 (repository instructions are untrusted input).
//
// # Surfacing a conflict rather than resolving it
//
// RUL-2 says conflicts "must be surfaced rather than silently resolved". That is a stronger claim
// than it looks. Precedence already picks a winner, so a resolver *could* apply the winner and say
// nothing — the output would be well defined and deterministic, and RUL-1 would be satisfied.
//
// It would also be the failure RUL-2 names. A repository rule saying "never run the linter" and an
// administrator rule saying "always run the linter" is not a precedence question the author of
// either one would recognise as settled; one of them is wrong and neither knows it. So `Resolve`
// returns the winner *and* the conflict, and a caller that ignores the second is making a choice
// rather than not seeing one.
//
// # Why a repository rule cannot outrank an administrator rule
//
// RUL-5 requires repository-authored instructions to be distinguishable from administrator policy,
// and INV-13 makes repository content untrusted input. Distinguishable is the floor, not the
// ceiling: a precedence order that let a repository rule win would mean a file in a cloned
// repository could switch off an organization's controls, which is prompt injection with a config
// file for a delivery mechanism.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Source is who authored a rule. The order of these constants is the precedence order (RUL-1).
type Source int

const (
	// SourceRepository is the zero value and the weakest, deliberately.
	//
	// A rule whose source nobody set is treated as repository-authored: untrusted, lowest
	// precedence. The alternative would let an unattributed rule outrank an administrator's, which
	// is the exact inversion RUL-5 exists to prevent.
	SourceRepository Source = iota
	// SourceUser is a developer's own configuration.
	SourceUser
	// SourceOrganization is org-level configuration.
	SourceOrganization
	// SourceAdministrator is managed policy and outranks everything.
	SourceAdministrator
)

var sourceNames = map[Source]string{
	SourceRepository:    "repository",
	SourceUser:          "user",
	SourceOrganization:  "organization",
	SourceAdministrator: "administrator",
}

// String renders a source for a trace line (RUL-1's visibility half).
func (s Source) String() string {
	if n, ok := sourceNames[s]; ok {
		return n
	}
	return "unknown"
}

// Trusted reports whether a source is administrator-controlled.
//
// Only repository content is untrusted under INV-13. A user's own configuration is theirs, and an
// organization's is the organization's; neither arrives from a cloned repository.
func (s Source) Trusted() bool { return s != SourceRepository }

// Provenance maps a source to its taint class, so a rule carries the same provenance vocabulary as
// every other piece of context (TNT-1).
func (s Source) Provenance() taint.Class {
	if s == SourceRepository {
		return taint.RepositoryUntrusted
	}
	return taint.UserTrusted
}

// Condition narrows where a rule applies (RUL-3).
type Condition struct {
	// PathGlob matches repository-relative paths. Empty matches every path.
	PathGlob string `json:"path_glob,omitempty"`
	// TaskType matches the run mode or task kind. Empty matches every task.
	TaskType string `json:"task_type,omitempty"`
}

// Matches reports whether the condition admits a context.
func (c Condition) Matches(ctx Context) (bool, error) {
	if c.TaskType != "" && c.TaskType != ctx.TaskType {
		return false, nil
	}
	if c.PathGlob == "" {
		return true, nil
	}
	ok, err := path.Match(c.PathGlob, ctx.Path)
	if err != nil {
		// A malformed glob is refused rather than treated as non-matching. Silently never matching
		// would disable a rule its author believes is active, which for an administrator rule means
		// a control that is off and looks on.
		return false, modberr.Newf(modberr.CodeInvalidArgument,
			"rule condition has a malformed path glob %q", c.PathGlob).WithDetail("field", "path_glob")
	}
	return ok, nil
}

// Context is what a rule set is being resolved against.
type Context struct {
	Path     string `json:"path"`
	TaskType string `json:"task_type"`
}

// Rule is one instruction.
type Rule struct {
	ID     string `json:"id"`
	Source Source `json:"source"`
	// Key names what the rule governs. Two rules sharing a key and disagreeing are a conflict.
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Condition Condition `json:"condition"`
}

// Hash is the content digest RUL-4 records.
//
// It covers everything that changes what the rule does, including its source: the same text from a
// repository and from an administrator are different rules, and a digest that collapsed them would
// make the recorded set unable to prove which one applied.
func (r Rule) Hash() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		r.ID, r.Source.String(), r.Key, r.Value, r.Condition.PathGlob, r.Condition.TaskType,
	}, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Validate checks a rule is usable.
func (r Rule) Validate() error {
	switch {
	case strings.TrimSpace(r.ID) == "":
		return modberr.New(modberr.CodeInvalidArgument, "a rule has no identifier").
			WithDetail("field", "id")
	case strings.TrimSpace(r.Key) == "":
		return modberr.Newf(modberr.CodeInvalidArgument, "rule %q governs no key", r.ID).
			WithDetail("field", "key")
	case r.Source < SourceRepository || r.Source > SourceAdministrator:
		return modberr.Newf(modberr.CodeInvalidArgument, "rule %q has an unknown source", r.ID).
			WithDetail("field", "source")
	}
	return nil
}

// Conflict is two applicable rules disagreeing on one key (RUL-2).
type Conflict struct {
	Key string `json:"key"`
	// Winner is the rule precedence selected; Loser is the one it displaced.
	Winner Rule `json:"winner"`
	Loser  Rule `json:"loser"`
	// AcrossTrustBoundary marks a conflict where an untrusted repository rule tried to displace a
	// trusted one. It is the case an operator should look at first: it is either a mistake or an
	// attempt.
	AcrossTrustBoundary bool `json:"across_trust_boundary"`
}

// Resolved is the outcome of resolution, and what RUL-4 records on the run.
type Resolved struct {
	// Effective is the winning rule per key, ordered by key for a stable record.
	Effective []Rule `json:"effective"`
	// Conflicts is every disagreement, surfaced rather than resolved away (RUL-2).
	Conflicts []Conflict `json:"conflicts"`
	// SetHash covers the effective set, so a run can prove which rules it applied (RUL-4).
	SetHash string `json:"set_hash"`
}

// Resolve orders rules, selects the effective set, and reports every conflict (RUL-1..RUL-4).
//
// Precedence is source first, then rule id for determinism. Two rules from the same source
// disagreeing on a key is still a conflict — it is not resolvable by authority, and picking by id
// is a tiebreak for reproducibility rather than a judgement about which is right.
func Resolve(rules []Rule, ctx Context) (Resolved, error) {
	applicable := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return Resolved{}, err
		}
		matches, err := r.Condition.Matches(ctx)
		if err != nil {
			return Resolved{}, err
		}
		if matches {
			applicable = append(applicable, r)
		}
	}

	// Highest source first, then id. Deterministic and total, which is RUL-1.
	sort.SliceStable(applicable, func(i, j int) bool {
		if applicable[i].Source != applicable[j].Source {
			return applicable[i].Source > applicable[j].Source
		}
		return applicable[i].ID < applicable[j].ID
	})

	winners := map[string]Rule{}
	var conflicts []Conflict
	for _, r := range applicable {
		existing, seen := winners[r.Key]
		if !seen {
			winners[r.Key] = r
			continue
		}
		if existing.Value == r.Value {
			// Agreement is not a conflict. Two sources stating the same thing is redundancy, and
			// reporting it would bury the disagreements RUL-2 exists to surface.
			continue
		}
		conflicts = append(conflicts, Conflict{
			Key: r.Key, Winner: existing, Loser: r,
			AcrossTrustBoundary: existing.Source.Trusted() != r.Source.Trusted(),
		})
	}

	effective := make([]Rule, 0, len(winners))
	for _, r := range winners {
		effective = append(effective, r)
	}
	sort.Slice(effective, func(i, j int) bool { return effective[i].Key < effective[j].Key })
	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Key != conflicts[j].Key {
			return conflicts[i].Key < conflicts[j].Key
		}
		return conflicts[i].Loser.ID < conflicts[j].Loser.ID
	})

	return Resolved{Effective: effective, Conflicts: conflicts, SetHash: hashSet(effective)}, nil
}

func hashSet(effective []Rule) string {
	h := sha256.New()
	for _, r := range effective {
		_, _ = h.Write([]byte(r.Hash()))
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// UntrustedRules returns the applicable rules that came from repository content (RUL-5, INV-13).
//
// Separate from the effective set because the Instruction Inspector shows provenance, and because a
// reviewer asking "what did this repository tell the agent" should not have to filter the answer out
// of a merged list.
func (r Resolved) UntrustedRules() []Rule {
	var out []Rule
	for _, rule := range r.Effective {
		if !rule.Source.Trusted() {
			out = append(out, rule)
		}
	}
	return out
}

// Describe renders the resolution for a trace (RUL-1's visibility half).
func (r Resolved) Describe() string {
	parts := make([]string, 0, len(r.Effective))
	for _, rule := range r.Effective {
		parts = append(parts, fmt.Sprintf("%s=%s(%s)", rule.Key, rule.Value, rule.Source))
	}
	line := strings.Join(parts, " ")
	if len(r.Conflicts) > 0 {
		line += fmt.Sprintf(" [%d conflict(s) surfaced]", len(r.Conflicts))
	}
	return line
}
