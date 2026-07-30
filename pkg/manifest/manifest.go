// Package manifest builds and applies the Instruction Manifest (INS-1..INS-8).
//
// Boundary: it decides which instructions are active for a model turn and whether work may proceed
// without them. It calls no model, compacts no transcript, and resolves no rule — pkg/rules decides
// precedence and this decides what the resolved set means for a run.
//
// Requirements: PRD §14 INS-1 (the manifest is the source of truth for active instructions), INS-2
// (every relevant model turn reconstructs required instructions from the manifest independently of
// transcript compaction), INS-3 (compaction summaries MUST NOT replace Rules), INS-4 (the trace
// exposes active instruction identifiers and hashes for each model turn), INS-5 (worktrees, remote
// handoff, delegation, resume and retries preserve applicable instructions or report differences),
// INS-6 (mandatory instruction resolution failure blocks mutating work where policy requires it),
// INS-7 (conflicts are visible and resolved through deterministic precedence), INS-8 (users can
// inspect and test activation).
//
// # The transcript is not an instruction source
//
// INS-2 and INS-3 are the same requirement approached twice, and they exist because of how
// compaction actually works. A long conversation gets summarised, the summary says "the user asked
// for tests to be written first", and that sentence is now the only trace of a Rule that said
// something more specific. The next turn reads the transcript, finds the sentence, and follows the
// paraphrase.
//
// Nothing about that looks like a failure. The agent is following instructions; they are just
// slightly different instructions, and the difference is invisible because the original is gone. So
// a Turn carries its compaction summary as a field this package can see and never reads for
// instructions — the same shape as REV-1's implementer rationale, and for the same reason: a check
// has to be able to see what it is refusing.
//
// # Mandatory means mutating work stops
//
// INS-6 blocks mutating work when a mandatory instruction fails to resolve. Not all work: reading
// the codebase with an incomplete instruction set is how a user finds out something is wrong, and
// refusing that too would leave them with an agent that will not talk to them about why it will not
// work.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/rules"
)

// Instruction is one active instruction in the manifest.
type Instruction struct {
	// ID identifies it across turns, worktrees and delegations.
	ID string `json:"id"`
	// Hash is the content hash. INS-4 requires both, because an id says which instruction was
	// active and a hash says which *version* of it — and a Rule edited mid-run keeps its id.
	Hash string `json:"hash"`
	// Mandatory marks an instruction whose absence blocks mutating work (INS-6).
	Mandatory bool `json:"mandatory"`
}

// Manifest is the immutable resolved instruction set for a run (INS-1).
type Manifest struct {
	ID string `json:"id"`
	// Instructions are the effective set, sorted by id. Immutable: a manifest that can be edited
	// after a turn has run is not a source of truth, it is a log of the current opinion.
	Instructions []Instruction `json:"instructions"`
	// Hash covers the whole set, so two manifests can be compared without walking them.
	Hash string `json:"hash"`
	// Conflicts are INS-7's surfaced disagreements, carried from rule resolution rather than
	// discarded once precedence has settled them. Precedence decides what applies; it does not make
	// the disagreement stop having happened.
	Conflicts []rules.Conflict `json:"conflicts,omitempty"`
}

// Build assembles a manifest from resolved rules (INS-1, INS-7).
//
// mandatory names the instruction ids whose absence blocks mutating work. It is a parameter rather
// than a field on a Rule because "mandatory" is a deployment's policy statement about an
// instruction, not a property the instruction's author gets to assert.
func Build(id string, resolved rules.Resolved, mandatory []string) (Manifest, error) {
	if strings.TrimSpace(id) == "" {
		return Manifest{}, field("a manifest has no id", "id")
	}
	required := make(map[string]bool, len(mandatory))
	for _, m := range mandatory {
		if strings.TrimSpace(m) == "" {
			return Manifest{}, field("a mandatory instruction has no id", "mandatory")
		}
		required[m] = true
	}

	m := Manifest{ID: id, Conflicts: resolved.Conflicts}
	seen := map[string]bool{}
	for _, r := range resolved.Effective {
		if seen[r.ID] {
			return Manifest{}, field(fmt.Sprintf(
				"instruction %s appears twice in the effective set", r.ID), "instructions")
		}
		seen[r.ID] = true
		m.Instructions = append(m.Instructions, Instruction{
			ID: r.ID, Hash: r.Hash(), Mandatory: required[r.ID],
		})
	}
	sort.Slice(m.Instructions, func(i, j int) bool {
		return m.Instructions[i].ID < m.Instructions[j].ID
	})

	// A mandatory instruction the resolution did not produce is the INS-6 case. It is recorded as a
	// missing mandatory rather than refused here, because Build is also how a caller discovers the
	// problem — refusing would leave them with no manifest to inspect.
	for _, want := range mandatory {
		if !seen[want] {
			m.Instructions = append(m.Instructions, Instruction{ID: want, Mandatory: true})
		}
	}
	sort.Slice(m.Instructions, func(i, j int) bool {
		return m.Instructions[i].ID < m.Instructions[j].ID
	})
	m.Hash = hashInstructions(m.Instructions)
	return m, nil
}

// hashInstructions covers ids and hashes together.
//
// Both, because a set with the same ids and different content is a different instruction set, and a
// hash over ids alone would call a mid-run Rule edit no change at all.
func hashInstructions(in []Instruction) string {
	h := sha256.New()
	for _, i := range in {
		fmt.Fprintf(h, "%s\x00%s\x00", i.ID, i.Hash)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Unresolved returns the mandatory instructions that did not resolve (INS-6).
func (m Manifest) Unresolved() []string {
	var out []string
	for _, i := range m.Instructions {
		if i.Mandatory && strings.TrimSpace(i.Hash) == "" {
			out = append(out, i.ID)
		}
	}
	sort.Strings(out)
	return out
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

func denied(msg, constraint string) error {
	return modberr.New(modberr.CodePolicyDenied, msg).WithDetail("constraint", constraint)
}

// Turn is one model turn's context.
type Turn struct {
	Index int `json:"index"`
	// CompactionSummary is the summarised transcript, when the conversation has been compacted.
	//
	// It is a field this package can see and never reads for instructions. INS-3 forbids a summary
	// replacing a Rule, and the way that happens is not malice: a summary says "the user asked for
	// tests first", the next turn reads the transcript, and it follows the paraphrase. Nothing about
	// that looks like a failure. Holding the field makes the refusal checkable.
	CompactionSummary string `json:"compaction_summary,omitempty"`
	// Mutating marks a turn that will change something (INS-6).
	Mutating bool `json:"mutating"`
}

// TurnTrace is INS-4's per-turn record.
type TurnTrace struct {
	TurnIndex int `json:"turn_index"`
	// InstructionIDs and InstructionHashes are reported together and in the same order. INS-4 asks
	// for both: the id says which instruction was active, the hash says which version — and a Rule
	// edited mid-run keeps its id.
	InstructionIDs    []string `json:"instruction_ids"`
	InstructionHashes []string `json:"instruction_hashes"`
	// ManifestHash lets two turns be compared without walking their instruction lists.
	ManifestHash string `json:"manifest_hash"`
}

// Reconstruct produces a turn's instructions from the manifest (INS-2, INS-3, INS-4).
//
// The turn is an input for its index and its mutating flag only. Its compaction summary is never
// consulted, which is what makes reconstruction independent of compaction rather than merely
// resilient to it.
func (m Manifest) Reconstruct(t Turn) (TurnTrace, error) {
	if strings.TrimSpace(m.ID) == "" {
		return TurnTrace{}, field("a turn cannot be reconstructed from an empty manifest", "manifest")
	}
	if t.Index < 0 {
		return TurnTrace{}, field("a turn has a negative index", "index")
	}

	trace := TurnTrace{TurnIndex: t.Index, ManifestHash: m.Hash}
	for _, i := range m.Instructions {
		if strings.TrimSpace(i.Hash) == "" {
			// An unresolved mandatory instruction contributes nothing to the turn. It is reported
			// through Unresolved and blocks mutating work through AdmitTurn; putting a hashless
			// entry in the trace would make the trace claim an instruction was active.
			continue
		}
		trace.InstructionIDs = append(trace.InstructionIDs, i.ID)
		trace.InstructionHashes = append(trace.InstructionHashes, i.Hash)
	}
	return trace, nil
}

// Policy is the deployment's stance on unresolved mandatory instructions (INS-6).
type Policy struct {
	// BlockMutatingOnUnresolved is INS-6's "where policy requires it". The zero value is false,
	// which is the permissive reading and is deliberate: INS-6 says policy decides, and a
	// deployment that has not decided has not decided. Unresolved instructions are still reported.
	BlockMutatingOnUnresolved bool `json:"block_mutating_on_unresolved"`
}

// AdmitTurn decides whether a turn may proceed (INS-6).
//
// Only mutating work is blocked. Reading the codebase with an incomplete instruction set is how a
// user finds out something is wrong, and refusing that too leaves them with an agent that will not
// explain why it will not work.
func (m Manifest) AdmitTurn(t Turn, p Policy) error {
	missing := m.Unresolved()
	if len(missing) == 0 {
		return nil
	}
	if !t.Mutating {
		return nil
	}
	if !p.BlockMutatingOnUnresolved {
		return nil
	}
	return denied(fmt.Sprintf(
		"mutating work is blocked: the mandatory instruction(s) %s did not resolve",
		strings.Join(missing, ", ")), "mandatory_instructions")
}

// Carriage is what happens to a manifest when work moves (INS-5).
type Carriage struct {
	// Preserved reports that the destination applies the same instruction set.
	Preserved bool `json:"preserved"`
	// Added and Removed name the differences, so "or report differences" reports them rather than
	// reporting that there are some.
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	// Changed names instructions present in both with different content — the case an id-only
	// comparison misses entirely, and the one a mid-run Rule edit produces.
	Changed []string `json:"changed,omitempty"`
}

// Carry compares a manifest against the one a destination will apply (INS-5).
//
// Covers worktrees, remote handoff, delegation, resume and retries, because they are the same
// operation from this package's point of view: work continues somewhere the instruction set was
// resolved separately.
func Carry(from, to Manifest) (Carriage, error) {
	if strings.TrimSpace(from.ID) == "" || strings.TrimSpace(to.ID) == "" {
		return Carriage{}, field("a carriage compares an empty manifest", "manifest")
	}

	fromByID := make(map[string]Instruction, len(from.Instructions))
	for _, i := range from.Instructions {
		fromByID[i.ID] = i
	}
	toByID := make(map[string]Instruction, len(to.Instructions))
	for _, i := range to.Instructions {
		toByID[i.ID] = i
	}

	c := Carriage{}
	for id, src := range fromByID {
		dst, present := toByID[id]
		switch {
		case !present:
			c.Removed = append(c.Removed, id)
		case src.Hash != dst.Hash:
			c.Changed = append(c.Changed, id)
		}
	}
	for id := range toByID {
		if _, present := fromByID[id]; !present {
			c.Added = append(c.Added, id)
		}
	}
	sort.Strings(c.Added)
	sort.Strings(c.Removed)
	sort.Strings(c.Changed)

	c.Preserved = len(c.Added) == 0 && len(c.Removed) == 0 && len(c.Changed) == 0
	return c, nil
}

// Activation is INS-8's dry-run result.
type Activation struct {
	// Active names the instructions that would apply.
	Active []string `json:"active"`
	// Inactive names the ones that would not, so "test activation" answers both halves — a user
	// checking why a Rule is not firing needs to see it considered and rejected, not simply absent.
	Inactive []string `json:"inactive"`
}

// TestActivation reports which instructions would apply, without applying them (INS-8).
//
// The manifest is passed by value and nothing here writes to it, which is what makes this a test
// rather than a run: an inspection that mutated what it inspected would answer a question about a
// state the user did not ask about.
func (m Manifest) TestActivation(candidates []string) Activation {
	active := make(map[string]bool, len(m.Instructions))
	for _, i := range m.Instructions {
		if strings.TrimSpace(i.Hash) != "" {
			active[i.ID] = true
		}
	}

	a := Activation{}
	for _, c := range candidates {
		if active[c] {
			a.Active = append(a.Active, c)
		} else {
			a.Inactive = append(a.Inactive, c)
		}
	}
	sort.Strings(a.Active)
	sort.Strings(a.Inactive)
	return a
}
