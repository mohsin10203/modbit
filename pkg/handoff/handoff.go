// Package handoff admits local-to-remote task handoffs (HND-1..HND-6, INS-5).
//
// Boundary: it decides whether a local task may be handed to a remote environment and what must be
// disclosed first. It transfers nothing, resolves no secret, and starts no remote run — a caller
// supplies both environments and this decides whether the move is sound.
//
// Requirements: PRD §20.4 HND-1 (hand a local task to a remote agent), HND-2 (what a handoff
// includes), HND-3 (secrets are not copied; the remote resolves separately authorized references),
// HND-4 (the target environment is validated before handoff), HND-5 (the user sees material
// differences in OS, tools, model policy, network, and available integrations), HND-6 (results
// return as a branch, pull request, artifact bundle, or patch), and §14 INS-5 (handoff preserves
// applicable instructions or reports differences). INV-2 makes HND-3 the credential boundary.
//
// # Differences are computed, not declared
//
// HND-5 asks that the user see material differences. The tempting shape is a Disclosure the source
// fills in, and it fails the same way a worker labelling itself does: the thing being described
// gets to describe itself, and the case that matters is the one where it is wrong. A source that
// has not noticed the target lacks Docker will not disclose that the target lacks Docker.
//
// So Differences takes both environments and derives the list. There is no field anywhere here by
// which a caller asserts that the environments match.
//
// # A handoff moves references, never material
//
// HND-3 says secrets are not copied and the remote resolves separately authorized references. Both
// halves matter. Not copying is INV-2. "Separately authorized" is the half that is easy to lose: a
// reference arriving from a trusted local session is still just a name, and the remote must decide
// whether *it* may resolve it. A handoff that carried resolved values would make the remote's
// authorization unreachable, so this refuses anything that looks like material rather than a name.
//
// # Unresolved questions travel
//
// They are the most droppable item on HND-2's list and the most consequential: an agent that
// resumes without them does not know it is missing anything, and produces a confident answer to a
// question the user had already flagged as open.
package handoff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Environment describes one side of a handoff, local or remote.
type Environment struct {
	ID string `json:"id"`
	// OrganizationID and SpaceID bound where a task may go (INV-10).
	OrganizationID string `json:"organization_id"`
	SpaceID        string `json:"space_id"`
	// OS is the platform, as "os/arch".
	OS string `json:"os"`
	// Tools are the tools available, sorted by the constructor.
	Tools []string `json:"tools"`
	// ModelPolicy names the effective model policy. Two environments under different policies
	// produce different work from the same instructions.
	ModelPolicy string `json:"model_policy"`
	// NetworkPolicy names the effective egress policy.
	NetworkPolicy string `json:"network_policy"`
	// Integrations are the connected integrations available.
	Integrations []string `json:"integrations"`
	// Validated records that the caller checked this environment is reachable and healthy (HND-4).
	// The zero value is false, so an environment nobody checked is not a validated one.
	Validated bool `json:"validated"`
}

// Difference is one material discrepancy between the environments (HND-5).
type Difference struct {
	// Dimension is one of HND-5's five.
	Dimension string `json:"dimension"`
	Local     string `json:"local"`
	Remote    string `json:"remote"`
}

// DifferenceDimensions are the five HND-5 names.
var DifferenceDimensions = []string{"os", "tools", "model_policy", "network", "integrations"}

// Differences derives what the user must be shown before a handoff (HND-5).
//
// Derived from the two environments rather than declared by either, because a source that has not
// noticed the target lacks Docker will not disclose that the target lacks Docker.
//
// Only losses are reported for tools and integrations: gaining a tool does not change what the task
// can do, and listing it turns a disclosure the user should read into a diff they will not.
func Differences(local, remote Environment) []Difference {
	var out []Difference
	if local.OS != remote.OS {
		out = append(out, Difference{Dimension: "os", Local: local.OS, Remote: remote.OS})
	}
	if missing := absent(local.Tools, remote.Tools); len(missing) > 0 {
		out = append(out, Difference{
			Dimension: "tools",
			Local:     strings.Join(missing, ", "),
			Remote:    "absent",
		})
	}
	if local.ModelPolicy != remote.ModelPolicy {
		out = append(out, Difference{
			Dimension: "model_policy", Local: local.ModelPolicy, Remote: remote.ModelPolicy,
		})
	}
	if local.NetworkPolicy != remote.NetworkPolicy {
		out = append(out, Difference{
			Dimension: "network", Local: local.NetworkPolicy, Remote: remote.NetworkPolicy,
		})
	}
	if missing := absent(local.Integrations, remote.Integrations); len(missing) > 0 {
		out = append(out, Difference{
			Dimension: "integrations",
			Local:     strings.Join(missing, ", "),
			Remote:    "absent",
		})
	}
	return out
}

// absent returns the entries of have that want does not contain, sorted.
func absent(have, want []string) []string {
	present := make(map[string]bool, len(want))
	for _, w := range want {
		present[w] = true
	}
	var missing []string
	for _, h := range have {
		if !present[h] {
			missing = append(missing, h)
		}
	}
	sort.Strings(missing)
	return missing
}

// ReturnForm is how remote results come back (HND-6).
type ReturnForm string

const (
	// ReturnUnspecified is the zero value and is never admissible. A handoff whose results have
	// nowhere to go produces work nobody can review.
	ReturnUnspecified    ReturnForm = ""
	ReturnBranch         ReturnForm = "branch"
	ReturnPullRequest    ReturnForm = "pull_request"
	ReturnArtifactBundle ReturnForm = "artifact_bundle"
	ReturnPatch          ReturnForm = "patch"
)

// Valid reports whether f is one of HND-6's four.
func (f ReturnForm) Valid() bool {
	switch f {
	case ReturnBranch, ReturnPullRequest, ReturnArtifactBundle, ReturnPatch:
		return true
	}
	return false
}

// Task is HND-2's payload.
//
// Every field is required. A handoff missing one produces a remote agent working with less than the
// local one had, and nothing downstream can tell — the run looks normal and the output is subtly
// wrong.
type Task struct {
	Goal string `json:"goal"`
	Plan string `json:"plan"`
	// Messages is the conversation so far.
	Messages []string `json:"messages"`
	// ContextRefs are references to retrieved context, not the content.
	ContextRefs []string `json:"context_refs"`
	// SelectedFiles are the files the user put in scope.
	SelectedFiles []string `json:"selected_files"`
	// Revision is the repository revision the work is against.
	Revision string `json:"revision"`
	// SettingsSnapshot and ProfileVersion pin the effective configuration.
	SettingsSnapshot string `json:"settings_snapshot"`
	ProfileVersion   int    `json:"profile_version"`
	// UnresolvedQuestions are the open questions. Explicitly a slice rather than a string, and
	// explicitly required to be present as a field, because an agent that resumes without them does
	// not know it is missing anything and answers confidently.
	UnresolvedQuestions []string `json:"unresolved_questions"`
	// SecretRefs are names the remote resolves under its own authorization (HND-3). Never material.
	SecretRefs []string `json:"secret_refs,omitempty"`
	// InstructionManifest is the immutable manifest of active instructions (INS-5).
	InstructionManifest string `json:"instruction_manifest"`
	// ReturnAs is how results come back (HND-6).
	ReturnAs ReturnForm `json:"return_as"`
}

// Validate enforces HND-2, HND-3, HND-6 and INS-5's manifest reference.
func (t Task) Validate() error {
	switch {
	case strings.TrimSpace(t.Goal) == "":
		return field("a handoff states no goal", "goal")
	case strings.TrimSpace(t.Plan) == "":
		return field("a handoff carries no plan", "plan")
	case len(t.Messages) == 0:
		return field("a handoff carries no messages", "messages")
	case t.ContextRefs == nil:
		// A nil slice is "nobody assembled this"; an empty non-nil one is "there was no retrieved
		// context", which is a real and different answer.
		return field("a handoff carries no context references", "context_refs")
	case t.SelectedFiles == nil:
		return field("a handoff carries no selected-file list", "selected_files")
	case strings.TrimSpace(t.Revision) == "":
		return field("a handoff names no repository revision", "revision")
	case strings.TrimSpace(t.SettingsSnapshot) == "":
		return field("a handoff references no settings snapshot", "settings_snapshot")
	case t.ProfileVersion < 1:
		return field("a handoff references no profile version", "profile_version")
	case t.UnresolvedQuestions == nil:
		// The most droppable item on HND-2's list and the most consequential.
		return field(
			"a handoff carries no unresolved-questions list; a remote agent that resumes without them "+
				"answers confidently to a question the user had already flagged as open",
			"unresolved_questions")
	case strings.TrimSpace(t.InstructionManifest) == "":
		// INS-5. The manifest is what survives compaction, worktrees and delegation, and a handoff
		// with none has made the handoff itself the source of truth for active instructions.
		return field("a handoff references no instruction manifest", "instruction_manifest")
	case !t.ReturnAs.Valid():
		return field("a handoff says nothing about how results return", "return_as")
	}

	for _, ref := range t.SecretRefs {
		if strings.TrimSpace(ref) == "" {
			return field("a handoff carries an empty secret reference", "secret_refs")
		}
		if looksLikeMaterial(ref) {
			// INV-2. A handoff carrying resolved values would also make the remote's own
			// authorization unreachable, which is the half of HND-3 that is easy to lose.
			return field(
				"a handoff carries what looks like secret material rather than a reference",
				"secret_refs")
		}
	}
	return nil
}

// looksLikeMaterial catches the obvious case of a value where a name belongs.
//
// Narrow on purpose: it exists to catch the paste, not to certify that a string is not a secret.
// Nothing here can do the latter, and a check that claimed to would be worse than none.
func looksLikeMaterial(ref string) bool {
	s := strings.TrimSpace(ref)
	if len(s) > 40 && !strings.Contains(s, "/") && !strings.Contains(s, ".") {
		return true
	}
	lower := strings.ToLower(s)
	for _, prefix := range []string{"ghp_", "github_pat_", "sk-", "aws_", "akia", "xoxb-", "-----begin"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

func denied(msg, constraint string) error {
	return modberr.New(modberr.CodePolicyDenied, msg).WithDetail("constraint", constraint)
}

// Plan is what a handoff will do, for the user to approve.
type Plan struct {
	// Differences are HND-5's material discrepancies, derived from the environments.
	Differences []Difference `json:"differences,omitempty"`
	// ManifestPreserved reports whether the remote will run under the same instruction manifest
	// (INS-5). False means the differences must be reported, which is what ManifestNote carries.
	ManifestPreserved bool   `json:"manifest_preserved"`
	ManifestNote      string `json:"manifest_note,omitempty"`
	// SecretRefs are the names the remote must resolve under its own authorization.
	SecretRefs []string `json:"secret_refs,omitempty"`
}

// Prepare decides whether a handoff may proceed and what must be shown first.
//
// remoteManifest is the instruction manifest the remote environment will actually apply. INS-5
// permits it to differ and requires the difference to be reported, so a mismatch is a disclosure
// rather than a refusal — refusing would push users to work around the check, and the requirement
// asks for visibility rather than uniformity.
func Prepare(t Task, local, remote Environment, remoteManifest string) (Plan, error) {
	if err := t.Validate(); err != nil {
		return Plan{}, err
	}
	switch {
	case strings.TrimSpace(remote.ID) == "":
		return Plan{}, field("a handoff names no target environment", "remote")
	case !remote.Validated:
		// HND-4. Validated before handoff, not on arrival: a task that has already moved cannot be
		// un-moved, and the user is now watching a run that will not start.
		return Plan{}, denied(fmt.Sprintf(
			"the target environment %s has not been validated", remote.ID), "target_validation")
	case remote.OrganizationID != local.OrganizationID:
		// INV-10, and not something a difference disclosure can cover: this is not a discrepancy
		// the user should weigh, it is a boundary.
		return Plan{}, denied(fmt.Sprintf(
			"the target environment %s belongs to another organization", remote.ID),
			"organization_boundary")
	case remote.SpaceID != local.SpaceID:
		return Plan{}, denied(fmt.Sprintf(
			"the target environment %s is in another Space", remote.ID), "space_boundary")
	}

	p := Plan{
		Differences: Differences(local, remote),
		SecretRefs:  append([]string(nil), t.SecretRefs...),
	}
	if strings.TrimSpace(remoteManifest) == "" {
		return Plan{}, field(
			"the target environment reports no instruction manifest, so INS-5's comparison cannot be made",
			"remote_manifest")
	}
	p.ManifestPreserved = remoteManifest == t.InstructionManifest
	if !p.ManifestPreserved {
		p.ManifestNote = fmt.Sprintf(
			"the remote applies instruction manifest %s and the local task was built under %s",
			remoteManifest, t.InstructionManifest)
	}
	return p, nil
}

// RequiresDisclosure reports whether the user must be shown something before the handoff proceeds.
//
// True whenever there is anything to show. A plan with differences that a surface may proceed past
// silently is HND-5 not being implemented, whatever the field says.
func (p Plan) RequiresDisclosure() bool {
	return len(p.Differences) > 0 || !p.ManifestPreserved
}

// Describe renders a plan for the approval surface.
func (p Plan) Describe() string {
	if !p.RequiresDisclosure() {
		return "no material differences"
	}
	var parts []string
	for _, d := range p.Differences {
		parts = append(parts, fmt.Sprintf("%s: %s → %s", d.Dimension, d.Local, d.Remote))
	}
	if !p.ManifestPreserved {
		parts = append(parts, p.ManifestNote)
	}
	return strings.Join(parts, "; ")
}
