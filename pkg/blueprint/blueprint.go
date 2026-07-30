// Package blueprint admits environment Blueprints and the snapshots built from them (§23.20).
//
// Boundary: it decides whether a Blueprint may be built, whether a snapshot may be used for a given
// repository and worker, and whether a restore is sound. It builds nothing, runs no step, and pulls
// no image — a caller supplies declarations and build outcomes and this decides what they permit.
//
// Requirements: PRD §23.20 (validate declarative Blueprints, build reusable snapshots, run steps
// under policy, differential rebuilds, pin and restore versions, surface setup commands as agent
// knowledge, match snapshots to repositories and worker platforms) and §35's invariant that
// environment snapshots reference immutable Blueprint versions and content digests. INV-13 makes a
// repository-sourced Blueprint untrusted.
//
// # A mutable reference is not a snapshot
//
// The invariant asks for immutable Blueprint versions and content digests, and the reason is that
// every convenient way to name a base image is mutable. "ubuntu:24.04" is a moving target,
// "main" is whatever was pushed last, and both produce a snapshot that reproduces a different
// environment next month while claiming to be the same one. That is worse than an environment that
// obviously drifted, because the snapshot id in the run record still matches.
//
// So a base is a digest or it is refused. There is no "resolve it at build time and remember what
// we got" path here, because that records what the tag meant on the day and leaves the Blueprint
// still saying something else.
//
// # A Blueprint from the repository is repository content
//
// §23.20 surfaces setup commands as agent knowledge, and a Blueprint checked into a repository is
// the natural place to write them. It is also INV-13 territory: the commands are authored by
// whoever can open a pull request. They are not refused — that would make the feature useless — but
// their provenance travels with them, and a Blueprint from the repository cannot declare itself
// trusted.
package blueprint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
	"github.com/modbit/modbit/pkg/taint"
)

// Origin is where a Blueprint was authored.
type Origin string

const (
	// OriginRepository is the zero value: a Blueprint whose origin nobody recorded is treated as
	// repository content, which is the restrictive reading. An administrator-authored Blueprint is
	// registered deliberately, so the deliberate case is the one that has to say so.
	OriginRepository Origin = ""
	// OriginAdministrator is a Blueprint registered by an administrator outside the repository.
	OriginAdministrator Origin = "administrator"
)

// Class returns the provenance class of a Blueprint's steps (INV-13).
//
// A repository-sourced Blueprint's setup commands are authored by whoever can open a pull request,
// so they carry repository provenance into whatever reads them as agent knowledge.
func (o Origin) Class() taint.Class {
	if o == OriginAdministrator {
		return taint.UserTrusted
	}
	return taint.RepositoryUntrusted
}

// StepPhase is when a step runs (§23.20).
type StepPhase string

const (
	// PhaseUnspecified is the zero value and is never admissible.
	PhaseUnspecified StepPhase = ""
	PhaseInit        StepPhase = "init"
	PhaseMaintenance StepPhase = "maintenance"
	PhasePostBuild   StepPhase = "post_build"
)

// Valid reports whether p is a declared phase.
func (p StepPhase) Valid() bool {
	switch p {
	case PhaseInit, PhaseMaintenance, PhasePostBuild:
		return true
	}
	return false
}

// Step is one command in a Blueprint.
type Step struct {
	Phase   StepPhase `json:"phase"`
	Command string    `json:"command"`
	// Network declares that this step reaches the network. Declared rather than discovered, because
	// a build step that fetches something nobody expected is how a dependency arrives in an image
	// that an audit says contains only what the Blueprint listed.
	Network bool `json:"network"`
	// SecretRefs names the secrets the step needs, by reference. Never the material: a secret in a
	// Blueprint is a secret in every snapshot built from it and in every log line that echoes the
	// command (INV-2, INV-11).
	SecretRefs []string `json:"secret_refs,omitempty"`
}

// Blueprint is a declarative environment definition.
type Blueprint struct {
	ID     string `json:"id"`
	Origin Origin `json:"origin"`
	// BaseDigest is the immutable base image the environment is built from.
	BaseDigest string `json:"base_digest"`
	// Platform is the worker platform this Blueprint targets, as "os/arch".
	Platform string `json:"platform"`
	Steps    []Step `json:"steps"`
	// AllowNetworkSteps is the deployment's policy for this Blueprint. A step declaring network
	// access is refused unless the Blueprint was registered with it permitted.
	AllowNetworkSteps bool `json:"allow_network_steps"`
}

// digestPattern matches an immutable content digest. Deliberately narrow: an algorithm nobody
// recognised is not evidence of immutability.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ImmutableRef reports whether a reference names exactly one artifact forever.
//
// Tags are not immutable, and every readable way of naming an image is a tag. "ubuntu:24.04" moves,
// "main" moves, and "latest" is the same statement with less pretence.
func ImmutableRef(ref string) bool {
	return digestPattern.MatchString(strings.TrimSpace(ref))
}

var platformPattern = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+$`)

// Validate enforces §23.20's declarative requirements.
func (b Blueprint) Validate() error {
	switch {
	case strings.TrimSpace(b.ID) == "":
		return field("a Blueprint has no id", "id")
	case !ImmutableRef(b.BaseDigest):
		// The whole point of the invariant. A tag records what it meant on the day of the build and
		// keeps meaning something else afterwards, while the snapshot id in the run record still
		// matches.
		return field(fmt.Sprintf(
			"Blueprint %s names the base %q, which is not a content digest; a tag reproduces a "+
				"different environment later while claiming to be the same one", b.ID, b.BaseDigest),
			"base_digest")
	case !platformPattern.MatchString(b.Platform):
		return field(fmt.Sprintf(
			"Blueprint %s names no worker platform as os/arch", b.ID), "platform")
	case len(b.Steps) == 0:
		return field(fmt.Sprintf(
			"Blueprint %s declares no steps; an environment definition that defines nothing is the base "+
				"image under another name", b.ID), "steps")
	}

	for i, s := range b.Steps {
		switch {
		case !s.Phase.Valid():
			return field(fmt.Sprintf("Blueprint %s step %d declares no phase", b.ID, i), "phase")
		case strings.TrimSpace(s.Command) == "":
			return field(fmt.Sprintf("Blueprint %s step %d has no command", b.ID, i), "command")
		case s.Network && !b.AllowNetworkSteps:
			// Refused rather than run-and-logged: the point of declaring network access is that the
			// deployment gets to say no, and a step that fetches something nobody expected is how a
			// dependency arrives in an image an audit says contains only what the Blueprint listed.
			return denied(fmt.Sprintf(
				"Blueprint %s step %d reaches the network and this Blueprint is not permitted to",
				b.ID, i), "build_network")
		}
		for _, ref := range s.SecretRefs {
			if strings.TrimSpace(ref) == "" {
				return field(fmt.Sprintf(
					"Blueprint %s step %d names an empty secret reference", b.ID, i), "secret_refs")
			}
			if looksLikeMaterial(ref) {
				// A secret written into a Blueprint is a secret in every snapshot built from it and in
				// every log line that echoes the command.
				return field(fmt.Sprintf(
					"Blueprint %s step %d carries what looks like secret material rather than a reference",
					b.ID, i), "secret_refs")
			}
		}
	}
	return nil
}

// looksLikeMaterial catches the obvious case of a value pasted where a reference belongs.
//
// A heuristic, and narrow on purpose: it exists to catch the paste, not to certify that a string is
// not a secret. Nothing here can do the latter, and a check that claimed to would be worse than
// none because it would be believed.
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

// SetupKnowledge renders the Blueprint's commands for an agent, with their provenance (§23.20).
//
// The provenance is returned alongside rather than left to the caller, because "surface setup
// commands as agent knowledge" is exactly the path by which repository-authored instructions reach
// a model, and a caller that has to remember to label them will not.
func (b Blueprint) SetupKnowledge() ([]string, taint.Class) {
	var commands []string
	for _, s := range b.Steps {
		commands = append(commands, s.Command)
	}
	return commands, b.Origin.Class()
}

// BuildState is where a snapshot's build got to.
type BuildState string

const (
	// BuildPending is the zero value. A snapshot record nobody finished writing is not a usable
	// environment, and "ready" as a zero value would make an interrupted build indistinguishable
	// from a completed one.
	BuildPending   BuildState = ""
	BuildRunning   BuildState = "running"
	BuildFailed    BuildState = "failed"
	BuildCancelled BuildState = "cancelled"
	BuildReady     BuildState = "ready"
)

// Usable reports whether a snapshot in this state may be run. Only BuildReady may.
func (s BuildState) Usable() bool { return s == BuildReady }

// Snapshot is a built environment.
type Snapshot struct {
	ID string `json:"id"`
	// BlueprintID and BlueprintVersion pin the definition. The version is immutable: a Blueprint
	// edited after a snapshot was built produces a new version rather than changing this one.
	BlueprintID      string `json:"blueprint_id"`
	BlueprintVersion int    `json:"blueprint_version"`
	// ContentDigest is what the build produced.
	ContentDigest string `json:"content_digest"`
	// BaseSnapshotDigest is set on a differential rebuild and names the snapshot this one was built
	// on top of, by digest.
	BaseSnapshotDigest string     `json:"base_snapshot_digest,omitempty"`
	Platform           string     `json:"platform"`
	State              BuildState `json:"state"`
	// Repositories are the repositories this snapshot was prepared for.
	Repositories []string `json:"repositories"`
}

// Validate enforces the immutable-reference invariant on a snapshot.
func (s Snapshot) Validate() error {
	switch {
	case strings.TrimSpace(s.ID) == "":
		return field("a snapshot has no id", "id")
	case strings.TrimSpace(s.BlueprintID) == "":
		return field(fmt.Sprintf("snapshot %s references no Blueprint", s.ID), "blueprint_id")
	case s.BlueprintVersion < 1:
		// An unversioned reference points at whatever the Blueprint says now, which is the mutable
		// reference problem one level up.
		return field(fmt.Sprintf(
			"snapshot %s references Blueprint %s at no version", s.ID, s.BlueprintID),
			"blueprint_version")
	case !platformPattern.MatchString(s.Platform):
		return field(fmt.Sprintf("snapshot %s names no platform", s.ID), "platform")
	}

	if s.State.Usable() {
		if !ImmutableRef(s.ContentDigest) {
			return field(fmt.Sprintf(
				"snapshot %s is ready but has no content digest", s.ID), "content_digest")
		}
	}
	if s.BaseSnapshotDigest != "" && !ImmutableRef(s.BaseSnapshotDigest) {
		// A differential rebuild whose base is a tag is a chain with a moving link, and the whole
		// chain reproduces something different once that link moves.
		return field(fmt.Sprintf(
			"snapshot %s was built on the mutable base %q", s.ID, s.BaseSnapshotDigest),
			"base_snapshot_digest")
	}
	return nil
}

// Match is why a snapshot was or was not selected.
type Match struct {
	Usable bool   `json:"usable"`
	Reason string `json:"reason,omitempty"`
}

// Select decides whether a snapshot may be used for a repository on a worker (§23.20).
//
// Every mismatch is a refusal with its reason rather than a lower score. A ranked "best available"
// selection is how a snapshot built for another platform gets used when nothing better exists, and
// the failure it produces surfaces much later as a build error nobody connects to the environment.
func Select(s Snapshot, repository, workerPlatform string) (Match, error) {
	if err := s.Validate(); err != nil {
		return Match{}, err
	}
	switch {
	case !s.State.Usable():
		return Match{Reason: fmt.Sprintf(
			"snapshot %s is %s", s.ID, stateName(s.State))}, nil
	case s.Platform != workerPlatform:
		return Match{Reason: fmt.Sprintf(
			"snapshot %s was built for %s and the worker is %s",
			s.ID, s.Platform, workerPlatform)}, nil
	}
	for _, r := range s.Repositories {
		if r == repository {
			return Match{Usable: true}, nil
		}
	}
	return Match{Reason: fmt.Sprintf(
		"snapshot %s was not prepared for %s", s.ID, repository)}, nil
}

func stateName(s BuildState) string {
	if s == BuildPending {
		return "pending"
	}
	return string(s)
}

// Restore returns the snapshot a pin resolves to (§23.20 pin and restore).
//
// A pin resolves to the pinned snapshot even when a newer one exists, which is the entire purpose
// of pinning, and it resolves to nothing when the pinned snapshot never became usable. Falling
// forward to the newest ready snapshot is the tempting behaviour and it silently un-pins the thing
// somebody pinned deliberately — most likely right after the newer build broke.
func Restore(pinnedID string, available []Snapshot) (Snapshot, error) {
	if strings.TrimSpace(pinnedID) == "" {
		return Snapshot{}, field("a restore names no snapshot", "pinned_id")
	}
	for _, s := range available {
		if s.ID != pinnedID {
			continue
		}
		if err := s.Validate(); err != nil {
			return Snapshot{}, err
		}
		if !s.State.Usable() {
			return Snapshot{}, denied(fmt.Sprintf(
				"snapshot %s is %s and cannot be restored", s.ID, stateName(s.State)), "restore_state")
		}
		return s, nil
	}
	return Snapshot{}, modberr.Newf(modberr.CodeNotFound,
		"snapshot %s is not available to restore", pinnedID).WithDetail("resource", "snapshot")
}

// Chain walks a differential rebuild back to its full base (§23.20 differential rebuilds).
//
// Returned oldest-first. A chain with a missing link is an error rather than a truncated result: a
// partial chain looks like a complete one built on a different base, and the caller cannot tell.
func Chain(head Snapshot, byDigest map[string]Snapshot) ([]Snapshot, error) {
	var chain []Snapshot
	seen := map[string]bool{}
	current := head
	for {
		if err := current.Validate(); err != nil {
			return nil, err
		}
		if seen[current.ID] {
			return nil, field(fmt.Sprintf(
				"snapshot %s appears twice in its own rebuild chain", current.ID), "base_snapshot_digest")
		}
		seen[current.ID] = true
		chain = append(chain, current)

		if current.BaseSnapshotDigest == "" {
			break
		}
		base, ok := byDigest[current.BaseSnapshotDigest]
		if !ok {
			return nil, modberr.Newf(modberr.CodeNotFound,
				"snapshot %s was built on %s, which is not available; the chain cannot be verified",
				current.ID, current.BaseSnapshotDigest).WithDetail("resource", "snapshot")
		}
		current = base
	}
	// Reversed in place: a comparator cannot express "reverse the order I built this in", and
	// sorting by any field would impose an ordering the chain does not have.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}
