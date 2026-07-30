// Package commandcenter admits actions on runs in the Agent Command Center (§20.3, CRC-1, CRC-5).
//
// Boundary: it decides which runs a viewer may see and which actions a run's state permits. It
// starts no run, cancels nothing, and renders no view — a caller supplies the runs and this decides
// what may be offered.
//
// Requirements: PRD §20.3 Agent Command Center (the categories the view covers, the filters it
// offers, and the actions it exposes), §21.2 CRC-1 (symbol- and dependency-graph overlap between
// active runs is surfaced in the Command Center *before either run creates a PR*), CRC-5 (detected
// semantic conflicts produce a Command Center finding and are never resolved silently). INV-10
// bounds what the view may contain.
//
// # Offering an action is a claim that it will work
//
// §20.3 lists fourteen actions and twelve run categories, and the tempting implementation renders
// all fourteen and lets the backend reject the ones that do not apply. That is a worse interface
// than it looks: a Resume button on a completed run is not a harmless no-op, it is the product
// telling a user the run can be resumed. They plan around it.
//
// So the action set is derived from the state, and a state that admits nothing says so.
//
// # CRC-1 is a gate, not a notification
//
// CRC-1 says overlap is surfaced "before either run creates a PR". The word before is the
// requirement: a finding shown next to an enabled Create Pull Request button has been surfaced, in
// the sense that it is on the screen, and has not been surfaced in the sense the requirement means.
// So an unresolved overlap finding removes the action.
package commandcenter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/modbit/modbit/pkg/modberr"
)

// Category is one of §20.3's run categories.
type Category string

const (
	// CategoryUnclassified is the zero value and is never displayable. A run nobody categorised
	// would land in whichever column the view iterates first.
	CategoryUnclassified     Category = ""
	CategoryLocal            Category = "local"
	CategoryRemote           Category = "remote"
	CategoryCustomerCloud    Category = "customer_cloud"
	CategoryQueued           Category = "queued"
	CategoryAwaitingApproval Category = "awaiting_approval"
	CategoryPaused           Category = "paused"
	CategoryFailed           Category = "failed"
	CategoryCompleted        Category = "completed"
	CategoryAutomation       Category = "automation"
	CategoryArena            Category = "arena"
	CategoryDelegated        Category = "delegated"
)

// Categories are §20.3's eleven displayable categories.
var Categories = []Category{
	CategoryLocal, CategoryRemote, CategoryCustomerCloud, CategoryQueued,
	CategoryAwaitingApproval, CategoryPaused, CategoryFailed, CategoryCompleted,
	CategoryAutomation, CategoryArena, CategoryDelegated,
}

// Valid reports whether c is a displayable category.
func (c Category) Valid() bool {
	for _, known := range Categories {
		if known == c {
			return true
		}
	}
	return false
}

// Terminal reports whether a run in this category has finished.
//
// A terminal run admits no action that would change what it is doing, because it is not doing
// anything.
func (c Category) Terminal() bool {
	return c == CategoryCompleted || c == CategoryFailed
}

// Action is one of §20.3's actions.
type Action string

const (
	ActionOpen          Action = "open"
	ActionAttach        Action = "attach"
	ActionFollowUp      Action = "send_follow_up"
	ActionPause         Action = "pause"
	ActionResume        Action = "resume"
	ActionTakeOver      Action = "take_over"
	ActionHandoff       Action = "handoff"
	ActionDuplicate     Action = "duplicate"
	ActionArchive       Action = "archive"
	ActionCancel        Action = "cancel"
	ActionExport        Action = "export"
	ActionOpenArtifacts Action = "open_artifacts"
	ActionCreatePR      Action = "create_pull_request"
)

// Run is what the Command Center displays.
type Run struct {
	ID string `json:"id"`
	// OrganizationID and SpaceID bound visibility (INV-10).
	OrganizationID string   `json:"organization_id"`
	SpaceID        string   `json:"space_id"`
	Category       Category `json:"category"`
	// Live marks a run that is currently executing, which is what makes Attach and Take Over
	// meaningful. A queued run has not started and a paused one has stopped.
	Live bool `json:"live"`
	// UnresolvedOverlaps are CRC-1 findings against this run that nobody has dealt with.
	UnresolvedOverlaps []string `json:"unresolved_overlaps,omitempty"`
	// HasArtifacts reports whether there is anything to open.
	HasArtifacts bool `json:"has_artifacts"`
}

// Validate refuses a run that cannot be displayed soundly.
func (r Run) Validate() error {
	switch {
	case strings.TrimSpace(r.ID) == "":
		return field("a run has no id", "id")
	case strings.TrimSpace(r.OrganizationID) == "":
		return field(fmt.Sprintf("run %s names no organization", r.ID), "organization_id")
	case !r.Category.Valid():
		return field(fmt.Sprintf(
			"run %s has no category; an uncategorised run lands in whichever column the view iterates "+
				"first", r.ID), "category")
	}
	return nil
}

func field(msg, name string) error {
	return modberr.New(modberr.CodeInvalidArgument, msg).WithDetail("field", name)
}

func denied(msg, constraint string) error {
	return modberr.New(modberr.CodePolicyDenied, msg).WithDetail("constraint", constraint)
}

// Actions returns what may be offered for a run, sorted (§20.3).
//
// Derived from the state rather than rendered wholesale and rejected later. A Resume button on a
// completed run is not a harmless no-op — it is the product telling a user the run can be resumed,
// and they plan around it.
func Actions(r Run) ([]Action, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}

	// Always available: looking at a run and copying it never depends on what it is doing.
	out := []Action{ActionOpen, ActionDuplicate, ActionExport}
	if r.HasArtifacts {
		out = append(out, ActionOpenArtifacts)
	}

	if r.Category.Terminal() {
		// A finished run can be filed away and nothing else. Archive is the only state change left
		// because it is a change to the *record*, not to the run.
		out = append(out, ActionArchive)
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out, nil
	}

	// Cancel applies to anything not yet finished, including a queued run that has not started —
	// which is the case a "cancel only what is running" rule leaves a user unable to stop.
	out = append(out, ActionCancel)

	switch r.Category {
	case CategoryQueued:
		// Not started: there is nothing to attach to and nothing to pause.
	case CategoryPaused:
		out = append(out, ActionResume, ActionFollowUp)
	case CategoryAwaitingApproval:
		// The run is waiting on a person, so a follow-up reaches it, but pausing something already
		// stopped is not a state.
		out = append(out, ActionFollowUp)
	default:
		if r.Live {
			out = append(out, ActionAttach, ActionTakeOver, ActionPause, ActionFollowUp, ActionHandoff)
		}
	}

	// CRC-1. The word "before" is the requirement: a finding shown next to an enabled Create Pull
	// Request button has been surfaced onto the screen and not surfaced in the sense that matters.
	if len(r.UnresolvedOverlaps) == 0 {
		out = append(out, ActionCreatePR)
	}

	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// Permits reports whether a run's state admits an action, and why not.
func Permits(r Run, a Action) error {
	available, err := Actions(r)
	if err != nil {
		return err
	}
	for _, candidate := range available {
		if candidate == a {
			return nil
		}
	}
	if a == ActionCreatePR && len(r.UnresolvedOverlaps) > 0 {
		// Named specifically, because "not available in this state" would send somebody looking at
		// the state rather than at the overlap.
		return denied(fmt.Sprintf(
			"run %s has %d unresolved overlap finding(s); CRC-1 requires them surfaced before a pull "+
				"request is created", r.ID, len(r.UnresolvedOverlaps)), "run_overlap")
	}
	return denied(fmt.Sprintf(
		"a %s run does not admit %s", r.Category, a), "run_state")
}

// Filter is §20.3's view filter. A zero-valued field does not narrow.
type Filter struct {
	SpaceID    string     `json:"space_id,omitempty"`
	Repository string     `json:"repository,omitempty"`
	Categories []Category `json:"categories,omitempty"`
}

// View returns the runs a viewer may see (§20.3, INV-10).
//
// organizationID is a parameter rather than a filter field, because a filter is something a user
// narrows and the organization boundary is not. Putting it in Filter would make the most important
// constraint in the function the one a caller can leave blank.
func View(organizationID string, runs []Run, f Filter) ([]Run, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, field("a view names no organization", "organization_id")
	}

	var out []Run
	for _, r := range runs {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		// INV-10, before any filter. A filter narrows what a permitted viewer sees; it is not what
		// makes them permitted, and checking it first would make the boundary depend on the filter.
		if r.OrganizationID != organizationID {
			continue
		}
		if f.SpaceID != "" && r.SpaceID != f.SpaceID {
			continue
		}
		if len(f.Categories) > 0 && !containsCategory(f.Categories, r.Category) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func containsCategory(in []Category, c Category) bool {
	for _, candidate := range in {
		if candidate == c {
			return true
		}
	}
	return false
}
