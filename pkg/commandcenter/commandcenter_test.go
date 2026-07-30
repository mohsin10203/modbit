package commandcenter_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/commandcenter"
	"github.com/modbit/modbit/pkg/modberr"
)

// Command Center invariants (CC1–CC7). One test each; a test without a CC-number, or a CC-number
// without a test, is a gap.
//
//	CC1 §20.3: the category set is closed and the zero is not displayable.
//	CC2 CRC-1: an unresolved overlap removes Create Pull Request, and says so specifically.
//	CC3 A terminal run admits no action that would change what it is doing.
//	CC4 A queued run can be cancelled, which a "cancel only what is running" rule would forbid.
//	CC5 Attach and Take Over require a live run, not merely a non-terminal one.
//	CC6 INV-10: the organization boundary is a parameter, not a filter field.
//	CC7 A filter narrows and never widens; an empty filter is not an empty view.

func run() commandcenter.Run {
	return commandcenter.Run{
		ID: "run-1", OrganizationID: "org-a", SpaceID: "space-1",
		Category: commandcenter.CategoryRemote, Live: true, HasArtifacts: true,
	}
}

func has(actions []commandcenter.Action, want commandcenter.Action) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}

// CC1. §20.3's categories are closed, and an uncategorised run lands in whichever column the view
// iterates first.
func TestSecurityTheCategorySetIsClosedAndTheZeroIsNotDisplayable(t *testing.T) {
	var zero commandcenter.Category
	if zero != commandcenter.CategoryUnclassified {
		t.Fatalf("the zero Category is %q", zero)
	}
	if zero.Valid() {
		t.Fatal("the zero Category is displayable")
	}
	if commandcenter.Category("in_progress").Valid() {
		t.Fatal("an invented category is displayable")
	}
	if len(commandcenter.Categories) != 11 {
		t.Fatalf("categories = %v, want §20.3's eleven", commandcenter.Categories)
	}

	uncategorised := run()
	uncategorised.Category = commandcenter.CategoryUnclassified
	if err := uncategorised.Validate(); err == nil {
		t.Fatal("an uncategorised run validated")
	}
	if _, err := commandcenter.Actions(uncategorised); err == nil {
		t.Fatal("an uncategorised run was offered actions")
	}

	// Terminal is derived from the category rather than declared, so a caller cannot mark a running
	// run terminal to shed its actions.
	if !commandcenter.CategoryCompleted.Terminal() || !commandcenter.CategoryFailed.Terminal() {
		t.Fatal("a finished run does not report itself terminal")
	}
	for _, c := range []commandcenter.Category{
		commandcenter.CategoryQueued, commandcenter.CategoryPaused, commandcenter.CategoryRemote,
		commandcenter.CategoryAwaitingApproval,
	} {
		if c.Terminal() {
			t.Errorf("%s reports itself terminal", c)
		}
	}
}

// CC2. CRC-1: "before either run creates a PR" is a gate, not a notification.
//
// A finding shown next to an enabled Create Pull Request button has been surfaced onto the screen
// and has not been surfaced in the sense the requirement means.
func TestSecurityAnUnresolvedOverlapRemovesCreatePullRequest(t *testing.T) {
	clean, err := commandcenter.Actions(run())
	if err != nil {
		t.Fatalf("Actions: %v", err)
	}
	if !has(clean, commandcenter.ActionCreatePR) {
		t.Fatal("a run with no overlaps was not offered Create Pull Request")
	}

	conflicted := run()
	conflicted.UnresolvedOverlaps = []string{"run-2 touches auth.Login"}
	got, err := commandcenter.Actions(conflicted)
	if err != nil {
		t.Fatalf("Actions: %v", err)
	}
	if has(got, commandcenter.ActionCreatePR) {
		t.Fatal("a run with an unresolved overlap was offered Create Pull Request")
	}
	// Everything else it could do, it still can — the gate is on the PR, not on the run.
	for _, a := range []commandcenter.Action{
		commandcenter.ActionOpen, commandcenter.ActionPause, commandcenter.ActionCancel,
	} {
		if !has(got, a) {
			t.Errorf("the overlap also removed %s", a)
		}
	}

	// The refusal names the overlap rather than the state, or somebody goes looking at the wrong
	// thing.
	err = commandcenter.Permits(conflicted, commandcenter.ActionCreatePR)
	if err == nil {
		t.Fatal("Permits allowed a pull request against an unresolved overlap")
	}
	if !modberr.Is(err, modberr.CodePolicyDenied) {
		t.Errorf("error = %v, want POLICY_DENIED", err)
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Errorf("error = %v; it must name the overlap, not the run state", err)
	}
}

// CC3. A terminal run admits nothing that would change what it is doing, because it is not doing
// anything.
//
// A Resume button on a completed run is not a harmless no-op — it is the product telling a user the
// run can be resumed, and they plan around it.
func TestSecurityATerminalRunAdmitsNoStateChangingAction(t *testing.T) {
	for _, c := range []commandcenter.Category{
		commandcenter.CategoryCompleted, commandcenter.CategoryFailed,
	} {
		r := run()
		r.Category = c
		r.Live = false
		got, err := commandcenter.Actions(r)
		if err != nil {
			t.Fatalf("%s: Actions: %v", c, err)
		}
		for _, forbidden := range []commandcenter.Action{
			commandcenter.ActionResume, commandcenter.ActionPause, commandcenter.ActionCancel,
			commandcenter.ActionAttach, commandcenter.ActionTakeOver, commandcenter.ActionFollowUp,
			commandcenter.ActionHandoff, commandcenter.ActionCreatePR,
		} {
			if has(got, forbidden) {
				t.Errorf("a %s run was offered %s", c, forbidden)
			}
		}
		// Archive is permitted: it changes the record, not the run.
		if !has(got, commandcenter.ActionArchive) {
			t.Errorf("a %s run could not be archived", c)
		}
		// And looking at it always works.
		for _, want := range []commandcenter.Action{
			commandcenter.ActionOpen, commandcenter.ActionExport, commandcenter.ActionOpenArtifacts,
		} {
			if !has(got, want) {
				t.Errorf("a %s run was not offered %s", c, want)
			}
		}

		// A terminal run that claims to be live still admits nothing: the category decides.
		lying := r
		lying.Live = true
		liveGot, err := commandcenter.Actions(lying)
		if err != nil {
			t.Fatalf("Actions: %v", err)
		}
		if has(liveGot, commandcenter.ActionPause) {
			t.Errorf("a %s run marked live was offered Pause", c)
		}
	}
}

// CC4. A queued run can be cancelled.
//
// A "cancel only what is running" rule leaves a user unable to stop something that has not started,
// which is precisely when they most want to.
func TestAQueuedRunCanBeCancelledButNotAttachedTo(t *testing.T) {
	r := run()
	r.Category = commandcenter.CategoryQueued
	r.Live = false

	got, err := commandcenter.Actions(r)
	if err != nil {
		t.Fatalf("Actions: %v", err)
	}
	if !has(got, commandcenter.ActionCancel) {
		t.Fatal("a queued run could not be cancelled")
	}
	for _, forbidden := range []commandcenter.Action{
		commandcenter.ActionAttach, commandcenter.ActionTakeOver, commandcenter.ActionPause,
		commandcenter.ActionResume,
	} {
		if has(got, forbidden) {
			t.Errorf("a queued run was offered %s; it has not started", forbidden)
		}
	}

	// A paused run resumes and takes follow-ups, and does not pause again.
	paused := run()
	paused.Category, paused.Live = commandcenter.CategoryPaused, false
	got, err = commandcenter.Actions(paused)
	if err != nil {
		t.Fatalf("Actions: %v", err)
	}
	if !has(got, commandcenter.ActionResume) || !has(got, commandcenter.ActionFollowUp) {
		t.Fatalf("a paused run was not offered Resume and Send follow-up: %v", got)
	}
	if has(got, commandcenter.ActionPause) {
		t.Fatal("a paused run was offered Pause")
	}
}

// CC5. Attach and Take Over need a live run, not merely a non-terminal one.
func TestSecurityAttachAndTakeOverRequireALiveRun(t *testing.T) {
	live := run()
	got, err := commandcenter.Actions(live)
	if err != nil {
		t.Fatalf("Actions: %v", err)
	}
	for _, want := range []commandcenter.Action{
		commandcenter.ActionAttach, commandcenter.ActionTakeOver,
		commandcenter.ActionPause, commandcenter.ActionHandoff,
	} {
		if !has(got, want) {
			t.Errorf("a live run was not offered %s", want)
		}
	}

	// Same category, not live: nothing to attach to.
	idle := run()
	idle.Live = false
	got, err = commandcenter.Actions(idle)
	if err != nil {
		t.Fatalf("Actions: %v", err)
	}
	for _, forbidden := range []commandcenter.Action{
		commandcenter.ActionAttach, commandcenter.ActionTakeOver, commandcenter.ActionPause,
	} {
		if has(got, forbidden) {
			t.Errorf("a non-live run was offered %s", forbidden)
		}
	}
	if err := commandcenter.Permits(idle, commandcenter.ActionTakeOver); err == nil {
		t.Fatal("Permits allowed a takeover of a run that is not executing")
	}
	if err := commandcenter.Permits(live, commandcenter.ActionTakeOver); err != nil {
		t.Fatalf("Permits refused a takeover of a live run: %v", err)
	}

	// Artifacts are offered only when there are some.
	bare := run()
	bare.HasArtifacts = false
	got, _ = commandcenter.Actions(bare)
	if has(got, commandcenter.ActionOpenArtifacts) {
		t.Fatal("a run with no artifacts was offered Open artifacts")
	}
}

// CC6. INV-10: the organization is a parameter, not a filter field.
//
// A filter is something a user narrows. The organization boundary is not, and putting it in Filter
// would make the most important constraint in the function the one a caller can leave blank.
func TestSecurityTheOrganizationBoundaryIsNotAFilter(t *testing.T) {
	mine := run()
	theirs := run()
	theirs.ID, theirs.OrganizationID = "run-2", "org-b"

	got, err := commandcenter.View("org-a", []commandcenter.Run{mine, theirs}, commandcenter.Filter{})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if len(got) != 1 || got[0].ID != "run-1" {
		t.Fatalf("view = %v, want only this organization's run", got)
	}

	// No filter at all still does not widen past the boundary.
	for _, f := range []commandcenter.Filter{
		{},
		{SpaceID: "space-1"},
		{Categories: []commandcenter.Category{commandcenter.CategoryRemote}},
	} {
		got, err := commandcenter.View("org-a", []commandcenter.Run{mine, theirs}, f)
		if err != nil {
			t.Fatalf("View: %v", err)
		}
		for _, r := range got {
			if r.OrganizationID != "org-a" {
				t.Fatalf("filter %+v let %s through the boundary", f, r.OrganizationID)
			}
		}
	}

	// A view with no organization is refused rather than showing everything.
	if _, err := commandcenter.View(" ", []commandcenter.Run{mine, theirs}, commandcenter.Filter{}); err == nil {
		t.Fatal("a view with no organization returned runs")
	}
	// Including when there is nothing to filter, where the per-run check has nothing to catch.
	if _, err := commandcenter.View("", nil, commandcenter.Filter{}); err == nil {
		t.Fatal("a view with no organization and no runs succeeded")
	}
}

// CC7. A filter narrows and never widens.
func TestAFilterNarrowsAndNeverWidens(t *testing.T) {
	a := run()
	b := run()
	b.ID, b.SpaceID, b.Category = "run-2", "space-2", commandcenter.CategoryQueued
	all := []commandcenter.Run{a, b}

	unfiltered, err := commandcenter.View("org-a", all, commandcenter.Filter{})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if len(unfiltered) != 2 {
		t.Fatalf("an empty filter returned %d runs, want both", len(unfiltered))
	}

	bySpace, err := commandcenter.View("org-a", all, commandcenter.Filter{SpaceID: "space-2"})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if len(bySpace) != 1 || bySpace[0].ID != "run-2" {
		t.Fatalf("space filter returned %v", bySpace)
	}

	byCategory, err := commandcenter.View("org-a", all, commandcenter.Filter{
		Categories: []commandcenter.Category{commandcenter.CategoryQueued},
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if len(byCategory) != 1 || byCategory[0].ID != "run-2" {
		t.Fatalf("category filter returned %v", byCategory)
	}

	// Two filters compose by narrowing further, not by widening to either.
	both, err := commandcenter.View("org-a", all, commandcenter.Filter{
		SpaceID:    "space-1",
		Categories: []commandcenter.Category{commandcenter.CategoryQueued},
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if len(both) != 0 {
		t.Fatalf("two filters matching different runs returned %v, want nothing", both)
	}

	// An invalid run in the set is an error rather than a silently shorter list.
	broken := run()
	broken.Category = commandcenter.CategoryUnclassified
	if _, err := commandcenter.View("org-a", []commandcenter.Run{broken}, commandcenter.Filter{}); err == nil {
		t.Fatal("an uncategorised run was silently dropped from the view")
	}
}
