package benchmark

import (
	"fmt"
	"sort"
	"strings"
)

// TaskClass is one of §37.1's thirteen task classes.
//
// A benchmark that reports a single aggregate over an unstated mix of task classes is comparing
// nothing: two runs can differ entirely because one had more cross-repository work. So every task
// names its class and the zero value is not one.
type TaskClass string

const (
	// ClassUnclassified is the zero value and is never admissible.
	ClassUnclassified      TaskClass = ""
	ClassRepoComprehension TaskClass = "repository_comprehension"
	ClassLocalizedBugFix   TaskClass = "localized_bug_fix"
	ClassCrossFileFeature  TaskClass = "cross_file_feature"
	ClassCrossRepoChange   TaskClass = "cross_repository_change"
	ClassDependencyUpgrade TaskClass = "dependency_upgrade"
	ClassCIFailureRepair   TaskClass = "ci_failure_repair"
	ClassRuntimeDebugging  TaskClass = "runtime_debugging"
	ClassFrontendVisual    TaskClass = "frontend_visual_change"
	ClassSecurityReview    TaskClass = "security_review"
	ClassPullRequestReview TaskClass = "pull_request_review"
	ClassIssueToPR         TaskClass = "issue_to_pr_automation"
	ClassLongRefactor      TaskClass = "long_running_refactor"
	ClassInterruptedRun    TaskClass = "interrupted_and_resumed_run"
)

// Valid reports whether c is one of §37.1's classes.
func (c TaskClass) Valid() bool {
	switch c {
	case ClassRepoComprehension, ClassLocalizedBugFix, ClassCrossFileFeature,
		ClassCrossRepoChange, ClassDependencyUpgrade, ClassCIFailureRepair,
		ClassRuntimeDebugging, ClassFrontendVisual, ClassSecurityReview,
		ClassPullRequestReview, ClassIssueToPR, ClassLongRefactor, ClassInterruptedRun:
		return true
	}
	return false
}

// TaskKind marks the three measurements §37.2 mandates a release carry, alongside ordinary tasks.
//
// These are separate from TaskClass: a class says what the work is, a kind says what the task is
// measuring. Compaction fidelity, approval quality and streaming overhead each carry extra
// structure the ordinary kind has no place for, and each is a property that degrades invisibly —
// which is why §37.2 names them specifically rather than leaving them to whoever writes tasks.
type TaskKind string

const (
	// KindUnspecified is the zero value and is never admissible. A task that did not say what it
	// measures would be counted as ordinary, and the mandated coverage check would not see it
	// missing.
	KindUnspecified        TaskKind = ""
	KindOrdinary           TaskKind = "ordinary"
	KindCompactionFidelity TaskKind = "compaction_fidelity"
	KindApprovalQuality    TaskKind = "approval_quality"
	KindStreamingOverhead  TaskKind = "streaming_overhead"
)

// MandatoryKinds are the kinds §37.2 requires every release to include.
var MandatoryKinds = []TaskKind{
	KindCompactionFidelity, KindApprovalQuality, KindStreamingOverhead,
}

// CompactionLabels are the six categories §37.2 requires a compaction-fidelity task to label.
//
// All six, not a representative sample. Compaction loses whichever category nobody measured, and
// the categories are listed because each fails differently: a dropped file reference produces a
// wrong edit, a dropped approval produces an unapproved action, a dropped unresolved item produces
// a run that reports success.
var CompactionLabels = []string{
	"critical_facts", "constraints", "decisions",
	"file_references", "approvals", "unresolved_work",
}

// ApprovalCategories are the three §37.2 requires of an approval-quality task.
//
// The seeded high-risk mutations are the load-bearing one: benign and ambiguous operations measure
// whether approval is annoying, and only the seeded mutations measure whether it works.
var ApprovalCategories = []string{"benign", "ambiguous", "seeded_high_risk"}

// ClientSurfaces is every surface §37.2's streaming-overhead measurement must reach.
//
// Taken from the capability registry's surface set rather than a shorter "surfaces that obviously
// stream" list. Over-inclusion refuses a release for an unmeasured surface, which is visible and
// fixable; under-inclusion ships a surface whose first-token latency nobody ever measured, which is
// discovered by users.
var ClientSurfaces = []string{
	"desktop", "cli", "web", "extension", "jetbrains", "mobile", "ts_sdk", "python_sdk",
}

// Task is a benchmark task definition. Trials are admitted against it.
type Task struct {
	ID    string    `json:"id"`
	Class TaskClass `json:"class"`
	Kind  TaskKind  `json:"kind"`
	// Revision is the fixed repository revision (§37.2). Trials must run against it.
	Revision string `json:"revision"`
	// Environment names the reproducible environment — an image digest or blueprint id. This package
	// does not build it; it refuses a task that never said which one to build, because "the
	// environment we had that week" is not reproducible and nobody notices until a rerun disagrees.
	Environment string `json:"environment"`
	// VerificationContract states what counts as done. §37.2 calls it explicit, and the reason is
	// that an implicit contract is settled after the results are in, by whoever is reading them.
	VerificationContract string `json:"verification_contract"`
	// InterventionAllowance is §37.2's "defined human-intervention allowance": the most corrective
	// messages a trial of this task may take and still count. Zero is a real value meaning none are
	// permitted, and is distinct from the unattended subset, which is computed across tasks whatever
	// their allowance.
	InterventionAllowance int `json:"intervention_allowance"`
	// Stochastic marks a task needing MinTrials before a rate may be published.
	Stochastic bool `json:"stochastic"`
	// Labels are the compaction-fidelity categories present, when Kind is KindCompactionFidelity.
	Labels []string `json:"labels,omitempty"`
	// Operations are the approval-quality categories present, when Kind is KindApprovalQuality.
	Operations []string `json:"operations,omitempty"`
	// Surfaces are the client surfaces measured, when Kind is KindStreamingOverhead.
	Surfaces []string `json:"surfaces,omitempty"`
}

// Validate enforces the per-task requirements of §37.1 and §37.2.
func (t Task) Validate() error {
	switch {
	case strings.TrimSpace(t.ID) == "":
		return field("a task has no id", "id")
	case !t.Class.Valid():
		return field(fmt.Sprintf(
			"task %s declares no §37.1 task class; an aggregate over an unstated mix compares nothing",
			t.ID), "class")
	case strings.TrimSpace(t.Revision) == "":
		return field(fmt.Sprintf("task %s fixes no repository revision", t.ID), "revision")
	case strings.TrimSpace(t.Environment) == "":
		return field(fmt.Sprintf(
			"task %s names no reproducible environment; a rerun would not be the same run", t.ID),
			"environment")
	case strings.TrimSpace(t.VerificationContract) == "":
		return field(fmt.Sprintf(
			"task %s states no verification contract; an implicit one gets settled after the results are in",
			t.ID), "verification_contract")
	case t.InterventionAllowance < 0:
		return field(fmt.Sprintf("task %s has a negative intervention allowance", t.ID),
			"intervention_allowance")
	}

	switch t.Kind {
	case KindUnspecified:
		return field(fmt.Sprintf(
			"task %s does not say what it measures; an unstated kind is counted as ordinary and the "+
				"mandated coverage check would not see it missing", t.ID), "kind")
	case KindOrdinary:
	case KindCompactionFidelity:
		if err := covers(t.ID, "labels", t.Labels, CompactionLabels); err != nil {
			return err
		}
	case KindApprovalQuality:
		if err := covers(t.ID, "operations", t.Operations, ApprovalCategories); err != nil {
			return err
		}
	case KindStreamingOverhead:
		if err := covers(t.ID, "surfaces", t.Surfaces, ClientSurfaces); err != nil {
			return err
		}
	default:
		return field(fmt.Sprintf("task %s has an unrecognised kind %q", t.ID, t.Kind), "kind")
	}
	return nil
}

// covers refuses a task that declares fewer than all of a required set, naming what is missing so
// the refusal is actionable rather than a re-read of the requirement.
func covers(taskID, fieldName string, got, want []string) error {
	have := make(map[string]bool, len(got))
	for _, g := range got {
		have[strings.TrimSpace(g)] = true
	}
	var missing []string
	for _, w := range want {
		if !have[w] {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return field(fmt.Sprintf("task %s is missing %s: %s",
			taskID, fieldName, strings.Join(missing, ", ")), fieldName)
	}
	return nil
}

// Admits reports whether a trial may count towards this task's result, and why not.
//
// This is the check Summarize alone cannot make: Trial.Validate knows a trial is internally
// coherent, and only the task knows how much intervention it permits and which revision it fixed.
func (t Task) Admits(tr Trial) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if err := tr.Validate(); err != nil {
		return err
	}
	switch {
	case tr.TaskID != t.ID:
		return field(fmt.Sprintf("a trial for %s was offered to task %s", tr.TaskID, t.ID), "task_id")
	case tr.Revision != t.Revision:
		return field(fmt.Sprintf(
			"trial of %s ran against revision %s and the task fixes %s",
			t.ID, tr.Revision, t.Revision), "revision")
	case tr.CorrectiveMessages > t.InterventionAllowance:
		// §37.2's defined allowance. A trial that took more help than the task permits is not a
		// worse result, it is a different task — and averaging it in is how an allowance becomes
		// whatever the hardest run needed.
		return field(fmt.Sprintf(
			"trial of %s took %d corrective message(s) and the task allows %d",
			t.ID, tr.CorrectiveMessages, t.InterventionAllowance), "corrective_messages")
	}
	return nil
}

// Release is a versioned benchmark release (§37.2).
type Release struct {
	// Version identifies the release. Results from an unversioned release cannot be compared with
	// anything, including a later run of what is nominally the same suite.
	Version string `json:"version"`
	Tasks   []Task `json:"tasks"`
}

// Validate enforces §37.2's versioning and mandated coverage.
func (r Release) Validate() error {
	if strings.TrimSpace(r.Version) == "" {
		return field("a benchmark release has no version; its results compare with nothing", "version")
	}
	if len(r.Tasks) == 0 {
		return field(fmt.Sprintf("release %s has no tasks", r.Version), "tasks")
	}

	seen := map[string]bool{}
	kinds := map[TaskKind]bool{}
	for _, t := range r.Tasks {
		if err := t.Validate(); err != nil {
			return err
		}
		if seen[t.ID] {
			return field(fmt.Sprintf("release %s defines task %s twice", r.Version, t.ID), "tasks")
		}
		seen[t.ID] = true
		kinds[t.Kind] = true
	}

	var missing []string
	for _, k := range MandatoryKinds {
		if !kinds[k] {
			missing = append(missing, string(k))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		// These three measure properties that degrade without anyone noticing, which is why §37.2
		// names them rather than leaving them to whoever writes tasks. A release quietly shipped
		// without one reports a suite that looks complete.
		return field(fmt.Sprintf("release %s is missing mandated task kinds: %s",
			r.Version, strings.Join(missing, ", ")), "tasks")
	}
	return nil
}

// Task returns the task with the given id.
func (r Release) Task(id string) (Task, bool) {
	for _, t := range r.Tasks {
		if t.ID == id {
			return t, true
		}
	}
	return Task{}, false
}

// SummarizeTask admits each trial against its task definition and summarizes what survives.
//
// It refuses rather than filters. A benchmark that silently drops the trials it cannot admit
// reports the subset that behaved, which is the highest number the data can be made to yield.
func (r Release) SummarizeTask(taskID string, trials []Trial) (Result, error) {
	if err := r.Validate(); err != nil {
		return Result{}, err
	}
	t, ok := r.Task(taskID)
	if !ok {
		return Result{}, field(fmt.Sprintf(
			"release %s defines no task %s", r.Version, taskID), "task_id")
	}
	for _, tr := range trials {
		if err := t.Admits(tr); err != nil {
			return Result{}, err
		}
	}
	return Summarize(taskID, trials, t.Stochastic)
}
