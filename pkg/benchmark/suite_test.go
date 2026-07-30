package benchmark_test

import (
	"strings"
	"testing"

	"github.com/modbit/modbit/pkg/benchmark"
)

// §37.1/§37.2 suite invariants (E9–E15). One test each; a test without an E-number, or an E-number
// without a test, is a gap.
//
//	E9  A release with no version is refused; its results compare with nothing.
//	E10 A task missing any of revision, environment, verification contract or class is refused.
//	E11 A trial exceeding its task's declared intervention allowance is inadmissible.
//	E12 A compaction-fidelity task must carry all six §37.2 label categories.
//	E13 An approval-quality task must carry all three operation categories.
//	E14 A streaming-overhead task must measure every client surface.
//	E15 A release missing any mandated task kind is refused.

func ordinary(id string) benchmark.Task {
	return benchmark.Task{
		ID: id, Class: benchmark.ClassLocalizedBugFix, Kind: benchmark.KindOrdinary,
		Revision: "abc123", Environment: "sha256:beef",
		VerificationContract: "hidden and visible tests pass",
	}
}

func compaction() benchmark.Task {
	t := ordinary("compact")
	t.Kind = benchmark.KindCompactionFidelity
	t.Class = benchmark.ClassLongRefactor
	t.Labels = append([]string(nil), benchmark.CompactionLabels...)
	return t
}

func approval() benchmark.Task {
	t := ordinary("approve")
	t.Kind = benchmark.KindApprovalQuality
	t.Class = benchmark.ClassSecurityReview
	t.Operations = append([]string(nil), benchmark.ApprovalCategories...)
	return t
}

func streaming() benchmark.Task {
	t := ordinary("stream")
	t.Kind = benchmark.KindStreamingOverhead
	t.Class = benchmark.ClassRepoComprehension
	t.Surfaces = append([]string(nil), benchmark.ClientSurfaces...)
	return t
}

func release() benchmark.Release {
	return benchmark.Release{
		Version: "2026.07",
		Tasks:   []benchmark.Task{ordinary("task-1"), compaction(), approval(), streaming()},
	}
}

// E9. An unversioned release compares with nothing, including a later run of the same suite.
func TestSecurityAnUnversionedReleaseIsRefused(t *testing.T) {
	r := release()
	r.Version = "  "
	if err := r.Validate(); err == nil {
		t.Fatal("a release with no version validated")
	}
	if _, err := r.SummarizeTask("task-1", nil); err == nil {
		t.Fatal("an unversioned release produced a result")
	}
	if err := release().Validate(); err != nil {
		t.Fatalf("a complete release was refused: %v", err)
	}
}

// E10. Every field a rerun needs is required, and each is checked independently — a single witness
// would pass against an implementation that only checks one.
func TestATaskMissingAnyReproducibilityFieldIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*benchmark.Task){
		"no id":                func(t *benchmark.Task) { t.ID = "" },
		"no class":             func(t *benchmark.Task) { t.Class = benchmark.ClassUnclassified },
		"unknown class":        func(t *benchmark.Task) { t.Class = "vibes" },
		"no revision":          func(t *benchmark.Task) { t.Revision = "" },
		"no environment":       func(t *benchmark.Task) { t.Environment = " " },
		"no contract":          func(t *benchmark.Task) { t.VerificationContract = "" },
		"no kind":              func(t *benchmark.Task) { t.Kind = benchmark.KindUnspecified },
		"unknown kind":         func(t *benchmark.Task) { t.Kind = "misc" },
		"negative allowance":   func(t *benchmark.Task) { t.InterventionAllowance = -1 },
		"labels without kind":  func(t *benchmark.Task) { t.Kind = benchmark.KindCompactionFidelity },
		"surfaces missing all": func(t *benchmark.Task) { t.Kind = benchmark.KindStreamingOverhead },
	} {
		task := ordinary("task-1")
		mutate(&task)
		if err := task.Validate(); err == nil {
			t.Errorf("%s: an unreproducible task validated", name)
		}
	}
	if err := ordinary("task-1").Validate(); err != nil {
		t.Fatalf("a complete task was refused: %v", err)
	}
}

// E11. §37.2's defined human-intervention allowance.
//
// This is a different claim from the unattended subset: unattended is zero across every task, and
// the allowance is per task. A trial that took more help than the task permits is not a worse
// result, it is a different task, and averaging it in is how an allowance becomes whatever the
// hardest run happened to need.
func TestSecurityATrialExceedingTheInterventionAllowanceIsRefused(t *testing.T) {
	task := ordinary("task-1")
	task.InterventionAllowance = 1

	within := trial("task-1", 1, true)
	within.CorrectiveMessages = 1
	if err := task.Admits(within); err != nil {
		t.Fatalf("a trial at the allowance was refused: %v", err)
	}

	over := trial("task-1", 2, true)
	over.CorrectiveMessages = 2
	err := task.Admits(over)
	if err == nil {
		t.Fatal("a trial exceeding the declared allowance was admitted")
	}
	if !strings.Contains(err.Error(), "allows 1") {
		t.Fatalf("error = %v; it must name the allowance it exceeded", err)
	}

	// An allowance of zero is a real value meaning none are permitted, not an absent setting.
	strict := ordinary("task-1")
	one := trial("task-1", 3, true)
	one.CorrectiveMessages = 1
	if err := strict.Admits(one); err == nil {
		t.Fatal("a zero allowance was read as no allowance and admitted a corrective message")
	}

	// A trial run against another revision is not this task's trial, whatever its allowance.
	drift := trial("task-1", 4, true)
	drift.Revision = "def456"
	if err := task.Admits(drift); err == nil {
		t.Fatal("a trial from another revision was admitted")
	}

	// Refused, not filtered: dropping inadmissible trials reports the subset that behaved.
	r := release()
	if _, err := r.SummarizeTask("task-1", []benchmark.Trial{trial("task-1", 1, true), one}); err == nil {
		t.Fatal("an inadmissible trial was silently dropped rather than refusing the result")
	}
}

// E12, E13, E14. Each mandated kind must carry all of its categories.
//
// Dropping each element in turn rather than one representative: an implementation checking only
// that the list is non-empty, or only that the first element is present, passes a single witness.
func TestSecurityAMandatedKindMustCarryEveryCategory(t *testing.T) {
	cases := []struct {
		kind     string
		required []string
		build    func(without string) benchmark.Task
	}{
		{"compaction labels", benchmark.CompactionLabels, func(without string) benchmark.Task {
			task := compaction()
			task.Labels = drop(task.Labels, without)
			return task
		}},
		{"approval operations", benchmark.ApprovalCategories, func(without string) benchmark.Task {
			task := approval()
			task.Operations = drop(task.Operations, without)
			return task
		}},
		{"streaming surfaces", benchmark.ClientSurfaces, func(without string) benchmark.Task {
			task := streaming()
			task.Surfaces = drop(task.Surfaces, without)
			return task
		}},
	}

	for _, c := range cases {
		if len(c.required) == 0 {
			t.Fatalf("%s: the required set is empty, so this test asserts nothing", c.kind)
		}
		for _, missing := range c.required {
			task := c.build(missing)
			err := task.Validate()
			if err == nil {
				t.Errorf("%s: a task missing %q validated", c.kind, missing)
				continue
			}
			// The refusal must name what is missing, or it is a re-read of the requirement.
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("%s: error %v does not name the missing %q", c.kind, err, missing)
			}
		}
	}

	// The complete forms are admitted, so the checks are not simply refusing everything.
	for _, task := range []benchmark.Task{compaction(), approval(), streaming()} {
		if err := task.Validate(); err != nil {
			t.Errorf("a complete %s task was refused: %v", task.Kind, err)
		}
	}

	// §37.2 names seeded high-risk mutations specifically: benign and ambiguous operations measure
	// whether approval is annoying, and only the seeded mutations measure whether it works.
	if !contains(benchmark.ApprovalCategories, "seeded_high_risk") {
		t.Fatal("the approval categories no longer require seeded high-risk mutations")
	}
}

// E15. A release missing any mandated kind is refused, and each is checked.
//
// These three measure properties that degrade without anyone noticing. A release shipped without
// one reports a suite that looks complete.
func TestSecurityAReleaseMustCoverEveryMandatedKind(t *testing.T) {
	if len(benchmark.MandatoryKinds) != 3 {
		t.Fatalf("mandated kinds = %v, want the three §37.2 names", benchmark.MandatoryKinds)
	}
	for _, kind := range benchmark.MandatoryKinds {
		r := release()
		var kept []benchmark.Task
		for _, task := range r.Tasks {
			if task.Kind != kind {
				kept = append(kept, task)
			}
		}
		if len(kept) == len(r.Tasks) {
			t.Fatalf("the fixture has no %s task, so removing it asserts nothing", kind)
		}
		r.Tasks = kept

		err := r.Validate()
		if err == nil {
			t.Errorf("a release with no %s task validated", kind)
			continue
		}
		if !strings.Contains(err.Error(), string(kind)) {
			t.Errorf("error %v does not name the missing %s", err, kind)
		}
	}

	// A duplicate task id would let one definition's allowance silently govern another's trials.
	dup := release()
	dup.Tasks = append(dup.Tasks, ordinary("task-1"))
	if err := dup.Validate(); err == nil {
		t.Fatal("a release defining the same task twice validated")
	}
}

// A task's stochastic flag governs the trial floor, so the floor cannot be sidestepped by
// summarizing through the release.
func TestTheTaskDecidesWhetherTheTrialFloorApplies(t *testing.T) {
	r := release()
	one := []benchmark.Trial{trial("task-1", 1, true)}
	if _, err := r.SummarizeTask("task-1", one); err != nil {
		t.Fatalf("a deterministic task was refused from one trial: %v", err)
	}

	for i := range r.Tasks {
		if r.Tasks[i].ID == "task-1" {
			r.Tasks[i].Stochastic = true
		}
	}
	if _, err := r.SummarizeTask("task-1", one); err == nil {
		t.Fatal("a stochastic task published a rate from one trial via the release")
	}
	if _, err := r.SummarizeTask("nonexistent", one); err == nil {
		t.Fatal("a task the release does not define produced a result")
	}
}

func drop(from []string, v string) []string {
	var out []string
	for _, s := range from {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

func contains(in []string, v string) bool {
	for _, s := range in {
		if s == v {
			return true
		}
	}
	return false
}
