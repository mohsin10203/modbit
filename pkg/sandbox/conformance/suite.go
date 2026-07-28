// Package conformance is the shared sandbox backend conformance suite (SBX-5).
//
// SBX-5 names ten areas every production backend must pass: path escape, symlink escape, process
// escape, network deny, resource limits, cancellation, snapshot, restore, artifact collection, and
// cleanup. The suite exists so those are checked the same way for every backend — SBX-1's "same
// versioned contract" is worth little if each backend is judged by its own tests.
//
// # Why a declared-but-unenforced control is Inconclusive, not Skipped
//
// A backend that declares a control and cannot demonstrate it is the case SBX-3 is about. Reporting
// it as Skipped would let an over-declaring backend look clean; reporting it as Pass would be the
// violation itself. So a control the backend declares Enforced but that the suite cannot verify is
// Inconclusive, and Inconclusive blocks production readiness. A control the backend honestly
// declares unsupported or advisory is Skipped, because there is no claim to check.
package conformance

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/modbit/modbit/pkg/id"
	"github.com/modbit/modbit/pkg/sandbox"
)

// SuiteVersion is bumped when a case is added or its meaning changes, so two reports are comparable.
const SuiteVersion = 1

// Status is a case outcome.
type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	// StatusInconclusive means the backend declares the control but the suite could not demonstrate
	// it. It is not a pass and it blocks readiness.
	StatusInconclusive Status = "inconclusive"
	// StatusSkipped means the backend does not claim the control, so there is nothing to check.
	StatusSkipped Status = "skipped"
)

// Area is one of SBX-5's ten required areas.
type Area string

const (
	AreaPathEscape         Area = "path_escape"
	AreaSymlinkEscape      Area = "symlink_escape"
	AreaProcessEscape      Area = "process_escape"
	AreaNetworkDeny        Area = "network_deny"
	AreaResourceLimits     Area = "resource_limits"
	AreaCancellation       Area = "cancellation"
	AreaSnapshot           Area = "snapshot"
	AreaRestore            Area = "restore"
	AreaArtifactCollection Area = "artifact_collection"
	AreaCleanup            Area = "cleanup"
)

// Areas returns SBX-5's ten areas in a stable order.
//
// X7. TestSuiteCoversEverySBX5Area asserts the suite produces a result for each, so a case cannot be
// quietly dropped — the same guard the adapter conformance suite uses for ADP-5.
func Areas() []Area {
	return []Area{
		AreaPathEscape, AreaSymlinkEscape, AreaProcessEscape, AreaNetworkDeny,
		AreaResourceLimits, AreaCancellation, AreaSnapshot, AreaRestore,
		AreaArtifactCollection, AreaCleanup,
	}
}

// Result is one area's outcome.
type Result struct {
	Area   Area   `json:"area"`
	Status Status `json:"status"`
	// Detail explains a non-pass. It never contains workspace content.
	Detail string `json:"detail,omitempty"`
}

// Report is the evidence artifact for one backend.
type Report struct {
	SuiteVersion int       `json:"suite_version"`
	Backend      string    `json:"backend"`
	Strength     string    `json:"strength"`
	Results      []Result  `json:"results"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
}

func (r Report) filter(s Status) []Result {
	var out []Result
	for _, result := range r.Results {
		if result.Status == s {
			out = append(out, result)
		}
	}
	return out
}

// Failures returns every failed area.
func (r Report) Failures() []Result { return r.filter(StatusFail) }

// Inconclusive returns every area the backend claimed but could not demonstrate.
func (r Report) Inconclusive() []Result { return r.filter(StatusInconclusive) }

// ProductionReady reports whether this backend may serve production work (SBX-5).
//
// It requires zero failures and zero inconclusive results. A declared control the suite could not
// demonstrate is not a pass, for the same reason it is not one in the adapter suite.
func (r Report) ProductionReady() bool {
	return len(r.Failures()) == 0 && len(r.Inconclusive()) == 0
}

// Summary renders a one-line report.
func (r Report) Summary() string {
	counts := map[Status]int{}
	for _, result := range r.Results {
		counts[result.Status]++
	}
	return fmt.Sprintf("%s/%s: %d pass, %d fail, %d inconclusive, %d skipped",
		r.Backend, r.Strength, counts[StatusPass], counts[StatusFail],
		counts[StatusInconclusive], counts[StatusSkipped])
}

// Options configure a run.
type Options struct {
	// Workspace is where the suite builds its fixtures. A temporary directory is used when empty.
	Workspace string
	// CommandTimeout bounds each probe.
	CommandTimeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.CommandTimeout <= 0 {
		o.CommandTimeout = 10 * time.Second
	}
	return o
}

type runner struct {
	backend sandbox.Backend
	caps    sandbox.Capabilities
	opts    Options
	results []Result
}

// Run exercises every SBX-5 area against a backend.
func Run(ctx context.Context, backend sandbox.Backend, opts Options) Report {
	caps := backend.Capabilities()
	r := &runner{backend: backend, caps: caps, opts: opts.withDefaults()}
	started := time.Now().UTC()

	r.checkPathEscape(ctx)
	r.checkSymlinkEscape(ctx)
	r.checkProcessEscape(ctx)
	r.checkNetworkDeny(ctx)
	r.checkResourceLimits(ctx)
	r.checkCancellation(ctx)
	r.checkSnapshot(ctx)
	r.checkRestore(ctx)
	r.checkArtifactCollection(ctx)
	r.checkCleanup(ctx)

	return Report{
		SuiteVersion: SuiteVersion,
		Backend:      caps.Backend,
		Strength:     caps.Strength.String(),
		Results:      r.results,
		StartedAt:    started,
		FinishedAt:   time.Now().UTC(),
	}
}

func (r *runner) record(area Area, status Status, detail string) {
	r.results = append(r.results, Result{Area: area, Status: status, Detail: detail})
}

// claim reports whether the backend declares a control as enforced. A control it does not claim is
// skipped: there is nothing to check, and marking it failed would punish honesty.
func (r *runner) claims(control sandbox.Control) bool {
	return r.caps.Enforcement(control).Enforces()
}

// establish creates a session for a probe, allowing degradation so a weak backend can still be
// exercised on the areas it does claim.
func (r *runner) establish(ctx context.Context, workspace string) (*sandbox.Session, error) {
	return r.backend.Establish(ctx, sandbox.Spec{
		RunID:         id.MustNew(id.Run),
		Workspace:     workspace,
		AllowDegraded: true,
		Rationale:     "conformance suite probe",
	})
}

func (r *runner) workspace() (string, func(), error) {
	if r.opts.Workspace != "" {
		dir, err := os.MkdirTemp(r.opts.Workspace, "sbx-")
		return dir, func() { _ = os.RemoveAll(dir) }, err
	}
	dir, err := os.MkdirTemp("", "sbx-")
	return dir, func() { _ = os.RemoveAll(dir) }, err
}

func (r *runner) checkPathEscape(ctx context.Context) {
	const area = AreaPathEscape
	if !r.claims(sandbox.ControlFilesystemScope) {
		r.record(area, StatusSkipped, "backend does not claim enforced filesystem scope")
		return
	}
	dir, cleanup, err := r.workspace()
	if err != nil {
		r.record(area, StatusInconclusive, "workspace could not be created")
		return
	}
	defer cleanup()

	session, err := r.establish(ctx, dir)
	if err != nil {
		r.record(area, StatusInconclusive, "sandbox could not be established")
		return
	}
	defer func() { _ = r.backend.Cleanup(ctx, session) }()

	// Writing outside the workspace must not succeed.
	outside := filepath.Join(os.TempDir(), "modbit-escape-probe")
	_ = os.Remove(outside)
	shell, args := writeProbe(outside)
	if shell == "" {
		r.record(area, StatusInconclusive, "no probe available on this platform")
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, r.opts.CommandTimeout)
	defer cancel()
	_, _ = r.backend.Run(callCtx, session, sandbox.Command{Path: shell, Args: args})

	if _, err := os.Stat(outside); err == nil {
		_ = os.Remove(outside)
		r.record(area, StatusFail, "a command wrote outside the workspace")
		return
	}
	r.record(area, StatusPass, "")
}

func (r *runner) checkSymlinkEscape(ctx context.Context) {
	const area = AreaSymlinkEscape
	if !r.claims(sandbox.ControlFilesystemScope) {
		r.record(area, StatusSkipped, "backend does not claim enforced filesystem scope")
		return
	}
	dir, cleanup, err := r.workspace()
	if err != nil {
		r.record(area, StatusInconclusive, "workspace could not be created")
		return
	}
	defer cleanup()

	// A link inside the workspace pointing out of it is the shape EXE-9 names.
	link := filepath.Join(dir, "escape")
	if err := os.Symlink(os.TempDir(), link); err != nil {
		r.record(area, StatusInconclusive, "symlink could not be created on this filesystem")
		return
	}
	session, err := r.establish(ctx, dir)
	if err != nil {
		r.record(area, StatusInconclusive, "sandbox could not be established")
		return
	}
	defer func() { _ = r.backend.Cleanup(ctx, session) }()

	callCtx, cancel := context.WithTimeout(ctx, r.opts.CommandTimeout)
	defer cancel()
	if _, err := r.backend.Run(callCtx, session, sandbox.Command{
		Path: probeShell(), Args: []string{"-c", "true"}, Dir: "escape",
	}); err == nil {
		r.record(area, StatusFail, "a working directory reached outside the workspace through a symlink")
		return
	}
	r.record(area, StatusPass, "")
}

func (r *runner) checkProcessEscape(ctx context.Context) {
	const area = AreaProcessEscape
	if !r.claims(sandbox.ControlProcessConfinement) {
		r.record(area, StatusSkipped, "backend does not claim enforced process confinement")
		return
	}
	r.record(area, StatusInconclusive,
		"the suite has no portable probe for process escape; a backend claiming this control must supply one")
}

func (r *runner) checkNetworkDeny(ctx context.Context) {
	const area = AreaNetworkDeny
	if !r.claims(sandbox.ControlNetworkDeny) {
		r.record(area, StatusSkipped, "backend does not claim enforced network deny")
		return
	}

	// The probe binds its own loopback listener. A public address could not distinguish a denied
	// egress from an unreachable host, which is why this was Inconclusive until a backend actually
	// claimed the control — the suite refusing to pass an undemonstrated claim is what forced the
	// probe to exist.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.record(area, StatusInconclusive, "a loopback listener could not be bound")
		return
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	dir, cleanup, err := r.workspace()
	if err != nil {
		r.record(area, StatusInconclusive, "workspace could not be created")
		return
	}
	defer cleanup()

	session, err := r.establish(ctx, dir)
	if err != nil {
		r.record(area, StatusInconclusive, "sandbox could not be established")
		return
	}
	defer func() { _ = r.backend.Cleanup(ctx, session) }()

	shell := probeShell()
	if shell == "" {
		r.record(area, StatusInconclusive, "no probe available on this platform")
		return
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		r.record(area, StatusInconclusive, "listener address could not be parsed")
		return
	}

	// The control: the listener is reachable from outside the sandbox, so a failure inside is the
	// confinement rather than a broken fixture.
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second); err != nil {
		r.record(area, StatusInconclusive, "the probe listener was unreachable even outside the sandbox")
		return
	} else {
		_ = conn.Close()
	}

	callCtx, cancel := context.WithTimeout(ctx, r.opts.CommandTimeout)
	defer cancel()
	result, err := r.backend.Run(callCtx, session, sandbox.Command{
		Path: shell,
		Args: []string{"-c", "nc -z -w2 127.0.0.1 " + port + " && echo CONNECTED || echo REFUSED"},
	})
	if err != nil {
		r.record(area, StatusInconclusive, "the network probe could not be run")
		return
	}
	if strings.Contains(result.Stdout, "CONNECTED") {
		r.record(area, StatusFail, "a confined command reached a listening socket")
		return
	}
	if !strings.Contains(result.Stdout, "REFUSED") {
		r.record(area, StatusInconclusive, "the network probe produced no verdict")
		return
	}
	r.record(area, StatusPass, "")
}

func (r *runner) checkResourceLimits(ctx context.Context) {
	const area = AreaResourceLimits
	claimed := false
	for _, control := range []sandbox.Control{
		sandbox.ControlCPULimit, sandbox.ControlMemoryLimit,
		sandbox.ControlProcessLimit, sandbox.ControlDiskLimit,
	} {
		if r.claims(control) {
			claimed = true
		}
	}
	if !claimed {
		r.record(area, StatusSkipped, "backend claims no enforced resource limit")
		return
	}
	r.record(area, StatusInconclusive,
		"the suite has no portable probe for CPU, memory, process, or disk limits")
}

func (r *runner) checkCancellation(ctx context.Context) {
	const area = AreaCancellation
	if !r.claims(sandbox.ControlWallClockLimit) {
		r.record(area, StatusSkipped, "backend does not claim an enforced wall-clock limit")
		return
	}
	dir, cleanup, err := r.workspace()
	if err != nil {
		r.record(area, StatusInconclusive, "workspace could not be created")
		return
	}
	defer cleanup()

	session, err := r.establish(ctx, dir)
	if err != nil {
		r.record(area, StatusInconclusive, "sandbox could not be established")
		return
	}
	defer func() { _ = r.backend.Cleanup(ctx, session) }()

	shell := probeShell()
	if shell == "" {
		r.record(area, StatusInconclusive, "no probe available on this platform")
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	started := time.Now()
	result, _ := r.backend.Run(callCtx, session, sandbox.Command{
		Path: shell, Args: []string{"-c", "sleep 30"},
	})
	elapsed := time.Since(started)

	if elapsed > 5*time.Second {
		r.record(area, StatusFail, "a cancelled command was not stopped promptly")
		return
	}
	if !result.TimedOut {
		// The command stopped quickly but the backend did not report why, which leaves a caller
		// unable to tell a timeout from a fast failure.
		r.record(area, StatusFail, "a cancelled command was not reported as timed out")
		return
	}
	r.record(area, StatusPass, "")
}

func (r *runner) checkSnapshot(ctx context.Context) {
	r.record(AreaSnapshot, StatusSkipped,
		"snapshot is an Environment Blueprint capability (EXE-B02); no backend claims it at this contract version")
}

func (r *runner) checkRestore(ctx context.Context) {
	r.record(AreaRestore, StatusSkipped,
		"restore is an Environment Blueprint capability (EXE-B02); no backend claims it at this contract version")
}

func (r *runner) checkArtifactCollection(ctx context.Context) {
	const area = AreaArtifactCollection
	dir, cleanup, err := r.workspace()
	if err != nil {
		r.record(area, StatusInconclusive, "workspace could not be created")
		return
	}
	defer cleanup()

	session, err := r.establish(ctx, dir)
	if err != nil {
		r.record(area, StatusInconclusive, "sandbox could not be established")
		return
	}
	defer func() { _ = r.backend.Cleanup(ctx, session) }()

	shell := probeShell()
	if shell == "" {
		r.record(area, StatusInconclusive, "no probe available on this platform")
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, r.opts.CommandTimeout)
	defer cancel()
	result, err := r.backend.Run(callCtx, session, sandbox.Command{
		Path: shell, Args: []string{"-c", "echo modbit-artifact-probe"},
	})
	if err != nil {
		r.record(area, StatusFail, "a command producing output could not be run")
		return
	}
	// Output is the minimum artifact: a backend that cannot return it cannot return anything else.
	if !strings.Contains(result.Stdout, "modbit-artifact-probe") {
		r.record(area, StatusFail, "command output was not collected")
		return
	}
	r.record(area, StatusPass, "")
}

func (r *runner) checkCleanup(ctx context.Context) {
	const area = AreaCleanup
	parent, cleanup, err := r.workspace()
	if err != nil {
		r.record(area, StatusInconclusive, "workspace could not be created")
		return
	}
	defer cleanup()

	// A workspace the backend creates itself is the case cleanup owns; a caller-supplied one it must
	// leave alone, and both halves matter.
	created := filepath.Join(parent, "created-by-backend")
	session, err := r.establish(ctx, created)
	if err != nil {
		r.record(area, StatusInconclusive, "sandbox could not be established")
		return
	}
	if err := r.backend.Cleanup(ctx, session); err != nil {
		r.record(area, StatusFail, "cleanup returned an error")
		return
	}
	if _, err := os.Stat(created); err == nil {
		r.record(area, StatusFail, "a backend-created workspace survived cleanup")
		return
	}
	// Cleanup must be idempotent: a caller unwinding through two paths must not fail the second time.
	if err := r.backend.Cleanup(ctx, session); err != nil {
		r.record(area, StatusFail, "cleanup was not idempotent")
		return
	}
	r.record(area, StatusPass, "")
}

func probeShell() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/bin/sh"
}

func writeProbe(target string) (string, []string) {
	shell := probeShell()
	if shell == "" {
		return "", nil
	}
	return shell, []string{"-c", "echo escaped > " + target}
}
