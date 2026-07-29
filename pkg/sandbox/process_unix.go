//go:build unix

package sandbox

import (
	"errors"
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group and makes cancellation reach it.
//
// This is why ControlProcessConfinement is declared advisory rather than enforced: it makes an
// orphaned child tree killable, and does nothing to stop a process leaving the group deliberately.
//
// # Why Cancel is replaced
//
// `exec.CommandContext` installs a default cancel that calls `Process.Kill`, which signals the one
// PID it started. With `Setpgid` that is precisely the wrong target: the shell dies, the children it
// forked keep running in the group, and because they inherited the write end of the stdout pipe,
// `Wait` blocks until they finish on their own. `sh -c "sleep 30"` under a 150 ms deadline therefore
// returned after 30 seconds — cancelled in name, not in effect.
//
// Signalling the negative pgid reaches the whole group the child leads, which is what `Setpgid` was
// set up for and what the previous comment here claimed already happened.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// The child leads its own group, so its pgid equals its pid. ESRCH means it and its
		// descendants are already gone, which is the outcome asked for rather than a failure.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}

	// A kill is not a guarantee that the pipe is released: a process can leave the group
	// deliberately — the same gap that makes this control advisory — or sit in uninterruptible I/O.
	// WaitDelay bounds how long Wait may block on the copying goroutines after cancellation, so the
	// worst case is a late return rather than one that never comes.
	cmd.WaitDelay = processWaitDelay
}
