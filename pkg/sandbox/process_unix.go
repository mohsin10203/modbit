//go:build unix

package sandbox

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group so cancellation can reach its
// descendants rather than only the process that was started.
//
// This is why ControlProcessConfinement is declared advisory rather than enforced: it makes an
// orphaned child tree killable, and does nothing to stop a process leaving the group deliberately.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
