//go:build !unix

package sandbox

import "os/exec"

// configureProcessGroup is a no-op where process groups are not available. The capability
// declaration is unchanged because advisory already promises nothing.
//
// WaitDelay still applies: it needs no process group, and without it a cancelled command whose
// descendants hold the output pipe blocks Wait for as long as they live.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.WaitDelay = processWaitDelay
}
