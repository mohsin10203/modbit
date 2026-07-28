//go:build !unix

package sandbox

import "os/exec"

// configureProcessGroup is a no-op where process groups are not available. The capability
// declaration is unchanged because advisory already promises nothing.
func configureProcessGroup(*exec.Cmd) {}
