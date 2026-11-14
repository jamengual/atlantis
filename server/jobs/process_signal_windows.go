// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package jobs

import "os/exec"

// Windows has no process groups to signal and no interrupt to send to a
// background process, so stopping a job kills its process at once.
func ownProcessGroup(_ *exec.Cmd) {}

func interruptProcess(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
}

func killProcess(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
}
