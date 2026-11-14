// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package jobs

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup starts cmd in a new process group, so signals reach the
// processes it starts too, such as Terraform under a shell or Terraform's
// providers. It is what a terminal does for a foreground command.
func ownProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

func signalGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid && cmd.SysProcAttr.Pgid == 0 {
		if err := syscall.Kill(-cmd.Process.Pid, sig); err == nil {
			return
		}
	}
	_ = cmd.Process.Signal(sig)
}

// interruptProcess sends SIGINT, as Ctrl-C would. Terraform then stops
// scheduling work, waits for in-flight operations, saves state, and releases
// its lock. Its providers ignore the interrupt and wait for Terraform.
func interruptProcess(cmd *exec.Cmd) {
	signalGroup(cmd, syscall.SIGINT)
}

func killProcess(cmd *exec.Cmd) {
	signalGroup(cmd, syscall.SIGKILL)
}
