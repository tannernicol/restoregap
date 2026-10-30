//go:build !darwin && !linux

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package command

import "os/exec"

func configureProcess(_ *exec.Cmd) {}

func stopProcessGroup(cmd *exec.Cmd, wait <-chan error) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	<-wait
}

func cleanupProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
