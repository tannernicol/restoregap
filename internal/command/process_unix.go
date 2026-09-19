//go:build darwin || linux

package command

import (
	"os/exec"
	"syscall"
	"time"
)

func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func stopProcessGroup(cmd *exec.Cmd, wait <-chan error) {
	if cmd.Process == nil {
		return
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-wait:
		// The parent is gone, but ordinary descendants may still hold the
		// output pipe. Give TERM a short grace period, then kill the group.
		time.Sleep(20 * time.Millisecond)
		if syscall.Kill(-pgid, 0) == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
	case <-timer.C:
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		waitTimer := time.NewTimer(500 * time.Millisecond)
		defer waitTimer.Stop()
		select {
		case <-wait:
		case <-waitTimer.C:
		}
	}
}

func cleanupProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	time.Sleep(20 * time.Millisecond)
	if syscall.Kill(-pgid, 0) == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}
}
