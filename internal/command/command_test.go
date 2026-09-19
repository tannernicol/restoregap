//go:build darwin || linux

package command

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestShellNormalAndFailingCommands(t *testing.T) {
	pass := Shell(context.Background(), "printf ok", Options{Timeout: time.Second})
	if pass.Err != nil || string(pass.Output) != "ok" {
		t.Fatalf("pass = %+v", pass)
	}
	fail := Shell(context.Background(), "printf nope >&2; exit 7", Options{Timeout: time.Second})
	if fail.Err == nil || string(fail.Output) != "nope" {
		t.Fatalf("fail = %+v", fail)
	}
}

func TestShellDoesNotStartAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := Shell(ctx, "touch "+filepath.Join(t.TempDir(), "started"), Options{Timeout: time.Second})
	if res.ContextErr != context.Canceled {
		t.Fatalf("ContextErr = %v, want canceled", res.ContextErr)
	}
}

func TestShellTimeoutKillsDescendantsHoldingOutput(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "pid")
	res := Shell(context.Background(), "sleep 30 & child=$!; printf '%s' $child > "+pidPath+"; wait", Options{Timeout: 80 * time.Millisecond})
	if res.ContextErr != context.DeadlineExceeded {
		t.Fatalf("ContextErr = %v, want deadline exceeded", res.ContextErr)
	}
	if res.Err == nil {
		t.Fatal("timeout must fail")
	}
	pidBytes, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("read child pid: %v", err)
	}
	var pid int
	if _, err := fmt.Sscanf(string(pidBytes), "%d", &pid); err != nil {
		t.Fatalf("parse child pid %q: %v", pidBytes, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant pid %d survived cancellation", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShellSuccessCleansDescendantThatIgnoresTerm(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "pid")
	res := Shell(context.Background(), "(trap '' TERM; sleep 30) & child=$!; printf '%s' $child > "+pidPath+"; exit 0", Options{Timeout: time.Second})
	if res.Err != nil {
		t.Fatalf("command: %v", res.Err)
	}
	pidBytes, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("read child pid: %v", err)
	}
	var pid int
	if _, err := fmt.Sscanf(string(pidBytes), "%d", &pid); err != nil {
		t.Fatalf("parse child pid %q: %v", pidBytes, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant pid %d survived successful command cleanup", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShellCancellationKillsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan Result, 1)
	go func() {
		close(started)
		result <- Shell(ctx, "sleep 30", Options{Timeout: time.Minute})
	}()
	<-started
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case res := <-result:
		if res.ContextErr != context.Canceled {
			t.Fatalf("ContextErr = %v, want canceled", res.ContextErr)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not return promptly")
	}
}

func TestShellBoundsNoisyOutput(t *testing.T) {
	res := Shell(context.Background(), "head -c 100000 /dev/zero", Options{Timeout: time.Second, OutputLimit: 128})
	if res.Err != nil {
		t.Fatalf("noisy command: %v", res.Err)
	}
	if len(res.Output) != 128 || !res.Truncated {
		t.Fatalf("output len/truncated = %d/%v, want 128/true", len(res.Output), res.Truncated)
	}
	if strings.Trim(string(res.Output), "\x00") != "" {
		t.Fatal("bounded output changed bytes")
	}
}

func TestTailBufferExactLimitIsComplete(t *testing.T) {
	b := newTailBuffer(4)
	_, _ = b.Write([]byte("1234"))
	if b.Truncated() {
		t.Fatal("exactly limit bytes must not be truncated")
	}
	_, _ = b.Write([]byte("5"))
	if !b.Truncated() {
		t.Fatal("bytes beyond limit must be marked truncated")
	}
}

func TestFinishOutputReportsCutoff(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := finishOutput(reader, make(chan error)); err == nil {
		t.Fatal("expected an output drain cutoff")
	}
}
