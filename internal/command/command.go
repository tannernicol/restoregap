// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package command runs declared local commands with one bounded, cancellable
// execution policy. A working directory is only a command's cwd; it is not a
// sandbox or a security boundary.
package command

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// DefaultTimeout is deliberately generous for real recovery sources. It is a
// runtime ceiling, independent from a drill's RTO budget.
const DefaultTimeout = 30 * time.Minute

// DefaultOutputLimit bounds bytes retained from a command's combined output.
// The command may write more; the runner never retains more than this amount.
const DefaultOutputLimit = 64 * 1024

// Options controls one invocation.
type Options struct {
	Env         []string
	Dir         string
	Timeout     time.Duration
	OutputLimit int
}

// Result is the bounded output and outcome of one invocation.
type Result struct {
	Output         []byte // bounded tail retained for diagnostics
	OutputDigest   []byte // SHA-256 of the complete streamed output
	Err            error
	ContextErr     error
	DrainErr       error
	OutputComplete bool
	Truncated      bool
}

// Shell runs command through the platform shell. Shell commands are declared
// by the operator in a context file, so callers must not use this for untrusted
// input. The process and its ordinary descendants share a process group.
func Shell(ctx context.Context, command string, opts Options) Result {
	return run(ctx, exec.Command("sh", "-c", command), opts)
}

// Command runs an executable with arguments. It uses the same timeout,
// output, cancellation, and descendant cleanup policy as Shell.
func Command(ctx context.Context, name string, args []string, opts Options) Result {
	return run(ctx, exec.Command(name, args...), opts)
}

func run(ctx context.Context, cmd *exec.Cmd, opts Options) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Timeout <= 0 {
		return Result{Err: fmt.Errorf("command: timeout must be positive")}
	}
	if err := ctx.Err(); err != nil {
		return Result{Err: err, ContextErr: err}
	}
	limit := opts.OutputLimit
	if limit <= 0 {
		limit = DefaultOutputLimit
	}
	if opts.Env != nil {
		cmd.Env = opts.Env
	}
	if opts.Dir != "" {
		cmd.Dir = opts.Dir
	}
	configureProcess(cmd)
	output := newTailBuffer(limit)
	reader, writer, err := os.Pipe()
	if err != nil {
		return Result{Err: err}
	}
	cmd.Stdout, cmd.Stderr = writer, writer

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	if err := cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return Result{Err: err}
	}
	_ = writer.Close()
	readDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(output, reader)
		readDone <- err
	}()

	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	select {
	case err := <-wait:
		// Prefer cancellation over a simultaneous zero exit. A command that
		// finishes as its caller is canceled cannot establish proof.
		if ctxErr := runCtx.Err(); ctxErr != nil {
			cleanupProcessGroup(cmd)
			drainErr := finishOutput(reader, readDone)
			return result(output, ctxErr, ctxErr, drainErr)
		}
		cleanupProcessGroup(cmd)
		drainErr := finishOutput(reader, readDone)
		return result(output, err, nil, drainErr)
	case <-runCtx.Done():
		stopProcessGroup(cmd, wait)
		ctxErr := runCtx.Err()
		drainErr := finishOutput(reader, readDone)
		return result(output, ctxErr, ctxErr, drainErr)
	}
}

func result(output *tailBuffer, err, contextErr, drainErr error) Result {
	if err == nil && drainErr != nil {
		err = fmt.Errorf("command: output drain failed: %w", drainErr)
	}
	return Result{
		Output: output.Bytes(), OutputDigest: output.Digest(), Err: err,
		ContextErr: contextErr, DrainErr: drainErr, OutputComplete: drainErr == nil,
		Truncated: output.Truncated(),
	}
}

func finishOutput(reader *os.File, done <-chan error) error {
	select {
	case err := <-done:
		_ = reader.Close()
		return err
	case <-time.After(500 * time.Millisecond):
		_ = reader.Close()
		select {
		case err := <-done:
			if err != nil {
				return err
			}
			return errors.New("output drain cutoff")
		case <-time.After(500 * time.Millisecond):
			return errors.New("output drain cutoff")
		}
	}
}

type tailBuffer struct {
	mu        sync.Mutex
	buf       []byte
	limit     int
	digest    hash.Hash
	truncated bool
}

func newTailBuffer(limit int) *tailBuffer { return &tailBuffer{limit: limit, digest: sha256.New()} }

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, _ = b.digest.Write(p)
	if len(p) >= b.limit {
		if len(p) > b.limit || len(b.buf) > 0 {
			b.truncated = true
		}
		b.buf = append(b.buf[:0], p[len(p)-b.limit:]...)
		return len(p), nil
	}
	if len(b.buf)+len(p) > b.limit {
		b.truncated = true
	}
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.limit {
		b.buf = b.buf[len(b.buf)-b.limit:]
	}
	return len(p), nil
}

func (b *tailBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf...)
}

func (b *tailBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

func (b *tailBuffer) Digest() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.digest.Sum(nil)...)
}
