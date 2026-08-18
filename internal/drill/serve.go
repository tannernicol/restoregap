// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// serveOutputTail is how much of the serve command's combined output is kept
// for a failure detail — enough context, never an unbounded amount of a
// server's stdout.
const serveOutputTail = 2048

// serveProbeInterval is how often readiness polls the first probe.
const serveProbeInterval = 250 * time.Millisecond

// serveProbeTimeout bounds a single probe attempt (HTTP request or command),
// independent of the overall ready_timeout — a hung probe must not hang the
// whole drill.
const serveProbeTimeout = 5 * time.Second

// runServe is the L4 rung: boot the recovered artifact in an isolated
// throwaway process (its own process group, killed on every exit path) and
// require it to answer. This is process-level isolation only — a process
// plus the drill's own sandbox dir, NEVER a container. The engine has no
// docker/container dependency; a user's serve command MAY shell out to one,
// but the engine only ever runs a command, waits, probes, and kills it.
//
// SAFETY: c.Run must reference only $RG_TARGET/$RG_SANDBOX — never a live
// production path. The engine has no way to enforce this (it just runs
// whatever shell command was declared); a serve command that points at live
// data instead of the recovered copy will still "pass", having proven
// nothing about recovery at all — see docs/drill-authoring.md's "sandbox
// paths only" note, which every author of a serve check must read.
func runServe(c contextspec.DrillCheck, env checkEnv) checkResult {
	if len(c.Probes) == 0 {
		return failOutcome("serve", "no probes declared")
	}

	port, err := freePort()
	if err != nil {
		return failOutcome("serve", fmt.Sprintf("cannot allocate a port: %v", err))
	}

	out := newTailBuffer(serveOutputTail)
	cmd := exec.Command("sh", "-c", c.Run)
	cmd.Env = append(os.Environ(),
		"RG_SANDBOX="+env.Sandbox,
		"RG_TARGET="+env.Target,
		"RG_RECOVERY_SOURCE="+env.RecoverySource,
		"RG_PORT="+strconv.Itoa(port),
	)
	cmd.Stdout, cmd.Stderr = out, out
	// Its own process group so the whole tree (a serve command that forks
	// helpers) can be killed in one signal, rather than leaving orphans that
	// hold the port or a lock on a file under the sandbox this drill is
	// about to remove.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return failOutcome("serve", fmt.Sprintf("cannot start serve command: %v", err))
	}
	w := waitAsync(cmd)
	// ALWAYS kill: on success, a failed probe, a ready timeout, or an engine
	// error above — every path through this function runs this. A leaked
	// server process is a test that corrupts the next run (port contention,
	// a lock on a file under a sandbox that's about to be removed out from
	// under it).
	defer killProcessGroup(cmd, w)

	readyTimeout := c.ReadyTimeout
	if readyTimeout <= 0 {
		readyTimeout = contextspec.DefaultServeReadyTimeout
	}
	readyIn, readyResult, err := waitReady(c.Probes[0], port, env, readyTimeout, w)
	if err != nil {
		return checkResult{outcome: contextspec.CheckOutcome{
			Type: "serve", Pass: false,
			Detail: fmt.Sprintf("%v — output: %s", err, out.String()),
		}}
	}

	// The serve phase (boot + every probe) runs inside the caller's RTO
	// clock by construction — Run measures start-of-recover to
	// end-of-last-check, and this function only returns once probing is
	// done.
	parts := []string{fmt.Sprintf("ready in %s", readyIn.Round(10*time.Millisecond)), readyResult.detail}
	pass := true
	for i, p := range c.Probes[1:] {
		res := runProbe(p, port, env)
		parts = append(parts, fmt.Sprintf("probe %d %s", i+2, res.detail))
		if !res.pass {
			pass = false
		}
	}

	return checkResult{outcome: contextspec.CheckOutcome{Type: "serve", Pass: pass, Detail: strings.Join(parts, "; ")}}
}

// freePort binds 127.0.0.1:0 to obtain an OS-assigned free port, then
// releases it immediately. There's a small window where something else
// could grab the same port before the serve command binds it — the
// standard, portable way to do this without a container runtime or
// root-only tooling, and good enough for a drill's own throwaway sandbox.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// procWaiter runs cmd.Wait() exactly once in its own goroutine and closes
// Done when it completes, so both the readiness poll loop and the final
// kill can each observe process exit (via select on the closed channel)
// without racing to call Wait() twice — os/exec forbids a second Wait call
// on the same *exec.Cmd.
type procWaiter struct {
	Done chan struct{}
	Err  error
}

func waitAsync(cmd *exec.Cmd) *procWaiter {
	w := &procWaiter{Done: make(chan struct{})}
	go func() {
		w.Err = cmd.Wait()
		close(w.Done)
	}()
	return w
}

// killProcessGroup sends SIGTERM to the whole process group, gives it 5s to
// exit, then SIGKILL. A no-op if the process already exited on its own
// (waitAsync's channel is already closed).
func killProcessGroup(cmd *exec.Cmd, w *procWaiter) {
	if cmd.Process == nil {
		return
	}
	select {
	case <-w.Done:
		return // already exited; nothing to kill
	default:
	}
	pgid := cmd.Process.Pid // Setpgid: true makes the child its own group leader, so pgid == pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	select {
	case <-w.Done:
		return
	case <-time.After(5 * time.Second):
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	<-w.Done
}

// waitReady polls probes[0] every serveProbeInterval until it passes or
// timeout expires, or the serve process exits first (a hard failure — a
// process that exited before ready proves nothing). Returns how long it
// took and the passing probe's own result, so the outcome detail can quote
// it directly instead of running probe 0 a second time.
func waitReady(p contextspec.DrillProbe, port int, env checkEnv, timeout time.Duration, w *procWaiter) (time.Duration, probeResult, error) {
	start := time.Now()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(serveProbeInterval)
	defer ticker.Stop()

	for {
		if res := runProbe(p, port, env); res.pass {
			return time.Since(start), res, nil
		}
		select {
		case <-w.Done:
			return 0, probeResult{}, fmt.Errorf("serve command exited before becoming ready (%v)", w.Err)
		case <-deadline.C:
			return 0, probeResult{}, fmt.Errorf("not ready within %s", timeout)
		case <-ticker.C:
		}
	}
}

// probeResult is one probe attempt's outcome.
type probeResult struct {
	pass   bool
	detail string
}

func runProbe(p contextspec.DrillProbe, port int, env checkEnv) probeResult {
	switch p.Type {
	case "http":
		return runHTTPProbe(p, port)
	case "command":
		return runCommandProbe(p, port, env)
	default:
		return probeResult{detail: fmt.Sprintf("unknown probe type %q", p.Type)}
	}
}

// runHTTPProbe GETs http://127.0.0.1:$RG_PORT<Path> and checks status (and,
// if declared, a body substring). A body mismatch is reported WITHOUT the
// body: the recovered artifact can carry real data, and this repo never
// prints data.
func runHTTPProbe(p contextspec.DrillProbe, port int) probeResult {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", port, p.Path)
	client := http.Client{Timeout: serveProbeTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return probeResult{detail: fmt.Sprintf("GET %s -> error: %v", p.Path, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	wantStatus := p.ExpectStatus
	if wantStatus == 0 {
		wantStatus = 200
	}
	if resp.StatusCode != wantStatus {
		return probeResult{detail: fmt.Sprintf("GET %s -> %d, want %d", p.Path, resp.StatusCode, wantStatus)}
	}
	if p.ExpectBody == "" {
		return probeResult{pass: true, detail: fmt.Sprintf("GET %s -> %d", p.Path, resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return probeResult{detail: fmt.Sprintf("GET %s -> %d (body read failed)", p.Path, resp.StatusCode)}
	}
	if !bytes.Contains(body, []byte(p.ExpectBody)) {
		return probeResult{detail: fmt.Sprintf("GET %s -> %d (body match failed)", p.Path, resp.StatusCode)}
	}
	return probeResult{pass: true, detail: fmt.Sprintf("GET %s -> %d (body ok)", p.Path, resp.StatusCode)}
}

// runCommandProbe runs an arbitrary sh -c probe with RG_PORT/RG_TARGET/
// RG_SANDBOX; exit 0 is pass. The detail is always just the first output
// line (or a plain ok/failed when there is none) — this is a liveness
// probe, not an invariant check, so it stays terse.
func runCommandProbe(p contextspec.DrillProbe, port int, env checkEnv) probeResult {
	cmd := exec.Command("sh", "-c", p.Run)
	cmd.Env = append(os.Environ(),
		"RG_PORT="+strconv.Itoa(port),
		"RG_TARGET="+env.Target,
		"RG_SANDBOX="+env.Sandbox,
	)
	out, err := cmd.CombinedOutput()
	line := firstLine(out)
	pass := err == nil
	if line == "" {
		if pass {
			line = "ok"
		} else {
			line = fmt.Sprintf("failed: %v", err)
		}
	}
	return probeResult{pass: pass, detail: "command probe: " + line}
}

// tailBuffer keeps only the last n bytes ever written to it — a bounded
// capture of a serve command's combined output for failure details, never
// an unbounded amount of a server's stdout.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	n   int
}

func newTailBuffer(n int) *tailBuffer { return &tailBuffer{n: n} }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.n {
		t.buf = t.buf[len(t.buf)-t.n:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
