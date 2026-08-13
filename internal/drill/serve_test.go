package drill

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// TestHelperProcess-pattern (stdlib-only, hermetic, no nc/python/docker
// dependency): the shell command a "serve" check runs re-invokes this same
// test binary in a special mode that starts a real net/http server on
// $RG_PORT. GO_WANT_HELPER_PROCESS gates it so a normal `go test` run treats
// TestHelperProcess as an instant no-op.

func helperCommand(t *testing.T, args ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return fmt.Sprintf("%s -test.run=^TestHelperProcess$ -- %s", exe, strings.Join(quoted, " "))
}

// TestHelperProcess is not a real test: it's the subprocess entry point for
// serve-check tests. GO_WANT_HELPER_PROCESS unset (every normal `go test`
// invocation) makes it return immediately.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}
	if len(args) == 0 {
		fatalHelper("no helper mode given")
	}
	switch args[0] {
	case "httpserver":
		runHelperHTTPServer(args[1:])
	case "exit":
		code := 0
		if len(args) > 1 {
			code, _ = strconv.Atoi(args[1])
		}
		os.Exit(code)
	case "sleep":
		time.Sleep(time.Hour) // never listens; killed by the test before this returns
	default:
		fatalHelper("unknown helper mode " + args[0])
	}
}

func fatalHelper(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

// runHelperHTTPServer starts a real HTTP server on $RG_PORT, writes its own
// pid to pidfile once bound (so the test can later assert it was killed),
// and serves each declared route ("path=status=body") a fixed response.
func runHelperHTTPServer(args []string) {
	if len(args) < 2 {
		fatalHelper("httpserver requires: pidfile route[,route...]")
	}
	pidfile, routes := args[0], args[1:]

	ln, err := net.Listen("tcp", "127.0.0.1:"+os.Getenv("RG_PORT"))
	if err != nil {
		fatalHelper("listen: " + err.Error())
	}
	if err := os.WriteFile(pidfile, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		fatalHelper("write pidfile: " + err.Error())
	}

	mux := http.NewServeMux()
	for _, route := range routes {
		parts := strings.SplitN(route, "=", 3)
		if len(parts) != 3 {
			fatalHelper("bad route spec " + route)
		}
		path, status, body := parts[0], parts[1], parts[2]
		code, err := strconv.Atoi(status)
		if err != nil {
			fatalHelper("bad status in route " + route)
		}
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		})
	}
	_ = http.Serve(ln, mux) // blocks until killed
}

// assertProcessGone reads pid from pidfile and polls until signal 0 fails
// with ESRCH (or a short deadline elapses) — the kill guarantee, checked for
// real rather than trusted.
func assertProcessGone(t *testing.T, pidfile string) {
	t.Helper()
	raw, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("bad pid in pidfile %q: %v", raw, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			return // ESRCH: gone
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d still alive after runServe returned — kill guarantee violated", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func serveEnv(dir string) checkEnv {
	return checkEnv{Target: dir, Sandbox: dir, Now: time.Now}
}

func TestRunServeReadyAndProbesPass(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")

	c := contextspec.DrillCheck{
		Type:         "serve",
		Run:          helperCommand(t, "httpserver", pidfile, "/health=200=ok", "/api/summary=200=net_worth_data"),
		ReadyTimeout: 5 * time.Second,
		Probes: []contextspec.DrillProbe{
			{Type: "http", Path: "/health", ExpectStatus: 200},
			{Type: "http", Path: "/api/summary", ExpectStatus: 200, ExpectBody: "net_worth"},
		},
	}
	res := runServe(c, serveEnv(dir))
	if !res.outcome.Pass {
		t.Fatalf("expected pass, got %+v", res.outcome)
	}
	if !strings.Contains(res.outcome.Detail, "ready in") {
		t.Errorf("detail should mention readiness timing: %q", res.outcome.Detail)
	}
	if !strings.Contains(res.outcome.Detail, "probe 2") {
		t.Errorf("detail should describe the second probe: %q", res.outcome.Detail)
	}
	if !strings.Contains(res.outcome.Detail, "body ok") {
		t.Errorf("detail should confirm the body match: %q", res.outcome.Detail)
	}
	assertProcessGone(t, pidfile)
}

func TestRunServeWrongStatus(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")

	c := contextspec.DrillCheck{
		Type:         "serve",
		Run:          helperCommand(t, "httpserver", pidfile, "/health=200=ok", "/other=500=broken"),
		ReadyTimeout: 5 * time.Second,
		Probes: []contextspec.DrillProbe{
			{Type: "http", Path: "/health", ExpectStatus: 200},
			{Type: "http", Path: "/other", ExpectStatus: 200},
		},
	}
	res := runServe(c, serveEnv(dir))
	if res.outcome.Pass {
		t.Fatal("wrong status on a probe must not pass")
	}
	if !strings.Contains(res.outcome.Detail, "500") || !strings.Contains(res.outcome.Detail, "want 200") {
		t.Errorf("detail should name status got vs want, got %q", res.outcome.Detail)
	}
	assertProcessGone(t, pidfile)
}

func TestRunServeBodyMismatch(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")

	c := contextspec.DrillCheck{
		Type:         "serve",
		Run:          helperCommand(t, "httpserver", pidfile, "/health=200=ok", "/other=200=super-secret-recovered-data"),
		ReadyTimeout: 5 * time.Second,
		Probes: []contextspec.DrillProbe{
			{Type: "http", Path: "/health", ExpectStatus: 200},
			{Type: "http", Path: "/other", ExpectStatus: 200, ExpectBody: "expected-substring"},
		},
	}
	res := runServe(c, serveEnv(dir))
	if res.outcome.Pass {
		t.Fatal("body mismatch must not pass")
	}
	if !strings.Contains(res.outcome.Detail, "body match failed") {
		t.Errorf("detail should say the body match failed, got %q", res.outcome.Detail)
	}
	if strings.Contains(res.outcome.Detail, "super-secret-recovered-data") {
		t.Errorf("detail must NEVER include the response body (it can carry real data): %q", res.outcome.Detail)
	}
	assertProcessGone(t, pidfile)
}

// TestRunServeReadyTimeout: a process that never listens must fail with a
// timeout detail, not hang forever.
func TestRunServeReadyTimeout(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	dir := t.TempDir()

	c := contextspec.DrillCheck{
		Type:         "serve",
		Run:          helperCommand(t, "sleep"),
		ReadyTimeout: 600 * time.Millisecond,
		Probes:       []contextspec.DrillProbe{{Type: "http", Path: "/health", ExpectStatus: 200}},
	}
	start := time.Now()
	res := runServe(c, serveEnv(dir))
	elapsed := time.Since(start)
	if res.outcome.Pass {
		t.Fatal("a process that never becomes ready must not pass")
	}
	if !strings.Contains(res.outcome.Detail, "not ready within") {
		t.Errorf("detail should say it never became ready, got %q", res.outcome.Detail)
	}
	if elapsed > 3*time.Second {
		t.Errorf("ready_timeout should bound the wait; took %s", elapsed)
	}
}

// TestRunServeProcessExitsEarly: exiting before the first probe passes is a
// hard failure — it proves nothing came up.
func TestRunServeProcessExitsEarly(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	dir := t.TempDir()

	c := contextspec.DrillCheck{
		Type:         "serve",
		Run:          helperCommand(t, "exit", "3"),
		ReadyTimeout: 3 * time.Second,
		Probes:       []contextspec.DrillProbe{{Type: "http", Path: "/health", ExpectStatus: 200}},
	}
	res := runServe(c, serveEnv(dir))
	if res.outcome.Pass {
		t.Fatal("an early-exiting serve command must not pass")
	}
	if !strings.Contains(res.outcome.Detail, "exited before becoming ready") {
		t.Errorf("detail should say the process exited early, got %q", res.outcome.Detail)
	}
}

func TestRunServeNoProbes(t *testing.T) {
	res := runServe(contextspec.DrillCheck{Type: "serve", Run: "true"}, serveEnv(t.TempDir()))
	if res.outcome.Pass {
		t.Fatal("a serve check with no probes must not pass")
	}
	if !strings.Contains(res.outcome.Detail, "no probes") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
}

// TestRunServeCommandProbe exercises the "command" probe type end to end,
// including it receiving RG_PORT so it can reach the booted server itself.
func TestRunServeCommandProbe(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "pid")

	c := contextspec.DrillCheck{
		Type:         "serve",
		Run:          helperCommand(t, "httpserver", pidfile, "/health=200=ok"),
		ReadyTimeout: 5 * time.Second,
		Probes: []contextspec.DrillProbe{
			{Type: "http", Path: "/health", ExpectStatus: 200},
			{Type: "command", Run: `[ -n "$RG_PORT" ] && echo "port seen"`},
		},
	}
	res := runServe(c, serveEnv(dir))
	if !res.outcome.Pass {
		t.Fatalf("expected pass, got %+v", res.outcome)
	}
	if !strings.Contains(res.outcome.Detail, "command probe: port seen") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
	assertProcessGone(t, pidfile)
}
