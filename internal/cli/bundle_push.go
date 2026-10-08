// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/bundle"
)

const (
	pushTokenEnv     = "RESTOREGAP_PUSH_TOKEN"
	pushTimeout      = 30 * time.Second
	pushMaxReadBytes = 64 << 10
	pushPath         = "/api/v1/bundles"
)

// newBundlePushCmd builds `restoregap bundle push`: the one explicit network
// action the binary has. It sends a signed bundle to a Restore Gap Cloud (or
// self-hosted) endpoint, and only when the operator runs it.
func newBundlePushCmd() *cobra.Command {
	var to, token string
	var insecureHTTP, summaryOnly bool
	var flags bundleExportFlags
	cmd := &cobra.Command{
		Use:   "push --to <base-url> --token <token> [export flags... | <existing.tgz>]",
		Short: "Send a signed bundle to Restore Gap Cloud (the only command that uses the network by itself)",
		Long: "Builds the same signed archive `bundle export` builds (same flags, same context discovery),\n" +
			"or sends an existing .tgz given as the one positional argument, with a single\n" +
			"POST <base-url>/api/v1/bundles. This is the ONE explicit network action restoregap has: it\n" +
			"runs only when you invoke it — put it in a cron line, a timer or a CI step if you want it\n" +
			"recurring. Nothing else in the binary contacts Cloud, and nothing runs in the background.\n" +
			"\n" +
			"The token is sent only as an Authorization: Bearer header and is never printed. Prefer the\n" +
			pushTokenEnv + " environment variable over --token, which is visible in the process list.\n" +
			"--to must be https://; plain http:// is accepted only for localhost/127.0.0.1/::1 or with\n" +
			"--insecure-http. Redirects are not followed, there is a 30s timeout, and there are no retries.\n" +
			"\n" +
			"Exit 0 when the service accepts the bundle; 1 when it refuses it (401/402/409/413/422 — the\n" +
			"reason is printed); 2 on a usage error, a network error, or any other response.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fail := func(code int, format string, a ...any) error {
				cmd.SilenceUsage = true
				return &ExitError{Code: code, Message: "bundle push: " + fmt.Sprintf(format, a...)}
			}
			if summaryOnly {
				return fail(2, "--summary-only is not supported; push sends the full signed archive")
			}
			if token == "" {
				token = os.Getenv(pushTokenEnv)
			}
			if to == "" {
				return fail(2, "--to is required (the base URL of the service, e.g. https://cloud.restoregap.com)")
			}
			if token == "" {
				return fail(2, "--token or %s is required", pushTokenEnv)
			}
			endpoint, err := pushEndpoint(to, insecureHTTP)
			if err != nil {
				return fail(2, "%v", err)
			}

			var body []byte
			if len(args) == 1 {
				for _, name := range bundleExportFlagNames {
					if cmd.Flags().Changed(name) {
						return fail(2, "--%s builds an archive and cannot be combined with an existing archive argument", name)
					}
				}
				body, err = os.ReadFile(args[0])
				if err != nil {
					return fail(2, "read archive: %v", err)
				}
			} else {
				body, err = buildPushArchive(cmd, &flags)
				if err != nil {
					return err
				}
			}

			status, respBody, err := postBundle(endpoint, token, body)
			if err != nil {
				return fail(2, "%s", scrubToken(err.Error(), token))
			}
			return reportPush(cmd, status, respBody)
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "base URL of the service to push to (required; https, or http only for localhost)")
	cmd.Flags().StringVar(&token, "token", "", "workspace push token (or set "+pushTokenEnv+"; never printed)")
	cmd.Flags().BoolVar(&insecureHTTP, "insecure-http", false, "allow a plain http:// --to for a non-localhost host (the token travels unencrypted)")
	cmd.Flags().BoolVar(&summaryOnly, "summary-only", false, "not supported for push")
	_ = cmd.Flags().MarkHidden("summary-only")
	flags.register(cmd)
	return cmd
}

// buildPushArchive exports the archive into a private temp directory with
// the shared export plumbing, returns its bytes, and deletes the temp file.
func buildPushArchive(cmd *cobra.Command, flags *bundleExportFlags) ([]byte, error) {
	in, err := flags.resolve(cmd, "bundle push")
	if err != nil {
		return nil, err
	}
	if flags.signingKey == "" {
		cmd.SilenceUsage = true
		return nil, &ExitError{Code: 2, Message: "bundle push: --signing-key is required — a bundle is only useful signed"}
	}
	dir, err := os.MkdirTemp("", "restoregap-push-")
	if err != nil {
		cmd.SilenceUsage = true
		return nil, &ExitError{Code: 2, Message: "bundle push: " + err.Error()}
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path, err := bundle.Export(flags.request(in, filepath.Join(dir, "bundle.tgz")))
	if err != nil {
		cmd.SilenceUsage = true
		return nil, &ExitError{Code: 2, Message: err.Error()}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		cmd.SilenceUsage = true
		return nil, &ExitError{Code: 2, Message: "bundle push: " + err.Error()}
	}
	return data, nil
}

// pushEndpoint validates --to and returns the full POST URL.
func pushEndpoint(to string, insecureHTTP bool) (string, error) {
	u, err := url.Parse(to)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "", errors.New("--to must be an absolute URL such as https://cloud.restoregap.com")
	}
	if u.User != nil {
		return "", errors.New("--to must not contain credentials; pass the token with --token or " + pushTokenEnv)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("--to must be a base URL without a query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !insecureHTTP && !isLoopbackHost(u.Hostname()) {
			return "", fmt.Errorf("refusing plain http:// to %s — the token would travel unencrypted; use https://, or pass --insecure-http to override", u.Hostname())
		}
	default:
		return "", errors.New("--to must be an https:// URL")
	}
	return strings.TrimRight(u.String(), "/") + pushPath, nil
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// postBundle sends the archive. It follows no redirects (a redirect would
// re-send the token to another place), has a 30s timeout and never retries.
// The response body is read up to 64 KiB.
func postBundle(endpoint, token string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("User-Agent", "restoregap/"+Version)
	client := &http.Client{
		Timeout:       pushTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, pushMaxReadBytes))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, data, nil
}

// reportPush maps the service's answer to output and exit code.
func reportPush(cmd *cobra.Command, status int, body []byte) error {
	out := cmd.OutOrStdout()
	switch status {
	case http.StatusCreated:
		var r struct {
			Host        string `json:"host"`
			HostID      string `json:"host_id"`
			GeneratedAt string `json:"generated_at"`
			URL         string `json:"url"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			_, _ = fmt.Fprintln(out, "pushed: the service accepted the bundle (201) but returned an unreadable response")
			return nil
		}
		_, _ = fmt.Fprintf(out, "pushed: %s (%s) generated %s → %s\n",
			cleanServerText(r.Host), cleanServerText(r.HostID), cleanServerText(r.GeneratedAt), cleanServerText(r.URL))
		return nil
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusConflict,
		http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		_, _ = fmt.Fprintf(out, "push refused (%d): %s\n", status, pushErrorText(status, body))
		cmd.SilenceUsage = true
		return &ExitError{Code: 1}
	default:
		cmd.SilenceUsage = true
		msg := fmt.Sprintf("bundle push: unexpected response %d %s", status, http.StatusText(status))
		if status >= 300 && status < 400 {
			msg += " (redirects are not followed)"
		}
		return &ExitError{Code: 2, Message: msg}
	}
}

// pushErrorText returns the "error" field of a JSON body, else the body
// text, else the status text.
func pushErrorText(status int, body []byte) string {
	var j struct {
		Error string `json:"error"`
	}
	text := ""
	if json.Unmarshal(body, &j) == nil && j.Error != "" {
		text = j.Error
	} else {
		text = string(body)
	}
	text = cleanServerText(text)
	if text == "" {
		text = http.StatusText(status)
	}
	return text
}

// cleanServerText drops control characters (terminal escape sequences) from
// text a remote service supplied, and trims surrounding space.
func cleanServerText(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
}

func scrubToken(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "[redacted]")
}
