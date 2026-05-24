package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// postSocket sends a JSON POST to the agent control socket and returns an
// error if the response status is not 2xx.
func postSocket(ctx context.Context, socketPath, urlPath string, body any) error {
	_, err := postSocketForResponse(ctx, socketPath, urlPath, body, 4<<10)
	return err
}

// postSocketForResponse sends a JSON POST and returns the response body
// (read into memory, capped at maxBytes) on 2xx. Non-2xx is converted to
// an error whose message includes the truncated server payload.
//
// `project result` is the only endpoint that needs the response body
// today; keeping the helper separate from postSocket means other callers
// stay unaffected by the larger read budget the summary log needs.
func postSocketForResponse(ctx context.Context, socketPath, urlPath string, body any, maxBytes int64) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+urlPath, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", urlPath, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", urlPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if len(msg) == 0 {
			return nil, fmt.Errorf("agent returned status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("agent returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	out, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", urlPath, err)
	}
	return out, nil
}

// formatAgentUnreachable produces a user-facing stderr message for cases
// where the agent control socket failed to answer. The raw error is kept
// verbatim so operators can still debug the root cause. `consequence`
// describes what the caller could not finish because of the failure.
func formatAgentUnreachable(socketPath, consequence string, err error) string {
	return fmt.Sprintf(
		"⚠️  cicd-sensor health check failed.\n"+
			"   The agent encountered an error or was terminated unexpectedly before the job finished.\n"+
			"   %s\n\n"+
			"   socket: %s\n"+
			"   underlying error: %v",
		consequence, socketPath, err,
	)
}
