package httpprepare

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

// Process identifies a process on this node. Docker reports PID in the daemon's
// namespace; DaemonPID anchors that namespace in the Agent's host PID view.
// NRI and machine callers leave DaemonPID zero and supply a host PID.
type Process struct {
	PID       int
	DaemonPID int
}

// Validate rejects values that cannot represent Linux process identifiers.
func (p Process) Validate() error {
	if p.PID <= 0 || p.PID > 1<<31-1 || p.DaemonPID < 0 || p.DaemonPID > 1<<31-1 {
		return errors.New("invalid HTTP preparation PID")
	}
	return nil
}

// Handler queues metadata only; all filesystem work belongs to the HTTP worker.
type Handler func(context.Context, Process) error

// SocketPath is node-only, separate from the Job-facing HTTP routes.
func SocketPath(agentSocket string) string { return agentSocket + ".http-preparation" }

// Client sends process metadata. It never opens another process's files.
type Client struct{ client *http.Client }

// NewRemote connects to the Agent on the same node and PID view.
func NewRemote(agentSocket string) *Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", SocketPath(agentSocket))
		},
	}
	return &Client{client: &http.Client{Transport: transport, Timeout: Budget}}
}

// Prepare waits for preparation within the caller deadline or Budget.
func (p *Client) Prepare(ctx context.Context, process Process) error {
	if err := process.Validate(); err != nil {
		return err
	}
	url := fmt.Sprintf("http://agent/prepare?pid=%d&daemon_pid=%d", process.PID, process.DaemonPID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("HTTP preparation returned %d", resp.StatusCode)
	}
	return nil
}
