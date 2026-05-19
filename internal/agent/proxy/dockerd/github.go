package dockerd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// proxyHandlerGitHub stages docker-<cid>.scope using peer-PID identity.
func proxyHandlerGitHub(logger *slog.Logger, upstreamSocket, agentSocket string) http.Handler {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", upstreamSocket)
		},
	}

	rev := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = "docker"
			req.Host = "docker"
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			if !isContainerCreate(resp.Request) {
				return nil
			}
			if resp.StatusCode != http.StatusCreated {
				return nil
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				logger.WarnContext(resp.Request.Context(), "container_create_body_read_failed", "error", err)
				return nil
			}
			// Restore the response body for the downstream client. Without
			// this the docker CLI receives an empty payload and aborts.
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

			var parsed containerCreateResponse
			if err := json.Unmarshal(body, &parsed); err != nil {
				logger.WarnContext(resp.Request.Context(), "container_create_decode_failed", "error", err)
				return nil
			}
			if parsed.ID == "" {
				logger.WarnContext(resp.Request.Context(), "container_create_missing_id")
				return nil
			}

			peerPID, _ := resp.Request.Context().Value(peerPIDCtxKey{}).(int32)
			basename := fmt.Sprintf("docker-%s.scope", parsed.ID)

			// Block briefly so staging_map is populated before docker
			// proceeds to /start and creates the container cgroup.
			ctx, cancel := context.WithTimeout(resp.Request.Context(), agentPostTimeout)
			defer cancel()
			if err := postGitHubStaging(ctx, agentSocket, jobcontext.GitHubStagingPutRequest{
				Basename: basename,
				PeerPID:  peerPID,
			}); err != nil {
				// Fail open: observability must not break docker create.
				logger.WarnContext(resp.Request.Context(), "staging_put_failed",
					"error", err,
					"basename", basename,
				)
				return nil
			}
			logger.InfoContext(resp.Request.Context(), "staging_put", "basename", basename)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.WarnContext(r.Context(), "proxy_forward_failed", "error", err, "path", r.URL.Path)
			http.Error(w, "upstream dockerd unavailable", http.StatusBadGateway)
		},
	}

	return rev
}

// postGitHubStaging submits one basename + peer_pid pair to the agent's
// GitHub staging endpoint.
func postGitHubStaging(ctx context.Context, agentSocket string, req jobcontext.GitHubStagingPutRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal staging request: %w", err)
	}
	status, respBody, err := postAgent(ctx, agentSocket, "/v1/github/staging/put", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("agent /v1/github/staging/put returned %d: %s", status, respBody)
	}
	return nil
}
