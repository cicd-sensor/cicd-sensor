package dockerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

// GitLab runner labels come from the runner job assignment, not project env.
const (
	gitLabRunnerJobURLLabel = "com.gitlab.gitlab-runner.job.url"
	gitLabRunnerJobIDLabel  = "com.gitlab.gitlab-runner.job.id"
)

// containerCreateRequest is the docker create request slice this proxy peeks.
type containerCreateRequest struct {
	Labels map[string]string `json:"Labels"`
}

// gitlabIdentityCtxKey carries labels identity evidence to response handling.
type gitlabIdentityCtxKey struct{}

// errGitLabJobNotFound triggers host/start before one staging retry.
var errGitLabJobNotFound = errors.New("gitlab job not found at agent")

// proxyHandlerGitLab stages docker-<cid>.scope with peer PID and optional
// GitLab runner label identity; the agent chooses which evidence to use.
func proxyHandlerGitLab(logger *slog.Logger, upstreamSocket, agentSocket string) http.Handler {
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

			if !isContainerCreate(req) || req.Body == nil {
				return
			}
			// Restore the body after peeking so dockerd receives identical bytes.
			body, err := io.ReadAll(req.Body)
			if err != nil {
				logger.WarnContext(req.Context(), "container_create_request_read_failed", "error", err)
				return
			}
			req.Body = io.NopCloser(bytes.NewReader(body))
			req.ContentLength = int64(len(body))

			var parsed containerCreateRequest
			if err := json.Unmarshal(body, &parsed); err != nil {
				logger.WarnContext(req.Context(), "container_create_request_decode_failed", "error", err)
				return
			}
			identity, err := jobIdentityFromGitLabLabels(parsed.Labels)
			if err != nil {
				// Helper containers may not carry job labels; peer_pid may still work.
				return
			}
			*req = *req.WithContext(context.WithValue(req.Context(), gitlabIdentityCtxKey{}, identity))
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
			identity, hasIdentity := resp.Request.Context().Value(gitlabIdentityCtxKey{}).(jobcontext.JobIdentity)
			var identityPtr *jobcontext.JobIdentity
			if hasIdentity {
				identityPtr = &identity
			}

			basename := fmt.Sprintf("docker-%s.scope", parsed.ID)
			ctx, cancel := context.WithTimeout(resp.Request.Context(), agentLazyCreateTimeout)
			defer cancel()
			if err := stageGitLabWithLazyCreate(ctx, agentSocket, basename, peerPID, identityPtr); err != nil {
				logger.WarnContext(resp.Request.Context(), "staging_put_failed",
					"error", err,
					"basename", basename,
					"peer_pid", peerPID,
				)
				return nil
			}
			logger.InfoContext(resp.Request.Context(), "staging_put",
				"basename", basename,
				"peer_pid", peerPID,
			)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.WarnContext(r.Context(), "proxy_forward_failed", "error", err, "path", r.URL.Path)
			http.Error(w, "upstream dockerd unavailable", http.StatusBadGateway)
		},
	}
	return rev
}

// stageGitLabWithLazyCreate retries staging once after host/start creates the Job.
func stageGitLabWithLazyCreate(ctx context.Context, agentSocket, basename string, peerPID int32, identity *jobcontext.JobIdentity) error {
	err := postGitLabStaging(ctx, agentSocket, basename, peerPID, identity)
	if err == nil {
		return nil
	}
	if !errors.Is(err, errGitLabJobNotFound) {
		return err
	}
	if identity == nil {
		return err
	}
	// The agent deduplicates concurrent host/start calls for the same identity.
	if err := postGitLabHostStart(ctx, agentSocket, *identity); err != nil {
		return fmt.Errorf("host_start: %w", err)
	}
	return postGitLabStaging(ctx, agentSocket, basename, peerPID, identity)
}

// postGitLabStaging maps 404 to errGitLabJobNotFound for lazy create.
func postGitLabStaging(ctx context.Context, agentSocket, basename string, peerPID int32, identity *jobcontext.JobIdentity) error {
	body, err := json.Marshal(jobcontext.GitLabStagingPutRequest{
		Basename:    basename,
		PeerPID:     peerPID,
		JobIdentity: identity,
	})
	if err != nil {
		return fmt.Errorf("marshal gitlab staging request: %w", err)
	}
	status, respBody, err := postAgent(ctx, agentSocket, "/v1/gitlab/staging/put", body)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return errGitLabJobNotFound
	default:
		return fmt.Errorf("agent /v1/gitlab/staging/put returned %d: %s", status, respBody)
	}
}

// postGitLabHostStart issues the agent's idempotent EnsureJob request.
func postGitLabHostStart(ctx context.Context, agentSocket string, identity jobcontext.JobIdentity) error {
	body, err := json.Marshal(jobcontext.GitLabHostStartRequest{
		JobIdentity: identity,
	})
	if err != nil {
		return fmt.Errorf("marshal gitlab host_start request: %w", err)
	}
	status, respBody, err := postAgent(ctx, agentSocket, "/v1/gitlab/host/start", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("agent /v1/gitlab/host/start returned %d: %s", status, respBody)
	}
	return nil
}

func jobIdentityFromGitLabLabels(labels map[string]string) (jobcontext.JobIdentity, error) {
	if labels == nil {
		return jobcontext.JobIdentity{}, errors.New("labels are required")
	}
	jobURL := strings.TrimSpace(labels[gitLabRunnerJobURLLabel])
	if jobURL == "" {
		return jobcontext.JobIdentity{}, fmt.Errorf("label %q is required", gitLabRunnerJobURLLabel)
	}
	jobID := strings.TrimSpace(labels[gitLabRunnerJobIDLabel])
	if jobID == "" {
		return jobcontext.JobIdentity{}, fmt.Errorf("label %q is required", gitLabRunnerJobIDLabel)
	}

	host, projectPath, urlJobID, err := parseGitLabJobURL(jobURL)
	if err != nil {
		return jobcontext.JobIdentity{}, err
	}
	if urlJobID != jobID {
		return jobcontext.JobIdentity{}, fmt.Errorf("label %q job id %q does not match label %q value %q",
			gitLabRunnerJobURLLabel, urlJobID, gitLabRunnerJobIDLabel, jobID)
	}

	identity := jobcontext.GitLabJobIdentity(host, projectPath, jobID)
	if err := identity.Validate(); err != nil {
		return jobcontext.JobIdentity{}, err
	}
	return identity, nil
}

// parseGitLabJobURL extracts the identity pieces from the runner label:
// https://<host>/<project_path>/-/jobs/<job_id>.
func parseGitLabJobURL(jobURL string) (host, projectPath, jobID string, err error) {
	host, err = jobcontext.DeriveProviderHost(jobURL)
	if err != nil {
		return "", "", "", fmt.Errorf("parse %s: %w", gitLabRunnerJobURLLabel, err)
	}

	parsed, err := url.Parse(jobURL)
	if err != nil {
		return "", "", "", fmt.Errorf("parse %s: %w", gitLabRunnerJobURLLabel, err)
	}

	path := parsed.Path
	if path == "" {
		return "", "", "", fmt.Errorf("%s missing path: %q", gitLabRunnerJobURLLabel, jobURL)
	}
	projectPart, jobPart, ok := strings.Cut(path, "/-/jobs/")
	if !ok {
		return "", "", "", fmt.Errorf("%s has unsupported job URL path: %q", gitLabRunnerJobURLLabel, jobURL)
	}
	projectPath = strings.Trim(projectPart, "/")
	if projectPath == "" {
		return "", "", "", fmt.Errorf("%s has empty project path: %q", gitLabRunnerJobURLLabel, jobURL)
	}

	jobID = strings.Trim(jobPart, "/")
	if jobID == "" {
		return "", "", "", fmt.Errorf("%s has empty job id: %q", gitLabRunnerJobURLLabel, jobURL)
	}
	if strings.Contains(jobID, "/") {
		return "", "", "", fmt.Errorf("%s has unsupported job URL path: %q", gitLabRunnerJobURLLabel, jobURL)
	}
	return host, projectPath, jobID, nil
}
