package nri

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

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

const agentPostTimeout = 5 * time.Second

type agentClient struct {
	socketPath string
}

func (c *agentClient) stage(ctx context.Context, decision stagingDecision) error {
	switch decision.Provider {
	case jobcontext.ProviderGitHub:
		return c.postGitHubStaging(ctx, decision.Basename, decision.Identity)
	case jobcontext.ProviderGitLab:
		return c.postGitLabStaging(ctx, decision.Basename, decision.Identity, decision.Metadata)
	default:
		return fmt.Errorf("unsupported provider %q", decision.Provider)
	}
}

func (c *agentClient) postGitHubStaging(ctx context.Context, basename string, identity jobcontext.JobIdentity) error {
	body, err := json.Marshal(jobcontext.GitHubK8sStagingPutRequest{
		Basename:    basename,
		JobIdentity: identity,
	})
	if err != nil {
		return fmt.Errorf("marshal github staging request: %w", err)
	}
	status, respBody, err := c.post(ctx, "/v1/github/k8s/staging/put", body)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("agent /v1/github/k8s/staging/put returned %d: job not found", status)
	default:
		return fmt.Errorf("agent /v1/github/k8s/staging/put returned %d: %s", status, respBody)
	}
}

func (c *agentClient) postGitLabStaging(ctx context.Context, basename string, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata) error {
	body, err := json.Marshal(jobcontext.GitLabK8sStagingPutRequest{
		Basename:    basename,
		JobIdentity: identity,
		Metadata:    metadata,
	})
	if err != nil {
		return fmt.Errorf("marshal gitlab staging request: %w", err)
	}
	status, respBody, err := c.post(ctx, "/v1/gitlab/k8s/staging/put", body)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		return nil
	default:
		return fmt.Errorf("agent /v1/gitlab/k8s/staging/put returned %d: %s", status, respBody)
	}
}

func (c *agentClient) post(ctx context.Context, path string, body []byte) (int, string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", c.socketPath)
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://cicd-sensor"+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", fmt.Errorf("build %s request: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("post %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(respBody)), nil
}
