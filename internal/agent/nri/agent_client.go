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

// agentPostTimeout must stay well below containerd's per-request NRI plugin
// budget (api.DefaultPluginRequestTimeout, 2s). If the runtime-side timeout
// fires first, containerd treats the plugin as failed and closes its
// connection. The agent is node-local, so a short timeout degrades a slow
// agent to a logged staging miss instead of a plugin disconnect.
const (
	agentPostTimeout = 1 * time.Second
	// The agent listener closes idle connections after 60s. Close client-side
	// idle Unix connections first so sparse CreateContainer traffic opens a
	// fresh connection instead of racing a server-side idle close on POST.
	agentIdleConnTimeout = 30 * time.Second
)

type agentClient struct {
	socketPath string
	provider   jobcontext.Provider
	client     *http.Client
}

func newAgentClient(socketPath string, provider jobcontext.Provider) *agentClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		IdleConnTimeout: agentIdleConnTimeout,
	}
	return &agentClient{
		socketPath: socketPath,
		provider:   provider,
		client: &http.Client{
			Transport: transport,
		},
	}
}

func (c *agentClient) closeIdleConnections() {
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
}

func (c *agentClient) stage(ctx context.Context, decision stagingDecision) error {
	switch c.provider {
	case jobcontext.ProviderGitHub:
		return c.postGitHubStaging(ctx, decision.Basename, decision.Identity)
	case jobcontext.ProviderGitLab:
		return c.postGitLabStaging(ctx, decision.Basename, decision.Identity, decision.Metadata)
	default:
		return fmt.Errorf("unsupported provider %q", c.provider)
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
	if c.client == nil {
		return 0, "", fmt.Errorf("agent client is not initialized")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://cicd-sensor"+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", fmt.Errorf("build %s request: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("post %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(respBody)), nil
}
