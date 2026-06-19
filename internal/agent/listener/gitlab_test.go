package listener

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	jobpkg "github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

func gitlabRegisteredJob(registry *jobregistry.JobRegistry, identity jobcontext.JobIdentity) *jobpkg.Job {
	for _, j := range registry.All() {
		if j.Identity() == identity {
			return j
		}
	}
	return nil
}

func jobIdentityPointer(identity jobcontext.JobIdentity) *jobcontext.JobIdentity {
	return &identity
}

type cacheMissManagerFetcher struct{}

func (cacheMissManagerFetcher) FetchConfig(context.Context, *managerv1beta1.FetchConfigRequest) (*managerclient.FetchResult, error) {
	return nil, managerclient.ErrConfigCacheNotReady
}

func requireLinuxPeerPIDLookup(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("GitLab staging/put always resolves peer PID through Linux cgroup tracking")
	}
}

// /v1/gitlab/host/start

func TestGitLabHostStart_RegistersJob(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, registry, cleanup := setupGitLabListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabHostStartRequest{
		JobIdentity: jobcontext.JobIdentity{
			Provider:     jobcontext.ProviderGitLab,
			ProviderHost: "gitlab.com",
			ProjectPath:  "cicd-sensor/cicd-sensor-testing",
			GitLabJobID:  "14202203981",
		},
	})

	resp, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}

	identity := jobcontext.GitLabJobIdentity("gitlab.com", "cicd-sensor/cicd-sensor-testing", "14202203981")
	if gitlabRegisteredJob(registry, identity) == nil {
		t.Fatal("Job was not registered after host_start")
	}
}

func TestGitLabHostStart_RequiresManager(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListenerWithHostManager(t, nil)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabHostStartRequest{
		JobIdentity: jobcontext.JobIdentity{
			Provider:     jobcontext.ProviderGitLab,
			ProviderHost: "gitlab.com",
			ProjectPath:  "cicd-sensor/cicd-sensor-testing",
			GitLabJobID:  "14202203981",
		},
	})

	resp, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusBadRequest, dump)
	}
}

// Idempotency invariant: a duplicate gitlab host_start must succeed
// silently because the GitLab proxy issues host_start as a lazy create
// after a 404 from staging/put. Concurrent container creates can race
// the lookup, so a 409 here would force the proxy to reason about race
// outcomes — we keep the contract simpler.
func TestGitLabHostStart_DuplicateIsIdempotent(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabHostStartRequest{
		JobIdentity: jobcontext.JobIdentity{
			Provider:     jobcontext.ProviderGitLab,
			ProviderHost: "gitlab.com",
			ProjectPath:  "cicd-sensor/cicd-sensor-testing",
			GitLabJobID:  "14202203981",
		},
	})

	first, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status: got %d, want %d", first.StatusCode, http.StatusOK)
	}

	second, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(second.Body)
		t.Fatalf("second status: got %d, want %d (body=%s)", second.StatusCode, http.StatusOK, dump)
	}
}

func TestGitLabHostStart_RejectsNonGitLabProvider(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabHostStartRequest{
		JobIdentity: jobcontext.JobIdentity{
			Provider:     jobcontext.ProviderGitHub,
			ProviderHost: "github.com",
			ProjectPath:  "acme/repo",
		},
	})

	resp, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestGitLabHostStart_RejectsBadBody(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	cases := []struct {
		name string
		body []byte
	}{
		{name: "not json", body: []byte("not json")},
		{name: "missing identity", body: mustMarshal(t, jobcontext.GitLabHostStartRequest{})},
		{
			name: "missing job id",
			body: mustMarshal(t, jobcontext.GitLabHostStartRequest{
				JobIdentity: jobcontext.JobIdentity{
					Provider:     jobcontext.ProviderGitLab,
					ProviderHost: "gitlab.com",
					ProjectPath:  "g/p",
				},
			}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(tc.body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

func TestGitLabHostStart_WrongUIDForbidden(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED owner gate is enforced only on linux")
	}

	original := agentOwnerUID
	agentOwnerUID = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { agentOwnerUID = original })

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabHostStartRequest{
		JobIdentity: jobcontext.JobIdentity{
			Provider:     jobcontext.ProviderGitLab,
			ProviderHost: "gitlab.com",
			ProjectPath:  "g/p",
			GitLabJobID:  "1",
		},
	})

	resp, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// /v1/gitlab/staging/put

func TestGitLabStagingPut_ReturnsStagedWhenJobExists(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	identity := jobcontext.JobIdentity{
		Provider:     jobcontext.ProviderGitLab,
		ProviderHost: "gitlab.com",
		ProjectPath:  "cicd-sensor/cicd-sensor-testing",
		GitLabJobID:  "14202203981",
	}
	startBody := mustMarshal(t, jobcontext.GitLabHostStartRequest{JobIdentity: identity})
	startResp, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(startBody))
	if err != nil {
		t.Fatalf("host_start request: %v", err)
	}
	startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("host_start status: %d", startResp.StatusCode)
	}

	body := mustMarshal(t, jobcontext.GitLabStagingPutRequest{
		Basename:    "docker-cafef00d.scope",
		JobIdentity: &identity,
	})
	resp, err := client.Post("http://cicd-sensor/v1/gitlab/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}

	var got struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != "staged" {
		t.Fatalf("status: got %q, want %q", got.Status, "staged")
	}
}

func TestGitLabStagingPut_StagesWithPeerPIDWithoutIdentity(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, registry, cleanup := setupGitLabListener(t)
	defer cleanup()

	identity := jobcontext.JobIdentity{
		Provider:     jobcontext.ProviderGitLab,
		ProviderHost: "gitlab.com",
		ProjectPath:  "cicd-sensor/cicd-sensor-testing",
		GitLabJobID:  "14202203981",
	}
	if _, err := registry.ApplyGitHubHostStart(context.Background(), identity, jobcontext.JobMetadata{}, "machine", int32(os.Getpid()), managerclient.Connection{}, staticManagerFetcher{}); err != nil {
		t.Fatalf("seed peer tracking: %v", err)
	}

	body := mustMarshal(t, jobcontext.GitLabStagingPutRequest{
		Basename: "docker-cafef00d.scope",
		PeerPID:  int32(os.Getpid()),
	})
	resp, err := client.Post("http://cicd-sensor/v1/gitlab/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}
	var got struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != "staged" {
		t.Fatalf("status: got %q, want %q", got.Status, "staged")
	}
}

func TestGitLabStagingPut_PeerPIDWinsWhenIdentityAlsoPresent(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, registry, cleanup := setupGitLabListener(t)
	defer cleanup()

	peerIdentity := jobcontext.JobIdentity{
		Provider:     jobcontext.ProviderGitLab,
		ProviderHost: "gitlab.com",
		ProjectPath:  "cicd-sensor/cicd-sensor-testing",
		GitLabJobID:  "14202203981",
	}
	if _, err := registry.ApplyGitHubHostStart(context.Background(), peerIdentity, jobcontext.JobMetadata{}, "machine", int32(os.Getpid()), managerclient.Connection{}, staticManagerFetcher{}); err != nil {
		t.Fatalf("seed peer tracking: %v", err)
	}

	labelsIdentity := jobcontext.JobIdentity{
		Provider:     jobcontext.ProviderGitLab,
		ProviderHost: "gitlab.com",
		ProjectPath:  "other/project",
		GitLabJobID:  "999",
	}
	body := mustMarshal(t, jobcontext.GitLabStagingPutRequest{
		Basename:    "docker-cafef00d.scope",
		PeerPID:     int32(os.Getpid()),
		JobIdentity: &labelsIdentity,
	})
	resp, err := client.Post("http://cicd-sensor/v1/gitlab/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}
	var got struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != "staged" {
		t.Fatalf("status: got %q, want %q", got.Status, "staged")
	}
}

func TestGitLabStagingPut_IgnoresPeerMissWithoutIdentity(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabStagingPutRequest{
		Basename: "docker-cafef00d.scope",
		PeerPID:  1,
	})
	resp, err := client.Post("http://cicd-sensor/v1/gitlab/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}
	var got struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != "ignored" {
		t.Fatalf("status: got %q, want %q", got.Status, "ignored")
	}
}

func TestGitLabStagingPut_CreatesMissingJobAndStages(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, registry, cleanup := setupGitLabListener(t)
	defer cleanup()

	identity := jobcontext.JobIdentity{
		Provider:     jobcontext.ProviderGitLab,
		ProviderHost: "gitlab.com",
		ProjectPath:  "g/p",
		GitLabJobID:  "1",
	}
	body := mustMarshal(t, jobcontext.GitLabStagingPutRequest{
		Basename:    "docker-cafef00d.scope",
		JobIdentity: &identity,
		Metadata:    jobcontext.JobMetadata{CommitSHA: "abc123"},
	})

	resp, err := client.Post("http://cicd-sensor/v1/gitlab/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}
	var got struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != "staged" {
		t.Fatalf("status: got %q, want %q", got.Status, "staged")
	}
	job := gitlabRegisteredJob(registry, identity)
	if job == nil {
		t.Fatal("expected job to be registered")
	}
	if job.HostScope() == nil {
		t.Fatal("expected host scope to be set")
	}
	if job.Metadata().CommitSHA != "abc123" {
		t.Fatalf("metadata commit_sha: got %q, want abc123", job.Metadata().CommitSHA)
	}
}

func TestGitLabStagingPut_RejectsBadBody(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	cases := []struct {
		name string
		body []byte
	}{
		{name: "not json", body: []byte("not json")},
		{name: "missing basename", body: mustMarshal(t, jobcontext.GitLabStagingPutRequest{
			JobIdentity: jobIdentityPointer(jobcontext.JobIdentity{
				Provider:     jobcontext.ProviderGitLab,
				ProviderHost: "gitlab.com",
				ProjectPath:  "g/p",
				GitLabJobID:  "1",
			}),
		})},
		{name: "non-gitlab provider", body: mustMarshal(t, jobcontext.GitLabStagingPutRequest{
			Basename: "docker-cafef00d.scope",
			JobIdentity: jobIdentityPointer(jobcontext.JobIdentity{
				Provider:     jobcontext.ProviderGitHub,
				ProviderHost: "github.com",
				ProjectPath:  "acme/repo",
			}),
		})},
		{name: "missing job id", body: mustMarshal(t, jobcontext.GitLabStagingPutRequest{
			Basename: "docker-cafef00d.scope",
			JobIdentity: jobIdentityPointer(jobcontext.JobIdentity{
				Provider:     jobcontext.ProviderGitLab,
				ProviderHost: "gitlab.com",
				ProjectPath:  "g/p",
			}),
		})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Post("http://cicd-sensor/v1/gitlab/staging/put", "application/json", bytes.NewReader(tc.body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

// Concurrent explicit host starts for one GitLab Job must serialize so no
// caller can observe a Job that has been published to the registry but not yet
// had its host scope attached.
func TestGitLabHostStart_ConcurrentStarts(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, registry, cleanup := setupGitLabListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabHostStartRequest{
		JobIdentity: jobcontext.JobIdentity{
			Provider:     jobcontext.ProviderGitLab,
			ProviderHost: "gitlab.com",
			ProjectPath:  "cicd-sensor/cicd-sensor-testing",
			GitLabJobID:  "14202203981",
		},
	})

	const goroutines = 16
	var wg sync.WaitGroup
	statuses := make([]int, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			resp, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Errorf("goroutine %d: %v", idx, err)
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			statuses[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	for i, s := range statuses {
		if s != http.StatusOK {
			t.Errorf("goroutine %d: status %d, want %d", i, s, http.StatusOK)
		}
	}

	identity := jobcontext.GitLabJobIdentity("gitlab.com", "cicd-sensor/cicd-sensor-testing", "14202203981")
	j := gitlabRegisteredJob(registry, identity)
	if j == nil {
		t.Fatal("Job was not registered after concurrent host_starts")
	}
	if j.HostScope() == nil {
		t.Fatal("Job HostScope is nil — serialisation invariant broken (Job published before host scope attached)")
	}
}

// Provider boundary: a GitLab-configured listener must not surface the
// GitHub identity contract. The route family is selected at construction
// time, so /v1/github/* is plain 404 (default mux behaviour).
func TestListener_GitLabProvider_RejectsGitHubRoutes(t *testing.T) {
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	cases := []string{
		"http://cicd-sensor/v1/github/job/health",
		"http://cicd-sensor/v1/github/host/start",
		"http://cicd-sensor/v1/github/host/end",
		"http://cicd-sensor/v1/github/project/start",
		"http://cicd-sensor/v1/github/project/result",
		"http://cicd-sensor/v1/github/staging/put",
		"http://cicd-sensor/v1/github/k8s/staging/put",
	}
	for _, url := range cases {
		t.Run(url, func(t *testing.T) {
			resp, err := client.Post(url, "application/json", bytes.NewReader([]byte("{}")))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusNotFound)
			}
		})
	}
}

func TestGitLabStagingPut_WrongUIDForbidden(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED owner gate is enforced only on linux")
	}

	original := agentOwnerUID
	agentOwnerUID = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { agentOwnerUID = original })

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabStagingPutRequest{
		Basename: "docker-cafef00d.scope",
		JobIdentity: jobIdentityPointer(jobcontext.JobIdentity{
			Provider:     jobcontext.ProviderGitLab,
			ProviderHost: "gitlab.com",
			ProjectPath:  "g/p",
			GitLabJobID:  "1",
		}),
	})
	resp, err := client.Post("http://cicd-sensor/v1/gitlab/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestGitLabK8sStagingPut_StagesWhenJobExists(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, registry, cleanup := setupGitLabListener(t)
	defer cleanup()

	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	startBody := mustMarshal(t, jobcontext.GitLabHostStartRequest{
		JobIdentity: identity,
		Metadata:    jobcontext.JobMetadata{CommitSHA: "abc123"},
	})
	startResp, err := client.Post("http://cicd-sensor/v1/gitlab/host/start", "application/json", bytes.NewReader(startBody))
	if err != nil {
		t.Fatalf("host_start request: %v", err)
	}
	startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("host_start status: %d", startResp.StatusCode)
	}

	body := mustMarshal(t, jobcontext.GitLabK8sStagingPutRequest{
		Basename:    "cri-containerd-build.scope",
		JobIdentity: identity,
	})
	resp, err := client.Post("http://cicd-sensor/v1/gitlab/k8s/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}
	job := gitlabRegisteredJob(registry, identity)
	if job == nil {
		t.Fatal("expected job to be registered")
	}
	if job.HostScope() == nil {
		t.Fatal("expected host scope to be set")
	}
	if job.Metadata().CommitSHA != "abc123" {
		t.Fatalf("metadata commit_sha: got %q, want abc123", job.Metadata().CommitSHA)
	}
}

func TestGitLabK8sStagingPut_CreatesMissingJobAndStages(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, registry, cleanup := setupGitLabListener(t)
	defer cleanup()

	identity := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123")
	body := mustMarshal(t, jobcontext.GitLabK8sStagingPutRequest{
		Basename:    "cri-containerd-build.scope",
		JobIdentity: identity,
		Metadata:    jobcontext.JobMetadata{CommitSHA: "abc123"},
	})
	resp, err := client.Post("http://cicd-sensor/v1/gitlab/k8s/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusOK, dump)
	}
	job := gitlabRegisteredJob(registry, identity)
	if job == nil {
		t.Fatal("expected job to be registered")
	}
	if job.HostScope() == nil {
		t.Fatal("expected host scope to be set")
	}
	if job.Metadata().CommitSHA != "abc123" {
		t.Fatalf("metadata commit_sha: got %q, want abc123", job.Metadata().CommitSHA)
	}
}

func TestGitLabK8sStagingPut_ReturnsUnavailableWhenHostConfigCacheMissing(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListenerWithHostManager(t, cacheMissManagerFetcher{})
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabK8sStagingPutRequest{
		Basename:    "cri-containerd-build.scope",
		JobIdentity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "123"),
	})
	resp, err := client.Post("http://cicd-sensor/v1/gitlab/k8s/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusServiceUnavailable, dump)
	}
	dump, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(dump, []byte(managerclient.ErrConfigCacheNotReady.Error())) {
		t.Fatalf("body should contain cache error, got %s", dump)
	}
}

func TestGitLabK8sStagingPut_RejectsNonGitLabIdentity(t *testing.T) {
	requireLinuxPeerPIDLookup(t)
	matchAgentOwnerUIDToPeerCred(t)

	client, _, cleanup := setupGitLabListener(t)
	defer cleanup()

	body := mustMarshal(t, jobcontext.GitLabK8sStagingPutRequest{
		Basename:    "cri-containerd-build.scope",
		JobIdentity: jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
	})
	resp, err := client.Post("http://cicd-sensor/v1/gitlab/k8s/staging/put", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusBadRequest, dump)
	}
}

// setupGitLabListener wires a Listener configured for the GitLab
// provider with a real KernelTracker. Mirrors setupGitHubStagingListener
// but with provider=gitlab so JobRegistry-side scope code that branches
// on identity provider exercises the GitLab path.
func setupGitLabListener(t *testing.T) (*http.Client, *jobregistry.JobRegistry, func()) {
	t.Helper()
	return setupGitLabListenerWithHostManager(t, staticManagerFetcher{})
}

func setupGitLabListenerWithHostManager(t *testing.T, hostManagerClient jobregistry.ManagerConfigFetcher) (*http.Client, *jobregistry.JobRegistry, func()) {
	t.Helper()

	dir := newTestSocketDir(t, "cicd-sensor-gitlab-test-")
	t.Cleanup(func() { os.RemoveAll(dir) })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := jobregistry.New(logger)

	engine, err := kerneltracker.New(logger, registry)
	if err != nil {
		t.Skipf("kernel tracker unavailable: %v", err)
	}
	registry.BindKernelTracker(engine)
	engineCtx, engineCancel := context.WithCancel(context.Background())
	engineDone := make(chan error, 1)
	go func() { engineDone <- engine.Run(engineCtx) }()

	sock := filepath.Join(dir, "t.sock")
	l := New(Config{
		Logger:                logger,
		JobRegistry:           registry,
		SocketPath:            sock,
		HostManagerConnection: managerclient.Connection{},
		HostManagerClient:     hostManagerClient,
		RunnerType:            "machine",
		Provider:              jobcontext.ProviderGitLab,
	})

	listenerCtx, listenerCancel := context.WithCancel(context.Background())
	listenerErrCh := make(chan error, 1)
	go func() { listenerErrCh <- l.Serve(listenerCtx) }()

	deadline := time.After(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case err := <-listenerErrCh:
			skipIfListenPermissionDenied(t, err)
			t.Fatalf("listener failed to start: %v", err)
		case <-deadline:
			t.Fatal("gitlab listener socket did not appear within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}

	cleanup := func() {
		listenerCancel()
		<-listenerErrCh
		_ = engine.Close()
		engineCancel()
		<-engineDone
	}
	return client, registry, cleanup
}
