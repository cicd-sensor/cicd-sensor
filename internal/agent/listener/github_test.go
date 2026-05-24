package listener_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/joblogs"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func TestListener_HostStart_SetsHostScope(t *testing.T) {
	client, registry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_tracking_host_scope",
		"metadata": map[string]string{
			"commit_sha":          "abc123",
			"ref_name":            "main",
			"trigger":             "push",
			"actor_name":          "alice",
			"github_workflow":     "build",
			"github_workflow_ref": "acme/example/.github/workflows/build.yml@refs/heads/main",
			"github_workflow_sha": "def456",
		},
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "github_tracking_host_scope")
	job := listenerRegisteredJob(registry, id)
	if job == nil {
		t.Fatal("expected job to be registered")
	}
	if job.HostScope() == nil {
		t.Fatal("expected host scope to be set")
	}
	// The listener stamps its agent-process-wide runner type ("machine"
	// in setupListenerWithRegistry) onto the metadata; request body fields
	// no longer carry it.
	if job.RunnerType() != "machine" {
		t.Fatalf("job runner_type: got %q, want %q", job.RunnerType(), "machine")
	}
	if job.Metadata().CommitSHA != "abc123" {
		t.Fatalf("job metadata commit_sha: got %q, want abc123", job.Metadata().CommitSHA)
	}
	if job.Metadata().GitHubWorkflowRef != "acme/example/.github/workflows/build.yml@refs/heads/main" {
		t.Fatalf("job metadata github_workflow_ref: got %q", job.Metadata().GitHubWorkflowRef)
	}
}

func TestListener_HostStartThenProjectStart_SetsBothScopes(t *testing.T) {
	client, registry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_tracking_both_scopes",
	})

	resp1, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("host/start request: %v", err)
	}
	resp1.Body.Close()

	resp2, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("project/start request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp2.StatusCode, http.StatusOK)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "github_tracking_both_scopes")
	job := listenerRegisteredJob(registry, id)
	if job == nil {
		t.Fatal("expected job to be registered")
	}
	if job.HostScope() == nil {
		t.Fatal("expected host scope to be set")
	}
	if job.ProjectScope() == nil {
		t.Fatal("expected project scope to be set")
	}
}

func TestListener_HostStart_StartsJob(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "555",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "host_tracking",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("status: got %q, want %q", result.Status, "ok")
	}
}

func TestListener_HostStart_RequiresManager(t *testing.T) {
	client, _, _, cleanup := setupListenerWithRegistryAndRootForProviderWithHostManager(t, jobcontext.ProviderGitHub, nil)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "556",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "host_without_manager",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, http.StatusBadRequest, dump)
	}
}

func TestListener_HostStartThenProjectStart_ReturnsExisting(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "666",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "host_then_job",
	})

	// Step 1: host/start starts the job.
	resp1, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("host/start: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("host/start status: %d", resp1.StatusCode)
	}

	// Step 2: project/start returns the same job (not conflict).
	resp2, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("project/start: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("project/start status: got %d, want %d", resp2.StatusCode, http.StatusOK)
	}

	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("status: got %q, want %q", result.Status, "ok")
	}
}

func TestListener_HostStart_DuplicateReturnsConflict(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "777",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "dup_host",
	})

	resp1, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	resp1.Body.Close()

	resp2, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("status: got %d, want %d", resp2.StatusCode, http.StatusConflict)
	}
}

func TestListener_HostStart_RejectsProjectOnlyDefaultMaxAlertsField(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                    "github",
		"provider_host":               "github.com",
		"project_path":                "acme/example",
		"github_run_id":               "777",
		"github_job":                  "build",
		"github_run_attempt":          "1",
		"github_runner_tracking_id":   "dup_host",
		"default_max_alerts_per_rule": 7,
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListener_HostEnd_FinalizesHostJob(t *testing.T) {
	client, registry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "778",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "host_end",
	})
	startResp, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("host/start: %v", err)
	}
	startResp.Body.Close()

	endResp, err := client.Post("http://cicd-sensor/v1/github/host/end", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("host/end: %v", err)
	}
	defer endResp.Body.Close()
	if endResp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", endResp.StatusCode, http.StatusOK)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "778", "build", "1", "host_end")
	if job := listenerRegisteredJob(registry, id); job != nil {
		t.Fatalf("expected job to be finalized and removed, got %#v", job)
	}
}

func TestListener_JobHealth_ReturnsScopeStatusForHostJob(t *testing.T) {
	client, registry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "781",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "host_health",
	})
	startResp, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("host/start: %v", err)
	}
	startResp.Body.Close()

	resp, err := client.Post("http://cicd-sensor/v1/github/job/health", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("job/health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var result struct {
		Host    map[string]string `json:"host"`
		Project map[string]string `json:"project"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Host["status"] != "active" {
		t.Fatalf("host status: got %q, want active", result.Host["status"])
	}
	if result.Project["status"] != "missing" {
		t.Fatalf("project status: got %q, want missing", result.Project["status"])
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "781", "build", "1", "host_health")
	if job := listenerRegisteredJob(registry, id); job == nil {
		t.Fatal("job health must not remove the job")
	}
}

func TestListener_JobHealth_ReturnsScopeStatusForProjectOnlyJob(t *testing.T) {
	client, registry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "782",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "project_only_host_health",
	})
	startResp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("project/start: %v", err)
	}
	startResp.Body.Close()

	resp, err := client.Post("http://cicd-sensor/v1/github/job/health", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("job/health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var result struct {
		Host    map[string]string `json:"host"`
		Project map[string]string `json:"project"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Host["status"] != "missing" {
		t.Fatalf("host status: got %q, want missing", result.Host["status"])
	}
	if result.Project["status"] != "active" {
		t.Fatalf("project status: got %q, want active", result.Project["status"])
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "782", "build", "1", "project_only_host_health")
	if job := listenerRegisteredJob(registry, id); job == nil {
		t.Fatal("project-only job should remain registered")
	}
}

func TestListener_JobHealth_ReturnsScopeStatusForHostAndProjectJob(t *testing.T) {
	client, registry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "784",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "host_project_job_health",
	})
	hostResp, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("host/start: %v", err)
	}
	hostResp.Body.Close()
	projectResp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("project/start: %v", err)
	}
	projectResp.Body.Close()

	resp, err := client.Post("http://cicd-sensor/v1/github/job/health", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("job/health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var result struct {
		Host    map[string]string `json:"host"`
		Project map[string]string `json:"project"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Host["status"] != "active" || result.Project["status"] != "active" {
		t.Fatalf("scope status: got host=%q project=%q, want both active", result.Host["status"], result.Project["status"])
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "784", "build", "1", "host_project_job_health")
	if job := listenerRegisteredJob(registry, id); job == nil {
		t.Fatal("job health must not remove the job")
	}
}

func TestListener_JobHealth_MissingJobReturnsNotFound(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "783",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "missing_host_health",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/job/health", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("job/health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestListener_HostEnd_ProjectOnlyJobReturnsConflict(t *testing.T) {
	client, registry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "779",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "project_only_host_end",
	})
	startResp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("project/start: %v", err)
	}
	startResp.Body.Close()

	endResp, err := client.Post("http://cicd-sensor/v1/github/host/end", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("host/end: %v", err)
	}
	defer endResp.Body.Close()
	if endResp.StatusCode != http.StatusConflict {
		t.Fatalf("status: got %d, want %d", endResp.StatusCode, http.StatusConflict)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "779", "build", "1", "project_only_host_end")
	if job := listenerRegisteredJob(registry, id); job == nil {
		t.Fatal("project-only job should remain registered")
	}
}

func TestListener_HostEnd_MissingJobIsIdempotent(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "780",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "missing_host_end",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/host/end", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("host/end: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestListener_GitHubIdentityRoutes_RejectBadIdentityRequest(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	validGitHubIdentity := map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "tracking",
	}
	wrongProvider := map[string]string{
		"provider":      "gitlab",
		"provider_host": "gitlab.com",
		"project_path":  "acme/example",
		"gitlab_job_id": "123",
	}
	missingRequired := map[string]string{
		"provider":      "github",
		"provider_host": "github.com",
		"project_path":  "acme/example",
	}

	cases := []struct {
		name string
		path string
		body []byte
	}{
		{name: "job health invalid json", path: "/v1/github/job/health", body: []byte("not json")},
		{name: "job health wrong provider", path: "/v1/github/job/health", body: mustJSON(t, wrongProvider)},
		{name: "job health missing required identity", path: "/v1/github/job/health", body: mustJSON(t, missingRequired)},
		{name: "host end invalid json", path: "/v1/github/host/end", body: []byte("not json")},
		{name: "host end wrong provider", path: "/v1/github/host/end", body: mustJSON(t, wrongProvider)},
		{name: "host end missing required identity", path: "/v1/github/host/end", body: mustJSON(t, missingRequired)},
		{name: "project result invalid json", path: "/v1/github/project/result", body: []byte("not json")},
		{name: "project result wrong provider", path: "/v1/github/project/result", body: mustJSON(t, wrongProvider)},
		{name: "project result missing required identity", path: "/v1/github/project/result", body: mustJSON(t, missingRequired)},
		{name: "job health valid identity but missing job", path: "/v1/github/job/health", body: mustJSON(t, validGitHubIdentity)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Post("http://cicd-sensor"+tc.path, "application/json", bytes.NewReader(tc.body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()

			want := http.StatusBadRequest
			if tc.name == "job health valid identity but missing job" {
				want = http.StatusNotFound
			}
			if resp.StatusCode != want {
				dump, _ := io.ReadAll(resp.Body)
				t.Fatalf("status: got %d, want %d (body=%s)", resp.StatusCode, want, dump)
			}
		})
	}
}

func TestListener_ProjectStart_GitHub(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123456789",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_tracking_alpha",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result struct {
		JobIdentity jobcontext.JobIdentity `json:"job_identity"`
		Status      string                 `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantIdentity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123456789", "build", "1", "github_tracking_alpha")
	if result.JobIdentity != wantIdentity {
		t.Errorf("job_identity: got %+v, want %+v", result.JobIdentity, wantIdentity)
	}
}

func TestListener_ProjectStart_SeedsProjectDefaultMaxAlerts(t *testing.T) {
	client, jobRegistry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                    "github",
		"provider_host":               "github.com",
		"project_path":                "acme/example",
		"github_run_id":               "123456789",
		"github_job":                  "build",
		"github_run_attempt":          "1",
		"github_runner_tracking_id":   "github_tracking_alpha",
		"default_max_alerts_per_rule": 7,
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123456789", "build", "1", "github_tracking_alpha")
	job := listenerRegisteredJob(jobRegistry, id)
	if job == nil || job.ProjectScope() == nil {
		t.Fatal("expected project scope to be created")
	}
	if got := job.ProjectScope().DefaultMaxAlertsPerRule; got != 7 {
		t.Fatalf("project default_max_alerts_per_rule: got %d, want 7", got)
	}
}

func TestListener_ProjectStart_AcceptsProjectRules(t *testing.T) {
	client, jobRegistry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123456789",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_tracking_rules",
		"rule_sources": []rulesource.LoadedRules{{
			RuleSets: []rule.RuleSet{{
				RulesetID: "project",
				Rules: []rule.Rule{{
					RuleID:    "project_exec",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				}},
			}},
		}},
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123456789", "build", "1", "github_tracking_rules")
	job := listenerRegisteredJob(jobRegistry, id)
	if job == nil || job.ProjectScope() == nil {
		t.Fatal("expected project scope to be created")
	}
	if got := len(job.ProjectScope().RuleSets); got != 1 {
		t.Fatalf("project scope rule_sets: got %d, want 1", got)
	}
	if got := len(job.ProjectScope().ResolvedRules.Rules); got != 1 {
		t.Fatalf("resolved rules: got %d, want 1", got)
	}
}

func TestListener_ProjectStart_AppliesProjectManagerConfig(t *testing.T) {
	managerBearerToken := managerauth.TokenPrefix + strings.Repeat("a", 64)
	svc := &fakeConfigService{
		handler: func(_ context.Context, req *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
			if req.Msg.RequestedOutputs != nil {
				t.Fatalf("requested outputs: got %+v, want nil", req.Msg.RequestedOutputs)
			}
			sources := mustRuleSources(t, []rule.RuleSet{{
				RulesetID: "project-manager",
				Rules: []rule.Rule{{
					RuleID:    "project-manager-rule",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				}},
			}}, nil)
			return connect.NewResponse(&managerv1.FetchConfigResponse{
				Config: &managerv1.ServedConfig{
					OutputSettings: &managerv1.OutputSettings{
						DetectionLog: &managerv1.OutputSetting{Enabled: true},
					},
				},
				RuleSources: sources,
			}), nil
		},
	}
	managerServer := newFakeConfigServer(t, svc)
	defer managerServer.Close()

	client, jobRegistry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123456789",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_tracking_manager",
		"manager_url":               managerServer.URL,
		"manager_token":             managerBearerToken,
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123456789", "build", "1", "github_tracking_manager")
	job := listenerRegisteredJob(jobRegistry, id)
	if job == nil || job.ProjectScope() == nil {
		t.Fatal("expected project scope to be created")
	}
	if got := len(job.ProjectScope().ResolvedRules.Rules); got != 1 {
		t.Fatalf("project manager rules: got %d, want 1", got)
	}
	if !job.ProjectScope().OutputSettings.GetDetectionLog().GetEnabled() {
		t.Fatal("project output detection: got false, want true")
	}
	if job.HostScope() != nil {
		t.Fatal("project manager config unexpectedly created host scope")
	}
}

func TestListener_ProjectStart_ManagerModeIgnoresLocalDefaultMaxAlerts(t *testing.T) {
	managerBearerToken := managerauth.TokenPrefix + strings.Repeat("a", 64)
	svc := &fakeConfigService{
		handler: func(context.Context, *connect.Request[managerv1.FetchConfigRequest]) (*connect.Response[managerv1.FetchConfigResponse], error) {
			return connect.NewResponse(&managerv1.FetchConfigResponse{
				Config: &managerv1.ServedConfig{
					DefaultMaxAlertsPerRule: 31,
				},
			}), nil
		},
	}
	managerServer := newFakeConfigServer(t, svc)
	defer managerServer.Close()

	client, jobRegistry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                    "github",
		"provider_host":               "github.com",
		"project_path":                "acme/example",
		"github_run_id":               "123456789",
		"github_job":                  "build",
		"github_run_attempt":          "1",
		"github_runner_tracking_id":   "github_tracking_manager_default",
		"manager_url":                 managerServer.URL,
		"manager_token":               managerBearerToken,
		"default_max_alerts_per_rule": -1,
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123456789", "build", "1", "github_tracking_manager_default")
	job := listenerRegisteredJob(jobRegistry, id)
	if job == nil || job.ProjectScope() == nil {
		t.Fatal("expected project scope to be created")
	}
	if got := job.ProjectScope().DefaultMaxAlertsPerRule; got != 31 {
		t.Fatalf("project default_max_alerts_per_rule: got %d, want 31", got)
	}
}

func TestListener_ProjectStart_RejectsProjectManagerWithoutToken(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123456789",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_tracking_missing_token",
		"manager_url":               "https://project-manager.example.com",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListener_ProjectStart_RejectsNegativeDefaultMaxAlerts(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                    "github",
		"provider_host":               "github.com",
		"project_path":                "acme/example",
		"github_run_id":               "123456789",
		"github_job":                  "build",
		"github_run_attempt":          "1",
		"github_runner_tracking_id":   "github_tracking_negative_cap",
		"default_max_alerts_per_rule": -1,
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var result struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error != "default_max_alerts_per_rule must be non-negative" {
		t.Fatalf("error: got %q, want %q", result.Error, "default_max_alerts_per_rule must be non-negative")
	}
}

func TestListener_ProjectStart_RejectsInvalidProjectRules(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123456789",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_tracking_bad_rules",
		"rule_sources": []rulesource.LoadedRules{{
			RuleSets: []rule.RuleSet{{
				Rules: []rule.Rule{{
					RuleID:    "bad",
					EventType: jobevent.ProcessExec,
					Condition: `process_name == "bash"`,
					Action:    rule.RuleActionDetect,
				}},
			}},
		}},
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListener_ProjectStart_RejectsDefaultMaxAlertsAboveCeiling(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                    "github",
		"provider_host":               "github.com",
		"project_path":                "acme/example",
		"github_run_id":               "123456789",
		"github_job":                  "build",
		"github_run_attempt":          "1",
		"github_runner_tracking_id":   "github_tracking_large_cap",
		"default_max_alerts_per_rule": 101,
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var result struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Error != "default_max_alerts_per_rule must be <= 100" {
		t.Fatalf("error: got %q, want %q", result.Error, "default_max_alerts_per_rule must be <= 100")
	}
}

func TestListener_ProjectStart_AcceptsDefaultMaxAlertsAtCeiling(t *testing.T) {
	client, jobRegistry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]any{
		"provider":                    "github",
		"provider_host":               "github.com",
		"project_path":                "acme/example",
		"github_run_id":               "123456789",
		"github_job":                  "build",
		"github_run_attempt":          "1",
		"github_runner_tracking_id":   "github_tracking_ceiling_cap",
		"default_max_alerts_per_rule": 100,
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123456789", "build", "1", "github_tracking_ceiling_cap")
	job := listenerRegisteredJob(jobRegistry, id)
	if job == nil || job.ProjectScope() == nil {
		t.Fatal("expected project scope to be created")
	}
	if got := job.ProjectScope().DefaultMaxAlertsPerRule; got != 100 {
		t.Fatalf("project default_max_alerts_per_rule: got %d, want 100", got)
	}
}

func TestListener_ProjectStart_MissingFields(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider": "github",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListener_ProjectStart_GitHubMissingRunnerTrackingID(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":           "github",
		"provider_host":      "github.com",
		"project_path":       "acme/example",
		"github_run_id":      "123",
		"github_job":         "build",
		"github_run_attempt": "1",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d (runner_tracking_id is required)", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListener_ProjectStart_DuplicateReactivatesExisting(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_tracking_dup",
	})

	resp1, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp1.Body.Close()

	// Second project/start on the same identity is rejected at the registry boundary.
	resp2, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("status: got %d, want %d", resp2.StatusCode, http.StatusConflict)
	}
}

func TestListener_ProjectStart_InvalidJSON(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListener_ProjectStart_RejectsTrailingJSON(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body := []byte(`{"provider":"github"}{"provider":"github"}`)
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["error"] != "invalid request body" {
		t.Fatalf("error: got %q, want invalid request body", got["error"])
	}
}

func TestListener_ProjectStart_RejectsUnknownFields(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "runner-1",
		"unexpected":                "field",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListener_ProjectStart_GitHubRunnerTrackingIDVariants(t *testing.T) {
	cases := []struct {
		name             string
		runnerTrackingID string
	}{
		{
			name:             "short opaque value is accepted",
			runnerTrackingID: "deadbeef",
		},
		{
			name:             "prefixed UUID value is accepted",
			runnerTrackingID: "github_4180ef41-9a26-45fc-8e46-9baa6831819f",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, cleanup := setupListener(t)
			defer cleanup()

			body, _ := json.Marshal(map[string]string{
				"provider":                  "github",
				"provider_host":             "github.com",
				"project_path":              "acme/example",
				"github_run_id":             "999",
				"github_job":                "build",
				"github_run_attempt":        "1",
				"github_runner_tracking_id": tc.runnerTrackingID,
			})
			resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
			}

			var result struct {
				JobIdentity jobcontext.JobIdentity `json:"job_identity"`
				Status      string                 `json:"status"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatalf("decode: %v", err)
			}
			wantIdentity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "999", "build", "1", tc.runnerTrackingID)
			if result.JobIdentity != wantIdentity {
				t.Errorf("job_identity: got %+v, want %+v", result.JobIdentity, wantIdentity)
			}
		})
	}
}

func TestListener_ProjectStart_SetsProjectScope(t *testing.T) {
	client, registry, cleanup := setupListenerWithRegistry(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "123",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "github_tracking_project_scope",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "github_tracking_project_scope")
	job := listenerRegisteredJob(registry, id)
	if job == nil {
		t.Fatal("expected job to be registered")
	}
	if job.ProjectScope() == nil {
		t.Fatal("expected project scope to be set")
	}
}

func TestListener_ProjectStart_UnsupportedProvider(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":      "bitbucket",
		"provider_host": "bitbucket.org",
		"project_path":  "acme/example",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestListener_ProjectResult_ReturnsContent(t *testing.T) {
	client, registry, _, cleanup := setupListenerWithRegistryAndRoot(t)
	defer cleanup()

	startBody, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "888",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "result_test",
	})
	startResp, err := client.Post("http://cicd-sensor/v1/github/project/start", "application/json", bytes.NewReader(startBody))
	if err != nil {
		t.Fatalf("project/start: %v", err)
	}
	startResp.Body.Close()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "888", "build", "1", "result_test")
	job := listenerRegisteredJob(registry, id)
	if job == nil || job.ProjectScope() == nil {
		t.Fatal("project job not registered")
	}
	debugDir := t.TempDir()
	debugOutput, err := joblogs.NewDebugOutputForTesting(testLogger, debugDir)
	if err != nil {
		t.Fatalf("NewDebugOutputForTesting: %v", err)
	}
	job.ProjectScope().SetDebugOutput(debugOutput)
	job.ProjectScope().WriteRuntimeEventLog(context.Background(), id, jobcontext.JobMetadata{}, "machine", jobevent.EventRecord{
		ID:        "listener-project-result-debug",
		EventType: jobevent.NetworkConnect,
		Process: jobevent.ProcessSummary{
			PID:      100,
			ExecPath: "/usr/bin/curl",
		},
		Payload: map[string]any{
			"remote_ip":   "203.0.113.20",
			"remote_port": int64(443),
			"protocol":    "tcp",
		},
	}, testLogger)

	resultBody, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "888",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "result_test",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/result", "application/json", bytes.NewReader(resultBody))
	if err != nil {
		t.Fatalf("project/result: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got resultdoc.JobEventSummaryForReport
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.JobIdentity.ProjectPath != "acme/example" {
		t.Fatalf("project: got %q, want acme/example", got.JobIdentity.ProjectPath)
	}
	if got.ResultSummary.Result != resultdoc.ResultNoAlert {
		t.Fatalf("result_summary.result: got %q, want %s", got.ResultSummary.Result, resultdoc.ResultNoAlert)
	}
	if body := readListenerDebugGzip(t, debugDir); !strings.Contains(body, "listener-project-result-debug") {
		t.Fatalf("debug gzip not closed/readable after project result response: %s", body)
	}
}

func TestListener_ProjectResult_NotFoundIfJobMissing(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "999999",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "missing_job",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/project/result", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestListener_ProjectResult_ProjectScopeMissingReturnsConflict(t *testing.T) {
	client, cleanup := setupListener(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "888888",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "host_only",
	})
	resp, err := client.Post("http://cicd-sensor/v1/github/host/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("host/start: %v", err)
	}
	resp.Body.Close()

	resultReqBody, _ := json.Marshal(map[string]string{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              "acme/example",
		"github_run_id":             "888888",
		"github_job":                "build",
		"github_run_attempt":        "1",
		"github_runner_tracking_id": "host_only",
	})
	resultResp, err := client.Post("http://cicd-sensor/v1/github/project/result", "application/json", bytes.NewReader(resultReqBody))
	if err != nil {
		t.Fatalf("project/result: %v", err)
	}
	defer resultResp.Body.Close()

	if resultResp.StatusCode != http.StatusConflict {
		t.Fatalf("status: got %d, want %d", resultResp.StatusCode, http.StatusConflict)
	}
}

func readListenerDebugGzip(t *testing.T, debugDir string) string {
	t.Helper()

	file, err := os.Open(filepath.Join(debugDir, joblogs.DebugRuntimeEventLogFilename))
	if err != nil {
		t.Fatalf("open debug gzip: %v", err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close gzip reader: %v", err)
	}
	return string(body)
}
