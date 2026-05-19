package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestBuildJobIdentityRequest(t *testing.T) {
	tests := []struct {
		name        string
		identity    jobIdentityFlags
		want        map[string]string
		wantErrText string
	}{
		{
			name:     "github identity",
			identity: githubIdentity(),
			want: map[string]string{
				"provider":                  "github",
				"provider_host":             "github.com",
				"project_path":              "acme/example",
				"github_run_id":             "123",
				"github_run_attempt":        "2",
				"github_job":                "build",
				"github_runner_tracking_id": "runner-1",
			},
		},
		{
			name:     "gitlab identity",
			identity: gitlabIdentity(),
			want: map[string]string{
				"provider":      "gitlab",
				"provider_host": "gitlab.example.com",
				"project_path":  "group/project",
				"gitlab_job_id": "789",
			},
		},
		{
			name:        "missing platform",
			identity:    jobIdentityFlags{},
			wantErrText: "provider is required",
		},
		{
			name: "unsupported provider",
			identity: jobIdentityFlags{
				Provider:     "circle",
				ProviderHost: "ci.example.com",
				ProjectPath:  "acme/example",
			},
			wantErrText: "provider must be github or gitlab",
		},
		{
			name: "missing provider host",
			identity: jobIdentityFlags{
				Provider:    "github",
				ProjectPath: "acme/example",
			},
			wantErrText: "provider-host is required",
		},
		{
			name: "missing project path",
			identity: jobIdentityFlags{
				Provider:     "github",
				ProviderHost: "github.com",
			},
			wantErrText: "project-path is required",
		},
		{
			name: "missing github run id",
			identity: jobIdentityFlags{
				Provider:               "github",
				ProviderHost:           "github.com",
				ProjectPath:            "acme/example",
				GitHubRunAttempt:       "2",
				GitHubJob:              "build",
				GitHubRunnerTrackingID: "runner-1",
			},
			wantErrText: "github-run-id is required",
		},
		{
			name: "missing github run attempt",
			identity: jobIdentityFlags{
				Provider:               "github",
				ProviderHost:           "github.com",
				ProjectPath:            "acme/example",
				GitHubRunID:            "123",
				GitHubJob:              "build",
				GitHubRunnerTrackingID: "runner-1",
			},
			wantErrText: "github-run-attempt is required",
		},
		{
			name: "missing github job",
			identity: jobIdentityFlags{
				Provider:               "github",
				ProviderHost:           "github.com",
				ProjectPath:            "acme/example",
				GitHubRunID:            "123",
				GitHubRunAttempt:       "2",
				GitHubRunnerTrackingID: "runner-1",
			},
			wantErrText: "github-job is required",
		},
		{
			name: "missing github runner tracking id",
			identity: jobIdentityFlags{
				Provider:         "github",
				ProviderHost:     "github.com",
				ProjectPath:      "acme/example",
				GitHubRunID:      "123",
				GitHubRunAttempt: "2",
				GitHubJob:        "build",
			},
			wantErrText: "github-runner-tracking-id is required",
		},
		{
			name: "missing gitlab job id",
			identity: jobIdentityFlags{
				Provider:     "gitlab",
				ProviderHost: "gitlab.example.com",
				ProjectPath:  "group/project",
			},
			wantErrText: "gitlab-job-id is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildJobIdentityRequest(tc.identity)
			if tc.wantErrText != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Fatalf("error: got %q, want substring %q", err.Error(), tc.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildJobIdentityRequest: %v", err)
			}
			for key, want := range tc.want {
				if got[key] != want {
					t.Fatalf("%s: got %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

func TestRequireGitHubProvider(t *testing.T) {
	if err := requireGitHubProvider(githubIdentity(), "github only"); err != nil {
		t.Fatalf("requireGitHubProvider: %v", err)
	}

	for _, identity := range []jobIdentityFlags{gitlabIdentity(), {}} {
		err := requireGitHubProvider(identity, "github only")
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "github only" {
			t.Fatalf("error: got %q, want github only", err.Error())
		}
	}
}

func TestBuildHostEndRequest(t *testing.T) {
	got, err := buildHostEndRequest(githubIdentity())
	if err != nil {
		t.Fatalf("buildHostEndRequest: %v", err)
	}
	if got["provider"] != "github" {
		t.Fatalf("provider: got %q, want github", got["provider"])
	}
	if got["github_run_id"] != "123" {
		t.Fatalf("github_run_id: got %q, want 123", got["github_run_id"])
	}

	_, err = buildHostEndRequest(jobIdentityFlags{Provider: "github"})
	if err == nil {
		t.Fatal("expected missing identity error")
	}
	if !strings.Contains(err.Error(), "provider-host is required") {
		t.Fatalf("error: got %q", err.Error())
	}
}

func TestBuildHostEndRequestUsesGitHubEnvFallback(t *testing.T) {
	setGitHubIdentityEnv(t)

	identity := jobIdentityFlags{}
	applyGitHubEnvFallback(&identity)
	got, err := buildHostEndRequest(identity)
	if err != nil {
		t.Fatalf("buildHostEndRequest: %v", err)
	}
	want := map[string]string{
		"provider":                  "github",
		"provider_host":             "github.example.com",
		"project_path":              "env/repo",
		"github_run_id":             "456",
		"github_run_attempt":        "3",
		"github_job":                "env-build",
		"github_runner_tracking_id": "env-runner",
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("%s: got %q, want %q", key, got[key], value)
		}
	}
}

func TestBuildJobHealthRequestUsesGitHubEnvFallback(t *testing.T) {
	setGitHubIdentityEnv(t)

	identity := jobIdentityFlags{}
	applyGitHubEnvFallback(&identity)
	got, err := buildJobHealthRequest(identity)
	if err != nil {
		t.Fatalf("buildJobHealthRequest: %v", err)
	}
	want := map[string]string{
		"provider":                  "github",
		"provider_host":             "github.example.com",
		"project_path":              "env/repo",
		"github_run_id":             "456",
		"github_run_attempt":        "3",
		"github_job":                "env-build",
		"github_runner_tracking_id": "env-runner",
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("%s: got %q, want %q", key, got[key], value)
		}
	}
}

func TestBuildHostStartMetadataUsesGitHubEnvFallback(t *testing.T) {
	setGitHubMetadataEnv(t)

	metadata := jobMetadataFlags{}
	applyGitHubMetadataEnvFallback(&metadata)
	got := buildJobMetadataRequest(metadata)
	want := map[string]string{
		"commit_sha":   "abc123",
		"branch":       "main",
		"trigger":      "push",
		"workflow":     "ci",
		"workflow_ref": "env/repo/.github/workflows/ci.yml@refs/heads/main",
		"workflow_sha": "def456",
		"actor":        "octocat",
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("%s: got %q, want %q", key, got[key], value)
		}
	}
}

func TestGitHubEnvFallbackDoesNotOverrideFlags(t *testing.T) {
	setGitHubIdentityEnv(t)
	setGitHubMetadataEnv(t)

	identity := githubIdentity()
	metadata := jobMetadataFlags{CommitSHA: "flag-sha"}
	applyGitHubEnvFallback(&identity)
	applyGitHubMetadataEnvFallback(&metadata)
	if identity.ProviderHost != "github.com" {
		t.Fatalf("provider host: got %q, want flag value github.com", identity.ProviderHost)
	}
	if identity.GitHubRunID != "123" {
		t.Fatalf("run id: got %q, want flag value 123", identity.GitHubRunID)
	}
	if metadata.CommitSHA != "flag-sha" {
		t.Fatalf("commit sha: got %q, want flag-sha", metadata.CommitSHA)
	}
}

func TestGitHubLifecycleUsageShowsEnvAsPrimaryInput(t *testing.T) {
	tests := map[string][]string{
		"host start": {"host", "start", "-h"},
		"host end":   {"host", "end", "-h"},
		"job health": {"job", "health", "-h"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			got := runCICDSensorHelp(t, args...)
			for _, want := range []string{
				"GitHub environment (used by default; flags override):",
				"GITHUB_REPOSITORY",
				"GITHUB_RUN_ID",
				"RUNNER_TRACKING_ID",
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("usage missing %q:\n%s", want, got)
				}
			}
			if strings.Contains(got, "Required:") {
				t.Fatalf("usage should not present GitHub identity as required flags:\n%s", got)
			}
		})
	}
}

func runCICDSensorHelp(t *testing.T, args ...string) string {
	t.Helper()
	cmdArgs := append([]string{"-test.run=TestCICDSensorHelpProcess", "--"}, args...)
	cmd := exec.Command(os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), "CICD_SENSOR_HELP_PROCESS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help command %v failed: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestCICDSensorHelpProcess(t *testing.T) {
	if os.Getenv("CICD_SENSOR_HELP_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"cicd-sensor"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestNormalizeProviderHostFromServerURL(t *testing.T) {
	tests := map[string]string{
		"":                                     "github.com",
		"https://GitHub.EXAMPLE.com/org/repo":  "github.example.com",
		"http://github.example.com:8443/path":  "github.example.com",
		"https://github.example.com./org/repo": "github.example.com",
	}
	for input, want := range tests {
		if got := normalizeProviderHostFromServerURL(input); got != want {
			t.Fatalf("%q: got %q, want %q", input, got, want)
		}
	}
}

func TestBuildJobHealthRequest(t *testing.T) {
	got, err := buildJobHealthRequest(githubIdentity())
	if err != nil {
		t.Fatalf("buildJobHealthRequest: %v", err)
	}
	if got["provider"] != "github" {
		t.Fatalf("provider: got %q, want github", got["provider"])
	}
	if got["github_run_id"] != "123" {
		t.Fatalf("github_run_id: got %q, want 123", got["github_run_id"])
	}

	_, err = buildJobHealthRequest(jobIdentityFlags{Provider: "github"})
	if err == nil {
		t.Fatal("expected missing identity error")
	}
	if !strings.Contains(err.Error(), "provider-host is required") {
		t.Fatalf("error: got %q", err.Error())
	}
}

func setGitHubIdentityEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_SERVER_URL", "https://GitHub.EXAMPLE.com/org")
	t.Setenv("GITHUB_REPOSITORY", "env/repo")
	t.Setenv("GITHUB_RUN_ID", "456")
	t.Setenv("GITHUB_RUN_ATTEMPT", "3")
	t.Setenv("GITHUB_JOB", "env-build")
	t.Setenv("RUNNER_TRACKING_ID", "env-runner")
}

func setGitHubMetadataEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_EVENT_NAME", "push")
	t.Setenv("GITHUB_WORKFLOW", "ci")
	t.Setenv("GITHUB_WORKFLOW_REF", "env/repo/.github/workflows/ci.yml@refs/heads/main")
	t.Setenv("GITHUB_WORKFLOW_SHA", "def456")
	t.Setenv("GITHUB_ACTOR", "octocat")
}
