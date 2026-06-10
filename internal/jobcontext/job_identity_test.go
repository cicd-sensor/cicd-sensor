package jobcontext_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestJobIdentity_JSONRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		input jobcontext.JobIdentity
	}{
		{
			name: "github identity",
			input: jobcontext.JobIdentity{
				Provider:               jobcontext.ProviderGitHub,
				ProviderHost:           "github.com",
				ProjectPath:            "acme/example",
				GitHubRunID:            "123456789",
				GitHubJob:              "build",
				GitHubRunAttempt:       "2",
				GitHubRunnerTrackingID: "github_tracking_alpha",
			},
		},
		{
			name: "gitlab identity",
			input: jobcontext.JobIdentity{
				Provider:     jobcontext.ProviderGitLab,
				ProviderHost: "gitlab.com",
				ProjectPath:  "group/project",
				GitLabJobID:  "987654321",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got jobcontext.JobIdentity
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got != tc.input {
				t.Errorf("got %+v, want %+v", got, tc.input)
			}
		})
	}
}

func TestDeriveProviderHost(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr bool
	}{
		{name: "github url", rawURL: "https://github.com", want: "github.com"},
		{name: "lowercases and strips port", rawURL: "https://GitHub.COM:443/owner/repo", want: "github.com"},
		{name: "trims trailing dot", rawURL: "https://gitlab.example.com./", want: "gitlab.example.com"},
		{name: "empty input", rawURL: "", wantErr: true},
		{name: "not a url", rawURL: "not a url", wantErr: true},
		{name: "missing host", rawURL: "https://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jobcontext.DeriveProviderHost(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("DeriveProviderHost(%q): expected error", tt.rawURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("DeriveProviderHost(%q): %v", tt.rawURL, err)
			}
			if got != tt.want {
				t.Fatalf("DeriveProviderHost(%q): got %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestJobIdentity_Validate_RejectsMalformedIDs(t *testing.T) {
	base := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")

	tests := []struct {
		name    string
		mutate  func(*jobcontext.JobIdentity)
		wantErr string
	}{
		{
			name:    "github_run_id non-numeric",
			mutate:  func(id *jobcontext.JobIdentity) { id.GitHubRunID = "abc" },
			wantErr: "github_run_id must be a positive integer",
		},
		{
			name:    "github_run_id zero",
			mutate:  func(id *jobcontext.JobIdentity) { id.GitHubRunID = "0" },
			wantErr: "github_run_id must be a positive integer",
		},
		{
			name:    "github_run_attempt negative-looking",
			mutate:  func(id *jobcontext.JobIdentity) { id.GitHubRunAttempt = "-1" },
			wantErr: "github_run_attempt must be a positive integer",
		},
		{
			name: "github_runner_tracking_id too long",
			mutate: func(id *jobcontext.JobIdentity) {
				id.GitHubRunnerTrackingID = strings.Repeat("x", 129)
			},
			wantErr: "github_runner_tracking_id exceeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := base
			tt.mutate(&id)
			err := id.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error: got %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestJobIdentity_Validate_RejectsMissingCommonFields(t *testing.T) {
	tests := []struct {
		name    string
		input   jobcontext.JobIdentity
		wantErr string
	}{
		{
			name:    "missing provider",
			input:   jobcontext.JobIdentity{ProviderHost: "github.com", ProjectPath: "acme/example"},
			wantErr: "provider is required",
		},
		{
			name:    "missing provider host",
			input:   jobcontext.JobIdentity{Provider: jobcontext.ProviderGitHub, ProjectPath: "acme/example"},
			wantErr: "provider_host is required",
		},
		{
			name:    "missing project path",
			input:   jobcontext.JobIdentity{Provider: jobcontext.ProviderGitHub, ProviderHost: "github.com"},
			wantErr: "project_path is required",
		},
		{
			name:    "unsupported provider",
			input:   jobcontext.JobIdentity{Provider: "bitbucket", ProviderHost: "bitbucket.org", ProjectPath: "acme/example"},
			wantErr: "unsupported provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error: got %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestJobIdentity_Validate_RejectsCrossProviderFields(t *testing.T) {
	tests := []struct {
		name    string
		input   jobcontext.JobIdentity
		wantErr string
	}{
		{
			name: "github identity with gitlab job id",
			input: jobcontext.JobIdentity{
				Provider:               jobcontext.ProviderGitHub,
				ProviderHost:           "github.com",
				ProjectPath:            "acme/example",
				GitHubRunID:            "123",
				GitHubJob:              "build",
				GitHubRunAttempt:       "1",
				GitHubRunnerTrackingID: "runner-1",
				GitLabJobID:            "999",
			},
			wantErr: "gitlab_job_id must be empty for github",
		},
		{
			name: "gitlab identity with github fields",
			input: jobcontext.JobIdentity{
				Provider:     jobcontext.ProviderGitLab,
				ProviderHost: "gitlab.com",
				ProjectPath:  "group/project",
				GitLabJobID:  "999",
				GitHubRunID:  "123",
			},
			wantErr: "github fields must be empty for gitlab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error: got %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestJobIdentity_Validate_RejectsMalformedGitLabID(t *testing.T) {
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "not-a-number")
	err := id.Validate()
	if err == nil || !strings.Contains(err.Error(), "gitlab_job_id must be a positive integer") {
		t.Fatalf("gitlab_job_id non-numeric: got %v", err)
	}
}

func TestJobIdentity_Validate_FieldLengthBounds(t *testing.T) {
	tests := []struct {
		name    string
		input   jobcontext.JobIdentity
		wantErr string
	}{
		{
			name: "project_path accepts 2048 bytes",
			input: jobcontext.GitHubJobIdentity(
				"github.com",
				strings.Repeat("x", 2048),
				"123",
				"build",
				"1",
				"runner-1",
			),
		},
		{
			name: "project_path rejects 2049 bytes",
			input: jobcontext.GitHubJobIdentity(
				"github.com",
				strings.Repeat("x", 2049),
				"123",
				"build",
				"1",
				"runner-1",
			),
			wantErr: "project_path exceeds 2048 bytes",
		},
		{
			name: "github_job rejects 2049 bytes",
			input: jobcontext.GitHubJobIdentity(
				"github.com",
				"acme/example",
				"123",
				strings.Repeat("x", 2049),
				"1",
				"runner-1",
			),
			wantErr: "github_job exceeds 2048 bytes",
		},
		{
			name: "gitlab_job_id rejects 2049 bytes",
			input: jobcontext.GitLabJobIdentity(
				"gitlab.com",
				"group/project",
				strings.Repeat("1", 2049),
			),
			wantErr: "gitlab_job_id exceeds 2048 bytes",
		},
		{
			name: "github_runner_tracking_id keeps shorter bound",
			input: jobcontext.GitHubJobIdentity(
				"github.com",
				"acme/example",
				"123",
				"build",
				"1",
				strings.Repeat("x", 129),
			),
			wantErr: "github_runner_tracking_id exceeds 128 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error: got %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestJobIdentity_FilenameKey(t *testing.T) {
	cases := []struct {
		name     string
		identity jobcontext.JobIdentity
		want     string
		wantErr  bool
	}{
		{
			name: "adds identity hash so sanitized slugs remain collision resistant",
			identity: jobcontext.GitHubJobIdentity(
				"github.com",
				"acme/example",
				"123456789",
				"build/linux",
				"2",
				"github_4180ef41-9a26-45fc-8e46-9baa6831819f",
			),
			want: "github-github-com-acme-example-123456789-build-linux-2-aed182ef-5cd351e382708b45",
		},
		{
			name:     "non ascii project uses hash-only segment",
			identity: jobcontext.GitHubJobIdentity("github.com", "東京/例", "123", "build", "1", "runner-1"),
			want:     "github-github-com-e58bba23-123-build-1-a28bbc96-1a34884defd5f586",
		},
		{
			name:     "exactly 64 byte segment is kept",
			identity: jobcontext.GitLabJobIdentity("gitlab.com", strings.Repeat("x", 64), "123"),
			want:     "gitlab-gitlab-com-" + strings.Repeat("x", 64) + "-123-7c346977b82e7f1d",
		},
		{
			name:     "65 byte segment truncates with hash suffix",
			identity: jobcontext.GitLabJobIdentity("gitlab.com", strings.Repeat("x", 65), "123"),
			want:     "gitlab-gitlab-com-" + strings.Repeat("x", 55) + "-9537c5fd-123-80de950289d6fb4a",
		},
		{
			name:     "long job name truncates compact job ref with hash of original",
			identity: jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build/"+strings.Repeat("x", 70), "1", "runner-1"),
			want:     "github-github-com-acme-example-123-build-" + strings.Repeat("x", 45) + "-be4428ce-d41c4efab6030b0e",
		},
		{
			name:    "invalid identity returns validation error",
			wantErr: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.identity.FilenameKey()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if got != "" {
					t.Fatalf("key on error: got %q, want empty", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("FilenameKey: %v", err)
			}
			if got != tt.want {
				t.Fatalf("FilenameKey: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJobIdentity_FilenameKey_DistinguishesSanitizedCollisions(t *testing.T) {
	slashProject := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	underscoreProject := jobcontext.GitHubJobIdentity("github.com", "acme_example", "123", "build", "1", "runner-1")

	slashKey, err := slashProject.FilenameKey()
	if err != nil {
		t.Fatalf("slash project FilenameKey: %v", err)
	}
	underscoreKey, err := underscoreProject.FilenameKey()
	if err != nil {
		t.Fatalf("underscore project FilenameKey: %v", err)
	}
	if slashKey == underscoreKey {
		t.Fatalf("FilenameKey collision: both identities produced %q", slashKey)
	}
}
