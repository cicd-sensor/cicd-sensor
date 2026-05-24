package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

func TestJobIdentityFlagsUseLogContextNames(t *testing.T) {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var identity jobIdentityFlags
	registerJobIdentityFlags(fs, &identity)

	args := []string{
		"--provider", "github",
		"--provider-host", "github.com",
		"--project-path", "acme/example",
		"--github-run-id", "123",
		"--github-job", "build",
		"--github-run-attempt", "2",
		"--github-runner-tracking-id", "runner-1",
		"--gitlab-job-id", "789",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse identity flags: %v", err)
	}

	want := jobIdentityFlags{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            "acme/example",
		GitHubRunID:            "123",
		GitHubJob:              "build",
		GitHubRunAttempt:       "2",
		GitHubRunnerTrackingID: "runner-1",
		GitLabJobID:            "789",
	}
	if identity != want {
		t.Fatalf("identity: got %+v, want %+v", identity, want)
	}
}

func TestJobMetadataFlagsUseLogContextNames(t *testing.T) {
	fs := flag.NewFlagSet("metadata", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var metadata jobMetadataFlags
	registerJobMetadataFlags(fs, &metadata)

	args := []string{
		"--commit-sha", "abc123",
		"--ref-name", "main",
		"--trigger", "push",
		"--actor-id", "1001",
		"--actor-name", "alice",
		"--github-workflow-ref", "acme/example/.github/workflows/build.yml@refs/heads/main",
		"--github-workflow-sha", "def456",
		"--github-workflow", "build",
		"--gitlab-job-name", "test",
		"--gitlab-config-ref-uri", "gitlab.com/acme/example//.gitlab-ci.yml@refs/heads/main",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse metadata flags: %v", err)
	}

	want := jobMetadataFlags{
		CommitSHA:          "abc123",
		RefName:            "main",
		Trigger:            "push",
		ActorID:            "1001",
		ActorName:          "alice",
		GitHubWorkflowRef:  "acme/example/.github/workflows/build.yml@refs/heads/main",
		GitHubWorkflowSHA:  "def456",
		GitHubWorkflow:     "build",
		GitLabJobName:      "test",
		GitLabConfigRefURI: "gitlab.com/acme/example//.gitlab-ci.yml@refs/heads/main",
	}
	if metadata != want {
		t.Fatalf("metadata: got %+v, want %+v", metadata, want)
	}
}

func TestJobMetadataFlagsRejectAmbiguousAliases(t *testing.T) {
	for _, oldFlag := range []string{"--branch", "--actor", "--workflow", "--workflow-ref", "--workflow-sha"} {
		t.Run(oldFlag, func(t *testing.T) {
			fs := flag.NewFlagSet("metadata", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			var metadata jobMetadataFlags
			registerJobMetadataFlags(fs, &metadata)

			err := fs.Parse([]string{oldFlag, "value"})
			if err == nil {
				t.Fatal("expected parse error")
			}
			if !strings.Contains(err.Error(), "flag provided but not defined") {
				t.Fatalf("error: got %q", err.Error())
			}
		})
	}
}
