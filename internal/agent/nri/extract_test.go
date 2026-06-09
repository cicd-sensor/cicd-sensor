package nri

import (
	"encoding/json"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestStagingDecisionForCreateContainer_GitLab(t *testing.T) {
	event := CreateContainerEvent{
		Pod: PodSnapshot{
			Labels: map[string]string{
				gitlabProjectNamespaceLabel: "group/subgroup",
				gitlabProjectNameLabel:      "project",
			},
			Annotations: map[string]string{
				gitlabJobIDAnnotation:   "14202203981",
				gitlabJobNameAnnotation: "test",
				gitlabJobRefAnnotation:  "main",
				gitlabJobSHAAnnotation:  "abc123",
			},
		},
		Container: ContainerSnapshot{
			Name: "build",
			Env: []string{
				"CI_SERVER_URL=https://gitlab.example.com",
				"CI_PROJECT_PATH=spoofed/project",
				"CI_PIPELINE_SOURCE=push",
				"GITLAB_USER_LOGIN=alice",
			},
		},
		CgroupBasename: "cri-containerd-build.scope",
	}

	got, ok := stagingDecisionForCreateContainer(jobcontext.ProviderGitLab, event)
	if !ok {
		t.Fatalf("stageable: got false (%s)", got.String())
	}
	want := jobcontext.GitLabJobIdentity("gitlab.example.com", "group/subgroup/project", "14202203981")
	if got.Identity != want {
		t.Fatalf("identity: got %+v, want %+v", got.Identity, want)
	}
	if got.Metadata.CommitSHA != "abc123" || got.Metadata.RefName != "main" || got.Metadata.GitLabJobName != "test" {
		t.Fatalf("metadata: got %+v", got.Metadata)
	}
	if got.Metadata.Trigger != "push" || got.Metadata.ActorName != "alice" {
		t.Fatalf("env metadata: got %+v", got.Metadata)
	}
}

func TestStagingDecisionForCreateContainer_ProviderSeparatesExtraction(t *testing.T) {
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	rawIdentity, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	event := CreateContainerEvent{
		Pod: PodSnapshot{
			Annotations: map[string]string{githubIdentityAnnotation: string(rawIdentity)},
		},
		Container:      ContainerSnapshot{Name: "job"},
		CgroupBasename: "cri-containerd-job.scope",
	}

	got, ok := stagingDecisionForCreateContainer(jobcontext.ProviderGitLab, event)
	if ok {
		t.Fatal("stageable: got true, want false")
	}
	if got.SkipReason != "identity_missing" {
		t.Fatalf("skip reason: got %q", got.SkipReason)
	}
}

func TestStagingDecisionForCreateContainer_SkipsGitLabRuntimeContainer(t *testing.T) {
	event := CreateContainerEvent{
		Pod: PodSnapshot{
			Labels: map[string]string{
				gitlabProjectNamespaceLabel: "group",
				gitlabProjectNameLabel:      "project",
			},
			Annotations: map[string]string{gitlabJobIDAnnotation: "1"},
		},
		Container:      ContainerSnapshot{Name: "helper", Env: []string{"CI_SERVER_HOST=gitlab.com"}},
		CgroupBasename: "cri-containerd-helper.scope",
	}

	got, ok := stagingDecisionForCreateContainer(jobcontext.ProviderGitLab, event)
	if ok {
		t.Fatal("stageable: got true, want false")
	}
	if got.SkipReason != "gitlab_runtime_container" {
		t.Fatalf("skip reason: got %q", got.SkipReason)
	}
}

func TestStagingDecisionForCreateContainer_GitHubInjectedIdentity(t *testing.T) {
	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	metadata := jobcontext.JobMetadata{CommitSHA: "abc123", GitHubWorkflow: "ci"}
	rawIdentity, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	rawMetadata, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	event := CreateContainerEvent{
		Pod: PodSnapshot{
			Annotations: map[string]string{
				githubIdentityAnnotation: string(rawIdentity),
				githubMetadataAnnotation: string(rawMetadata),
			},
		},
		Container:      ContainerSnapshot{Name: "job"},
		CgroupBasename: "cri-containerd-job.scope",
	}

	got, ok := stagingDecisionForCreateContainer(jobcontext.ProviderGitHub, event)
	if !ok {
		t.Fatalf("stageable: got false (%s)", got.String())
	}
	if got.Provider != jobcontext.ProviderGitHub || got.Identity != identity {
		t.Fatalf("identity: got provider=%q identity=%+v", got.Provider, got.Identity)
	}
	if got.Metadata.CommitSHA != "abc123" || got.Metadata.GitHubWorkflow != "ci" {
		t.Fatalf("metadata: got %+v", got.Metadata)
	}
}

func TestStagingDecisionForCreateContainer_SkipsMissingIdentity(t *testing.T) {
	got, ok := stagingDecisionForCreateContainer(jobcontext.ProviderGitLab, CreateContainerEvent{
		Container:      ContainerSnapshot{Name: "main"},
		CgroupBasename: "cri-containerd-main.scope",
	})
	if ok {
		t.Fatal("stageable: got true, want false")
	}
	if got.SkipReason != "identity_missing" {
		t.Fatalf("skip reason: got %q", got.SkipReason)
	}
}

func TestStagingDecisionForCreateContainer_SkipsMissingBasename(t *testing.T) {
	got, ok := stagingDecisionForCreateContainer(jobcontext.ProviderGitLab, CreateContainerEvent{
		Pod: PodSnapshot{Annotations: map[string]string{gitlabJobIDAnnotation: "1"}},
	})
	if ok {
		t.Fatal("stageable: got true, want false")
	}
	if got.SkipReason != "cgroup_basename_missing" {
		t.Fatalf("skip reason: got %q", got.SkipReason)
	}
}
