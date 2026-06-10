package nri

import (
	"encoding/json"
	"maps"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestStagingDecisionForCreateContainer_GitLab(t *testing.T) {
	// Label values cannot contain "/", so runner-set labels can never hold a
	// nested group path; the job URL annotation is the only lossless source.
	tests := []struct {
		name         string
		annotations  map[string]string
		labels       map[string]string
		env          []string
		wantIdentity jobcontext.JobIdentity
	}{
		{
			name: "job url annotation wins: nested group path, env spoof ignored",
			annotations: map[string]string{
				gitlabJobIDAnnotation:  "14202203981",
				gitlabJobURLAnnotation: "https://gitlab.example.com/group/subgroup/project/-/jobs/14202203981",
			},
			labels: map[string]string{
				gitlabProjectNamespaceLabel: "group-subgroup",
				gitlabProjectNameLabel:      "project",
			},
			env: []string{
				"CI_SERVER_URL=https://spoofed.example.com",
				"CI_PROJECT_PATH=spoofed/project",
			},
			wantIdentity: jobcontext.GitLabJobIdentity("gitlab.example.com", "group/subgroup/project", "14202203981"),
		},
		{
			name: "labels and env fall back when the url annotation is missing",
			annotations: map[string]string{
				gitlabJobIDAnnotation: "14202203981",
			},
			labels: map[string]string{
				gitlabProjectNamespaceLabel: "group",
				gitlabProjectNameLabel:      "project",
			},
			env:          []string{"CI_SERVER_URL=https://gitlab.example.com"},
			wantIdentity: jobcontext.GitLabJobIdentity("gitlab.example.com", "group/project", "14202203981"),
		},
		{
			name: "url without jobs marker still supplies host, labels supply path",
			annotations: map[string]string{
				gitlabJobIDAnnotation:  "14202203981",
				gitlabJobURLAnnotation: "https://gitlab.example.com/",
			},
			labels: map[string]string{
				gitlabProjectNamespaceLabel: "group",
				gitlabProjectNameLabel:      "project",
			},
			env:          []string{"CI_SERVER_URL=https://spoofed.example.com"},
			wantIdentity: jobcontext.GitLabJobIdentity("gitlab.example.com", "group/project", "14202203981"),
		},
		{
			name: "env is the last resort when labels are absent",
			annotations: map[string]string{
				gitlabJobIDAnnotation: "14202203981",
			},
			env: []string{
				"CI_SERVER_HOST=gitlab.example.com",
				"CI_PROJECT_PATH=group/project",
			},
			wantIdentity: jobcontext.GitLabJobIdentity("gitlab.example.com", "group/project", "14202203981"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			annotations := map[string]string{
				gitlabJobNameAnnotation: "test",
				gitlabJobRefAnnotation:  "main",
				gitlabJobSHAAnnotation:  "abc123",
			}
			maps.Copy(annotations, tc.annotations)
			event := CreateContainerEvent{
				Pod: PodSnapshot{
					Labels:      tc.labels,
					Annotations: annotations,
				},
				Container: ContainerSnapshot{
					Name: "build",
					Env:  append(tc.env, "CI_PIPELINE_SOURCE=push", "GITLAB_USER_LOGIN=alice"),
				},
				CgroupBasename: "cri-containerd-build.scope",
			}

			got, ok := stagingDecisionForCreateContainer(jobcontext.ProviderGitLab, event)
			if !ok {
				t.Fatalf("stageable: got false (%s)", got.String())
			}
			if got.Identity != tc.wantIdentity {
				t.Fatalf("identity: got %+v, want %+v", got.Identity, tc.wantIdentity)
			}
			if got.Metadata.CommitSHA != "abc123" || got.Metadata.RefName != "main" || got.Metadata.GitLabJobName != "test" {
				t.Fatalf("metadata: got %+v", got.Metadata)
			}
			if got.Metadata.Trigger != "push" || got.Metadata.ActorName != "alice" {
				t.Fatalf("env metadata: got %+v", got.Metadata)
			}
		})
	}
}

func TestStagingDecisionForCreateContainer_GitLabSkipsJobURLIDMismatch(t *testing.T) {
	event := CreateContainerEvent{
		Pod: PodSnapshot{
			Annotations: map[string]string{
				gitlabJobIDAnnotation:  "14202203981",
				gitlabJobURLAnnotation: "https://gitlab.example.com/group/project/-/jobs/999",
			},
		},
		Container:      ContainerSnapshot{Name: "build"},
		CgroupBasename: "cri-containerd-build.scope",
	}

	got, ok := stagingDecisionForCreateContainer(jobcontext.ProviderGitLab, event)
	if ok {
		t.Fatal("stageable: got true, want false")
	}
	if got.SkipReason != "gitlab_job_url_id_mismatch" {
		t.Fatalf("skip reason: got %q", got.SkipReason)
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
	if got.Identity != identity {
		t.Fatalf("identity: got %+v, want %+v", got.Identity, identity)
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
