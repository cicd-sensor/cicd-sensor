package nri

import (
	"reflect"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
)

func TestCgroupBasename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{
			name:  "systemd path builds scope basename",
			input: "kubepods-besteffort-podabc.slice:cri-containerd:857e7bad3d90",
			want:  "cri-containerd-857e7bad3d90.scope",
			ok:    true,
		},
		{
			name:  "empty prefix is rejected",
			input: "kubepods.slice::857e7bad3d90",
			ok:    false,
		},
		{
			name:  "empty path is rejected",
			input: "",
			ok:    false,
		},
		{
			name:  "empty colon suffix is rejected",
			input: "kubepods.slice:cri-containerd:",
			ok:    false,
		},
		{
			name:  "unexpected colon format is rejected",
			input: "kubepods.slice:cri-containerd",
			ok:    false,
		},
		{
			name:  "slash path is rejected",
			input: "/kubepods.slice/podabc/cri-containerd-123.scope",
			ok:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CgroupBasename(tc.input)
			if ok != tc.ok {
				t.Fatalf("ok: got %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("basename: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSafeCreateContainerSnapshotsForLogOmitSensitiveValues(t *testing.T) {
	pod := PodSnapshot{
		ID:        "pod-id",
		Name:      "job-pod",
		UID:       "pod-uid",
		Namespace: "ci",
		Labels: map[string]string{
			"app": "secret-label-value",
		},
		Annotations: map[string]string{
			"example.com/token": "secret-annotation-value",
		},
		CgroupsPath: "pod-cgroup",
	}
	container := ContainerSnapshot{
		ID:   "container-id",
		Name: "build",
		Labels: map[string]string{
			"container": "secret-container-label-value",
		},
		Annotations: map[string]string{
			"example.com/container-token": "secret-container-annotation-value",
		},
		Env: []string{
			"TOKEN=secret-env-value",
			"CI=true",
			"TOKEN=duplicate-secret-env-value",
			"malformed",
		},
		CgroupsPath: "container-cgroup",
	}

	gotPod := safePodSnapshotForLog(pod)
	if !reflect.DeepEqual(gotPod.LabelKeys, []string{"app"}) {
		t.Fatalf("pod label keys: got %#v", gotPod.LabelKeys)
	}
	if !reflect.DeepEqual(gotPod.AnnotationKeys, []string{"example.com/token"}) {
		t.Fatalf("pod annotation keys: got %#v", gotPod.AnnotationKeys)
	}

	gotContainer := safeContainerSnapshotForLog(container)
	if !reflect.DeepEqual(gotContainer.LabelKeys, []string{"container"}) {
		t.Fatalf("container label keys: got %#v", gotContainer.LabelKeys)
	}
	if !reflect.DeepEqual(gotContainer.AnnotationKeys, []string{"example.com/container-token"}) {
		t.Fatalf("container annotation keys: got %#v", gotContainer.AnnotationKeys)
	}
	if !reflect.DeepEqual(gotContainer.EnvKeys, []string{"CI", "TOKEN"}) {
		t.Fatalf("container env keys: got %#v", gotContainer.EnvKeys)
	}
}

func TestNormalizeCreateContainer(t *testing.T) {
	pod := &nriapi.PodSandbox{
		Id:        "pod-id",
		Name:      "job-pod",
		Uid:       "pod-uid",
		Namespace: "ci",
		Labels: map[string]string{
			"app": "runner",
		},
		Annotations: map[string]string{
			"example.com/job": "123",
		},
		Linux: &nriapi.LinuxPodSandbox{CgroupsPath: "kubepods.slice/pod-id"},
	}
	container := &nriapi.Container{
		Id:          "container-id",
		Name:        "build",
		Labels:      map[string]string{"container": "build"},
		Annotations: map[string]string{"example.com/container": "build"},
		Env:         []string{"CI=true", "GITHUB_ACTIONS=true"},
		Linux:       &nriapi.LinuxContainer{CgroupsPath: "kubepods.slice:cri-containerd:container-id"},
	}

	event := NormalizeCreateContainer(pod, container)

	if event.Pod.Name != "job-pod" || event.Pod.Namespace != "ci" {
		t.Fatalf("pod snapshot: got %#v", event.Pod)
	}
	if event.Container.Name != "build" || event.Container.CgroupsPath == "" {
		t.Fatalf("container snapshot: got %#v", event.Container)
	}
	if event.CgroupBasename != "cri-containerd-container-id.scope" {
		t.Fatalf("cgroup basename: got %q, want cri-containerd-container-id.scope", event.CgroupBasename)
	}
}

func TestNormalizeCreateContainer_MalformedCgroupPathKeepsRawFields(t *testing.T) {
	event := NormalizeCreateContainer(&nriapi.PodSandbox{}, &nriapi.Container{
		Name:  "build",
		Linux: &nriapi.LinuxContainer{CgroupsPath: "kubepods.slice:cri-containerd:"},
	})

	if event.Container.Name != "build" {
		t.Fatalf("container name: got %q", event.Container.Name)
	}
	if event.CgroupBasename != "" {
		t.Fatalf("cgroup basename: got %q, want empty", event.CgroupBasename)
	}
}
