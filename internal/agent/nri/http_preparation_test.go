package nri

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	nriapi "github.com/containerd/nri/pkg/api"
)

type recordingHTTPPreparation struct {
	calls    int
	root     string
	dirs     []string
	source   string
	deadline time.Time
	err      error
}

func (p *recordingHTTPPreparation) Prepare(ctx context.Context, root string, dirs []string, options kernelio.HTTPPreparationOptions) error {
	p.calls++
	p.root = root
	p.dirs = dirs
	p.source = options.Source
	p.deadline, _ = ctx.Deadline()
	return p.err
}
func TestStartContainerHTTPPreparation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		pid     uint32
		known   bool
		failure error
		calls   int
	}{
		{"known CI init is prepared before callback returns", 123, true, nil, 1},
		{"preparation failure does not fail startup", 123, true, errors.New("unavailable"), 1},
		{"unknown workload is skipped", 123, false, nil, 0},
		{"missing init PID is skipped", 0, true, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &recordingHTTPPreparation{err: tc.failure}
			o := &Observer{provider: jobcontext.ProviderGitLab, preparation: p}
			pod := &nriapi.PodSandbox{Id: "pod"}
			if tc.known {
				pod.Annotations = map[string]string{gitlabJobIDAnnotation: "123", gitlabJobURLAnnotation: "https://gitlab.com/group/project/-/jobs/123"}
			}
			container := &nriapi.Container{Id: "container", Name: "build", Pid: tc.pid, Args: []string{"/tools/gh"}, Env: []string{"PATH=/tools/bin"}, Linux: &nriapi.LinuxContainer{CgroupsPath: "kubepods.slice:cri-containerd:container"}}
			start := time.Now()
			if err := o.StartContainer(t.Context(), pod, container); err != nil {
				t.Fatal(err)
			}
			if p.calls != tc.calls {
				t.Fatalf("calls=%d", p.calls)
			}
			if p.calls > 0 && (p.root != "/proc/123/root" || p.source != "nri-start" || !slices.Equal(p.dirs, []string{"/tools", "/tools/bin"}) || p.deadline.IsZero() || p.deadline.Sub(start) > httpprepare.Budget+10*time.Millisecond) {
				t.Fatalf("preparation=%+v", p)
			}
		})
	}
}

func TestSynchronizeHTTPPreparation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		canceled bool
		want     int
	}{
		{"reconnect preparation stops at container cap", false, 32},
		{"canceled reconnect performs no preparation", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &recordingHTTPPreparation{}
			o := &Observer{provider: jobcontext.ProviderGitLab, preparation: p}
			pod := &nriapi.PodSandbox{Id: "pod", Annotations: map[string]string{gitlabJobIDAnnotation: "123", gitlabJobURLAnnotation: "https://gitlab.com/group/project/-/jobs/123"}}
			containers := make([]*nriapi.Container, 40)
			for i := range containers {
				containers[i] = &nriapi.Container{Id: "container", PodSandboxId: "pod", Name: "build", Pid: 123, Linux: &nriapi.LinuxContainer{CgroupsPath: "kubepods.slice:cri-containerd:container"}}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			updates, err := o.Synchronize(ctx, []*nriapi.PodSandbox{pod}, containers)
			if err != nil || len(updates) != 0 || p.calls != tc.want {
				t.Fatalf("calls=%d updates=%v err=%v", p.calls, updates, err)
			}
			if p.calls > 0 && p.source != "nri-synchronize" {
				t.Fatal(p.source)
			}
		})
	}
}
