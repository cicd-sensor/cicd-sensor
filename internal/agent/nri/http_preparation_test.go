package nri

import (
	"context"
	"errors"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	nriapi "github.com/containerd/nri/pkg/api"
)

type recordingHTTPPreparation struct {
	calls  int
	root   string
	source string
	err    error
}

func (p *recordingHTTPPreparation) Prepare(ctx context.Context, root string, source string) error {
	p.calls++
	p.root = root
	p.source = source
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
		{name: "known CI init is prepared before callback returns", pid: 123, known: true, calls: 1},
		{name: "preparation failure does not fail startup", pid: 123, known: true, failure: errors.New("unavailable"), calls: 1},
		{name: "unknown workload is skipped", pid: 123},
		{name: "missing init PID is skipped", known: true},
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
			if err := o.StartContainer(t.Context(), pod, container); err != nil {
				t.Fatal(err)
			}
			if p.calls != tc.calls {
				t.Fatalf("calls=%d", p.calls)
			}
			if p.calls > 0 && (p.root != "/proc/123/root" || p.source != "nri-start") {
				t.Fatalf("preparation=%+v", p)
			}
		})
	}
}
