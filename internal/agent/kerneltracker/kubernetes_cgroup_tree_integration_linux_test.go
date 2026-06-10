//go:build linux

package kerneltracker

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestBindPodCgroupTreeForProcess_KubernetesPod(t *testing.T) {
	if os.Getenv("CICD_SENSOR_K8S_BIND_POD_CGROUP_TREE_TEST") != "1" {
		t.Skip("set CICD_SENSOR_K8S_BIND_POD_CGROUP_TREE_TEST=1 inside a privileged hostPID Kubernetes Pod")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine, err := New(logger, nil)
	if err != nil {
		t.Fatalf("new kernel tracker: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	t.Cleanup(func() {
		_ = engine.Close()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("kernel tracker stopped with error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("kernel tracker did not stop")
		}
	})

	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "k8s-bind", "1", "runner")
	if _, err := engine.RegisterJob(ctx, identity); err != nil {
		t.Fatalf("register job: %v", err)
	}

	result, err := engine.BindPodCgroupTreeForProcess(ctx, identity, int32(os.Getpid()))
	if err != nil {
		t.Fatalf("bind pod cgroup tree: %v", err)
	}
	t.Logf("pod cgroup tree bind result: pod_cgroup_path=%s candidate_cgroups=%d bound_cgroups=%d", result.PodCgroupPath, result.CandidateCgroups, result.BoundCgroups)
	if result.PodCgroupPath == "" {
		t.Fatal("pod cgroup path is empty")
	}
	if result.CandidateCgroups == 0 {
		t.Fatal("candidate cgroups: got 0, want at least 1")
	}
	if result.BoundCgroups == 0 {
		t.Fatal("bound cgroups: got 0, want at least 1")
	}

	found, err := engine.JobForPeerPID(ctx, int32(os.Getpid()))
	if err != nil {
		t.Fatalf("job for peer pid: %v", err)
	}
	if !found.Found || found.JobID != identity {
		t.Fatalf("job for peer pid: got found=%v job=%+v, want %+v", found.Found, found.JobID, identity)
	}
}
