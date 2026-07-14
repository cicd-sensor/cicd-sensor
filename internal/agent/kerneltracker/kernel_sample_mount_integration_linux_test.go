//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"golang.org/x/sys/unix"
)

func TestLinuxKernelSampleMountBindEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for bind mount setup")
	}

	_, eventCh, cleanup := startMountIntegrationTracker(t, "classic-bind")
	defer cleanup()

	tempDir := t.TempDir()
	source := filepath.Join(tempDir, "source")
	target := filepath.Join(tempDir, "target")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", source, err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", target, err)
	}
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind mount %q -> %q: %v", source, target, err)
	}
	defer func() {
		if err := unix.Unmount(target, 0); err != nil {
			t.Fatalf("unmount %q: %v", target, err)
		}
	}()

	waitForEventRecord(t, eventCh, 5*time.Second, "bind mount", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.Mount {
			return false
		}
		sourcePath, _ := record.Payload["source_path"].(string)
		targetPath, _ := record.Payload["target_path"].(string)
		t.Logf("mount event payload=%v tags=%v", record.Payload, record.Tags)
		return sourcePath == source && targetPath == target
	})
}

func TestLinuxKernelSampleMountMoveMountEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for open_tree/move_mount setup")
	}

	_, eventCh, cleanup := startMountIntegrationTracker(t, "move-mount")
	defer cleanup()

	tempDir := t.TempDir()
	source := filepath.Join(tempDir, "source")
	target := filepath.Join(tempDir, "target")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", source, err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", target, err)
	}

	fd, err := unix.OpenTree(unix.AT_FDCWD, source, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		if isUnsupportedMountAPIError(err) {
			t.Skipf("open_tree unavailable on this kernel/environment: %v", err)
		}
		t.Fatalf("open_tree(%q): %v", source, err)
	}

	if err := unix.MoveMount(fd, "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		_ = unix.Close(fd)
		if isUnsupportedMountAPIError(err) {
			t.Skipf("move_mount unavailable on this kernel/environment: %v", err)
		}
		t.Fatalf("move_mount fd(%q) -> %q: %v", source, target, err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close open_tree fd: %v", err)
	}
	defer func() {
		if err := unix.Unmount(target, 0); err != nil {
			t.Fatalf("unmount %q: %v", target, err)
		}
	}()

	waitForEventRecord(t, eventCh, 5*time.Second, "move_mount", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.Mount {
			return false
		}
		sourcePath, _ := record.Payload["source_path"].(string)
		targetPath, _ := record.Payload["target_path"].(string)
		t.Logf("move_mount event payload=%v tags=%v", record.Payload, record.Tags)
		return sourcePath == source && targetPath == target
	})
}

func TestLinuxKernelSampleMountClassicMoveEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for MS_MOVE setup")
	}

	_, eventCh, cleanup := startMountIntegrationTracker(t, "classic-move")
	defer cleanup()

	tempDir := t.TempDir()
	source := filepath.Join(tempDir, "source")
	target := filepath.Join(tempDir, "target")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", source, err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", target, err)
	}
	// Linux rejects moving a mount whose parent has shared propagation. Run
	// the operation in a private mount namespace while keeping the helper in
	// this process's tracked cgroup.
	command := exec.CommandContext(t.Context(), "unshare", "--mount", "--propagation", "private",
		"sh", "-ceu", `
mount -t tmpfs -o size=1m tmpfs "$1"
mount --move "$1" "$2"
`, "sh", source, target)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("classic move mount %q -> %q: %v\n%s", source, target, err, output)
	}

	waitForEventRecord(t, eventCh, 5*time.Second, "classic move mount", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.Mount {
			return false
		}
		sourcePath, _ := record.Payload["source_path"].(string)
		targetPath, _ := record.Payload["target_path"].(string)
		return sourcePath == source && targetPath == target
	})
}

func TestLinuxKernelSampleMountIgnoresOrdinaryMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for mount setup")
	}

	_, eventCh, cleanup := startMountIntegrationTracker(t, "ordinary-mount")
	defer cleanup()

	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", target, err)
	}
	if err := unix.Mount("tmpfs", target, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatalf("mount tmpfs at %q: %v", target, err)
	}
	defer func() {
		if err := unix.Unmount(target, 0); err != nil {
			t.Fatalf("unmount %q: %v", target, err)
		}
	}()

	assertNoMountEvent(t, eventCh, 500*time.Millisecond)
}

func TestLinuxKernelSampleMountIgnoresBindRemount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for bind remount setup")
	}

	_, eventCh, cleanup := startMountIntegrationTracker(t, "bind-remount")
	defer cleanup()

	tempDir := t.TempDir()
	source := filepath.Join(tempDir, "source")
	target := filepath.Join(tempDir, "target")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", source, err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", target, err)
	}
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind mount %q -> %q: %v", source, target, err)
	}
	defer func() {
		if err := unix.Unmount(target, 0); err != nil {
			t.Fatalf("unmount %q: %v", target, err)
		}
	}()

	waitForEventRecord(t, eventCh, 5*time.Second, "initial bind mount", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.Mount {
			return false
		}
		sourcePath, _ := record.Payload["source_path"].(string)
		targetPath, _ := record.Payload["target_path"].(string)
		return sourcePath == source && targetPath == target
	})
	if err := unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_BIND, ""); err != nil {
		t.Fatalf("remount bind %q: %v", target, err)
	}

	assertNoMountEvent(t, eventCh, 500*time.Millisecond)
}

func TestLinuxKernelSampleMountIgnoresPropagationChange(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for mount propagation setup")
	}

	_, eventCh, cleanup := startMountIntegrationTracker(t, "propagation-change")
	defer cleanup()

	// Keep propagation changes out of the host mount namespace. Both the
	// unshare setup and the explicit operation reach the classic mount path,
	// and neither should produce the path-exposure event.
	command := exec.CommandContext(t.Context(), "unshare", "--mount", "--propagation", "private",
		"mount", "--make-private", "/")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("make mount private: %v\n%s", err, output)
	}

	assertNoMountEvent(t, eventCh, 500*time.Millisecond)
}

func assertNoMountEvent(t *testing.T, eventCh <-chan jobevent.EventRecord, duration time.Duration) {
	t.Helper()
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	for {
		select {
		case record := <-eventCh:
			if record.EventType == jobevent.Mount {
				t.Fatalf("unexpected mount event: payload=%v", record.Payload)
			}
		case <-deadline.C:
			return
		}
	}
}

func startMountIntegrationTracker(t *testing.T, jobSuffix string) (*KernelTracker, <-chan jobevent.EventRecord, func()) {
	t.Helper()

	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	ctx, cancel := context.WithCancel(context.Background())

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "mount-hooks-"+jobSuffix)
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		cancel()
		_ = kernelIO.Close()
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		cancel()
		_ = kernelIO.Close()
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}
	if eventCh == nil {
		cancel()
		_ = kernelIO.Close()
		t.Fatal("RegisterJob returned nil event channel")
	}

	cleanup := func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
		if err := kernelIO.Close(); err != nil {
			t.Fatalf("KernelIO Close: %v", err)
		}
	}
	return engine, eventCh, cleanup
}

func isUnsupportedMountAPIError(err error) bool {
	return err == unix.ENOSYS || err == unix.EOPNOTSUPP || err == unix.EINVAL || err == unix.EPERM
}
