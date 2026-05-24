//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLinuxKernelSampleFileOpenEndToEnd(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "file-hooks")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}
	if eventCh == nil {
		t.Fatal("RegisterJob returned nil event channel")
	}

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "visible.go")

	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}

	waitForEventRecord(t, eventCh, 5*time.Second, "file_open write", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileOpen {
			return false
		}
		gotPath, _ := record.Payload["path"].(string)
		isWrite, _ := record.Payload["is_write"].(bool)
		return gotPath == path && isWrite
	})

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	_ = file.Close()

	waitForEventRecord(t, eventCh, 5*time.Second, "file_open read", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileOpen {
			return false
		}
		gotPath, _ := record.Payload["path"].(string)
		isRead, _ := record.Payload["is_read"].(bool)
		if gotPath != path || !isRead {
			return false
		}
		if !filepath.IsAbs(gotPath) {
			t.Fatalf("file_open path = %q, want absolute path", gotPath)
		}
		return true
	})

	appendReadFile, err := os.OpenFile(path, os.O_RDONLY|syscall.O_APPEND, 0)
	if err != nil {
		t.Fatalf("OpenFile(%q, O_RDONLY|O_APPEND): %v", path, err)
	}
	_ = appendReadFile.Close()

	waitForEventRecord(t, eventCh, 5*time.Second, "file_open append read-only", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileOpen {
			return false
		}
		gotPath, _ := record.Payload["path"].(string)
		isRead, _ := record.Payload["is_read"].(bool)
		isWrite, _ := record.Payload["is_write"].(bool)
		return gotPath == path && isRead && !isWrite
	})
}

func TestLinuxKernelSampleFileOpenLongPathIsTruncated(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "file-open-long-path")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}

	dir := t.TempDir()
	for len(filepath.Join(dir, "target.txt")) <= 1030 {
		dir = filepath.Join(dir, strings.Repeat("d", 80))
	}
	path := filepath.Join(dir, "target.txt")
	if len(path) > 1280 {
		t.Fatalf("long path length = %d, want <= 1280", len(path))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	_ = file.Close()

	waitForEventRecord(t, eventCh, 5*time.Second, "file_open long path read", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileOpen {
			return false
		}
		isRead, _ := record.Payload["is_read"].(bool)
		if !isRead {
			return false
		}
		t.Logf("file_open long path saw path=%q tags=%v", record.Payload["path"], record.Tags)
		return record.Tags["truncated"] == "path"
	})
}

// TestLinuxKernelSampleFileRemoveEndToEnd exercises the security_inode_unlink and
// security_inode_rmdir hooks. The bounded dentry walk in resolve_dentry_path
// must produce the absolute path of the unlinked target via per-CPU scratch
// without verifier rejection.
func TestLinuxKernelSampleFileRemoveEndToEnd(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "file-remove")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}
	if eventCh == nil {
		t.Fatal("RegisterJob returned nil event channel")
	}

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "victim.txt")
	dirPath := filepath.Join(tempDir, "victim_dir")

	if err := os.WriteFile(filePath, []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	if err := os.Remove(filePath); err != nil {
		t.Fatalf("Remove(file): %v", err)
	}
	// Match by basename suffix rather than full absolute path: on
	// container CI rootfs (LVH kind) the self-built dentry walk in
	// emit_file_remove cannot resolve OverlayFS / bind-mount boundaries
	// reliably, so the BPF event may carry a layer-internal prefix
	// instead of the visible /tmp/... prefix. The basename is unique
	// within this test so suffix-match still proves the hook fired for
	// the right inode. See program.c around handle_security_inode_unlink.
	waitForEventRecord(t, eventCh, 5*time.Second, "file_remove unlink", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileRemove {
			return false
		}
		path, _ := record.Payload["path"].(string)
		isFolder, _ := record.Payload["is_folder"].(bool)
		t.Logf("file_remove unlink saw path=%q is_folder=%v", path, isFolder)
		return strings.HasSuffix(path, "/"+filepath.Base(filePath)) && !isFolder
	})

	if err := os.Remove(dirPath); err != nil {
		t.Fatalf("Remove(dir): %v", err)
	}
	waitForEventRecord(t, eventCh, 5*time.Second, "file_remove rmdir", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileRemove {
			return false
		}
		path, _ := record.Payload["path"].(string)
		isFolder, _ := record.Payload["is_folder"].(bool)
		t.Logf("file_remove rmdir saw path=%q is_folder=%v", path, isFolder)
		return strings.HasSuffix(path, "/"+filepath.Base(dirPath)) && isFolder
	})
}

// TestLinuxKernelSampleFileMoveEndToEnd exercises security_inode_rename. The
// hook resolves both old_dentry and new_dentry into the same event in one
// pass, exercising the __noinline subprog path for double-walk hooks.
func TestLinuxKernelSampleFileMoveEndToEnd(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "file-move")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}

	tempDir := t.TempDir()
	fromPath := filepath.Join(tempDir, "src.bin")
	toPath := filepath.Join(tempDir, "dst.bin")
	if err := os.WriteFile(fromPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := os.Rename(fromPath, toPath); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	// See file_remove unlink comment for the suffix-match rationale.
	waitForEventRecord(t, eventCh, 5*time.Second, "file_move rename", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileMove {
			return false
		}
		from, _ := record.Payload["from_path"].(string)
		to, _ := record.Payload["to_path"].(string)
		t.Logf("file_move rename saw from=%q to=%q", from, to)
		return strings.HasSuffix(from, "/"+filepath.Base(fromPath)) &&
			strings.HasSuffix(to, "/"+filepath.Base(toPath))
	})
}

// TestLinuxKernelSampleFileLinkEndToEnd covers security_inode_link (hardlink) and
// security_inode_symlink. The symlink hook emits the old_name verbatim
// left-aligned; userspace resolves relative targets against the new link's
// dirname so existing_path is always absolute by the time it reaches CEL.
func TestLinuxKernelSampleFileLinkEndToEnd(t *testing.T) {
	kernelIO, cgroupRoot := newLinuxKernelIO(t)
	defer kernelIO.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestKernelTracker(nil, nil, kernelIO, cgroupRoot)
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(ctx)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run error = %v, want nil", err)
		}
	}()

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "file-link")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}

	tempDir := t.TempDir()
	existingPath := filepath.Join(tempDir, "target.bin")
	hardlinkPath := filepath.Join(tempDir, "hardlink.bin")
	symlinkPath := filepath.Join(tempDir, "symlink.bin")
	if err := os.WriteFile(existingPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// See file_remove unlink comment for the suffix-match rationale.
	if err := os.Link(existingPath, hardlinkPath); err != nil {
		t.Fatalf("Link: %v", err)
	}
	waitForEventRecord(t, eventCh, 5*time.Second, "file_link hardlink", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileLink {
			return false
		}
		created, _ := record.Payload["created_path"].(string)
		existing, _ := record.Payload["existing_path"].(string)
		isHardlink, _ := record.Payload["is_hardlink"].(bool)
		t.Logf("file_link hardlink saw created=%q existing=%q is_hardlink=%v", created, existing, isHardlink)
		return isHardlink &&
			strings.HasSuffix(created, "/"+filepath.Base(hardlinkPath)) &&
			strings.HasSuffix(existing, "/"+filepath.Base(existingPath))
	})

	if err := os.Symlink(existingPath, symlinkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	waitForEventRecord(t, eventCh, 5*time.Second, "file_link symlink absolute", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileLink {
			return false
		}
		created, _ := record.Payload["created_path"].(string)
		existing, _ := record.Payload["existing_path"].(string)
		isSymlink, _ := record.Payload["is_symlink"].(bool)
		t.Logf("file_link symlink absolute saw created=%q existing=%q is_symlink=%v", created, existing, isSymlink)
		return isSymlink &&
			strings.HasSuffix(created, "/"+filepath.Base(symlinkPath)) &&
			strings.HasSuffix(existing, "/"+filepath.Base(existingPath))
	})

	relSymlinkPath := filepath.Join(tempDir, "rel_symlink.bin")
	if err := os.Symlink("target.bin", relSymlinkPath); err != nil {
		t.Fatalf("Symlink relative: %v", err)
	}
	waitForEventRecord(t, eventCh, 5*time.Second, "file_link symlink relative resolved", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileLink {
			return false
		}
		created, _ := record.Payload["created_path"].(string)
		existing, _ := record.Payload["existing_path"].(string)
		isSymlink, _ := record.Payload["is_symlink"].(bool)
		t.Logf("file_link symlink relative saw created=%q existing=%q is_symlink=%v", created, existing, isSymlink)
		return isSymlink &&
			strings.HasSuffix(created, "/"+filepath.Base(relSymlinkPath)) &&
			strings.HasSuffix(existing, "/"+filepath.Base(existingPath))
	})
}
