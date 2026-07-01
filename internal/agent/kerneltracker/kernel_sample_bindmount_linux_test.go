//go:build linux && bpf_integration

package kerneltracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
)

// TestLinuxKernelBindMountAliasPathReporting probes issue #48 "Bypass B":
// when a protected directory is reachable through a bind-mount alias, which
// path does each file hook report? security_inode_rename/link walk d_parent
// only (never crossing the alias vfsmount), so they should report the
// canonical source-fs path; security_file_open uses bpf_d_path(f_path), which
// is mount-aware and reports the alias path. This test pins both behaviours so
// the canonical-path guarantee for rename is a regression-tested property and
// the file_open gap is documented in executable form.
func TestLinuxKernelBindMountAliasPathReporting(t *testing.T) {
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

	jobID := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "bind-mount")
	eventCh, err := engine.RegisterJob(ctx, jobID)
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}
	if err := engine.BindProcessCgroupToJob(ctx, jobID, int32(os.Getpid())); err != nil {
		t.Fatalf("BindProcessCgroupToJob: %v", err)
	}

	tempDir := t.TempDir()
	canonDir := filepath.Join(tempDir, "canon") // stands in for /etc/cron.d
	aliasDir := filepath.Join(tempDir, "alias") // the bind-mount alias attacker uses
	for _, d := range []string{canonDir, aliasDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatalf("Mkdir(%q): %v", d, err)
		}
	}

	if err := syscall.Mount(canonDir, aliasDir, "", syscall.MS_BIND, ""); err != nil {
		t.Fatalf("bind mount %q -> %q: %v", canonDir, aliasDir, err)
	}
	defer func() {
		if err := syscall.Unmount(aliasDir, 0); err != nil {
			t.Logf("unmount %q: %v", aliasDir, err)
		}
	}()

	// 1) rename WITHIN the alias mount: expect the canonical /canon/ path.
	// (rename from outside the mount into the alias returns EXDEV, so the
	// realistic vector stages inside the aliased directory and renames there.)
	src := filepath.Join(aliasDir, "staging")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile staging: %v", err)
	}
	if err := os.Rename(src, filepath.Join(aliasDir, "job")); err != nil {
		t.Fatalf("Rename within alias: %v", err)
	}
	waitForEventRecord(t, eventCh, 5*time.Second, "file_move into bind alias", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileMove {
			return false
		}
		to, _ := record.Payload["to_path"].(string)
		if !strings.HasSuffix(to, "/job") {
			return false
		}
		t.Logf("file_move to_path = %q", to)
		if strings.Contains(to, "/canon/") {
			t.Logf("PASS rename reports CANONICAL path (alias-resistant)")
		} else if strings.Contains(to, "/alias/") {
			t.Errorf("rename reported ALIAS path %q (Bypass B affects rename)", to)
		}
		return true
	})

	// 2) open-for-write through the alias: record which path file_open reports.
	openTarget := filepath.Join(aliasDir, "opened")
	f, err := os.OpenFile(openTarget, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("OpenFile through alias: %v", err)
	}
	_ = f.Close()
	waitForEventRecord(t, eventCh, 5*time.Second, "file_open through bind alias", func(record jobevent.EventRecord) bool {
		if record.EventType != jobevent.FileOpen {
			return false
		}
		p, _ := record.Payload["path"].(string)
		isWrite, _ := record.Payload["is_write"].(bool)
		if !isWrite || !strings.HasSuffix(p, "/opened") {
			return false
		}
		resolved, _ := record.Payload["resolved_path"].(string)
		t.Logf("file_open path=%q resolved_path=%q", p, resolved)
		// path stays mount-aware (the alias); resolved_path is the canonical,
		// bind-mount-alias-resistant location a write rule matches on.
		if !strings.Contains(p, "/alias/") {
			t.Errorf("expected file_open path to be the alias, got %q", p)
		}
		if !strings.HasSuffix(resolved, "/canon/opened") {
			t.Errorf("expected resolved_path canonical /canon/opened, got %q", resolved)
		}
		return true
	})
}
