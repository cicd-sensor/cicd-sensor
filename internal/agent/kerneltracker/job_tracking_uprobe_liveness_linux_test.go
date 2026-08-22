//go:build linux

package kerneltracker

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func inoOf(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	return st.Ino
}

func TestScanTrackedCgroupPIDs(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_000_000, 0).UTC()

	t.Run("lists PIDs of tracked cgroups only and is complete", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		tracked := filepath.Join(root, "job-a")
		other := filepath.Join(root, "job-b")
		for _, dir := range []string{tracked, other} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(tracked, "cgroup.procs"), []byte("100\n200\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(other, "cgroup.procs"), []byte("999\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		snap := scanTrackedCgroupPIDs(root, map[uint64]struct{}{inoOf(t, tracked): {}}, start)
		if !snap.Complete {
			t.Fatalf("Complete = false, want true (readErrors=%d)", snap.ReadErrors)
		}
		if snap.ScannedCgroups != 1 {
			t.Fatalf("ScannedCgroups = %d, want 1", snap.ScannedCgroups)
		}
		if len(snap.PIDs) != 2 || snap.PIDs[0] != 100 || snap.PIDs[1] != 200 {
			t.Fatalf("PIDs = %v, want [100 200] (untracked cgroup excluded)", snap.PIDs)
		}
		if !snap.ScanStartedAt.Equal(start) {
			t.Fatalf("ScanStartedAt not preserved")
		}
	})

	t.Run("tracked cgroup without cgroup.procs is a normal race, still complete", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		tracked := filepath.Join(root, "gone")
		if err := os.MkdirAll(tracked, 0o755); err != nil {
			t.Fatal(err)
		}
		// no cgroup.procs file => ENOENT on read => PIDsGone, not an error
		snap := scanTrackedCgroupPIDs(root, map[uint64]struct{}{inoOf(t, tracked): {}}, start)
		if !snap.Complete {
			t.Fatal("ENOENT on cgroup.procs must not taint completeness (normal race)")
		}
		if snap.PIDsGone != 1 {
			t.Fatalf("PIDsGone = %d, want 1", snap.PIDsGone)
		}
	})

	t.Run("failed walk marks the snapshot incomplete (fail-keep)", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		boom := errors.New("walk failed")
		walk := func(string, fs.WalkDirFunc) error { return boom }
		snap := scanTrackedCgroupPIDsWithWalkDir(root, map[uint64]struct{}{1: {}}, start, walk)
		if snap.Complete {
			t.Fatal("a failed walk could hide a live tracked cgroup; Complete must be false")
		}
		if snap.ReadErrors == 0 {
			t.Fatal("ReadErrors should record the walk failure")
		}
	})
}

func TestScanTrackedCgroupPIDsMalformedProcsIsIncomplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	tracked := filepath.Join(root, "job")
	if err := os.MkdirAll(tracked, 0o755); err != nil {
		t.Fatal(err)
	}
	// one good PID, one line that hides a PID
	if err := os.WriteFile(filepath.Join(tracked, "cgroup.procs"), []byte("100\ngarbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := scanTrackedCgroupPIDs(root, map[uint64]struct{}{inoOf(t, tracked): {}}, time.Now())
	if snap.Complete {
		t.Fatal("a malformed cgroup.procs line may hide a live PID; snapshot must be incomplete (fail-keep)")
	}
	if len(snap.PIDs) != 1 || snap.PIDs[0] != 100 {
		t.Fatalf("PIDs = %v, want [100] (good lines still used)", snap.PIDs)
	}
}
