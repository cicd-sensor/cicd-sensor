//go:build linux

package kerneltracker

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCgroupIDFromProcCgroupData(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	child := root + "/job/child"
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	var childStat unix.Stat_t
	if err := unix.Stat(child, &childStat); err != nil {
		t.Fatalf("stat child: %v", err)
	}
	got, err := cgroupIDFromProcCgroupData([]byte("0::/job/child\n"), root)
	if err != nil {
		t.Fatalf("cgroupIDFromProcCgroupData child: %v", err)
	}
	if got != childStat.Ino {
		t.Fatalf("child cgroup id = %d, want inode %d", got, childStat.Ino)
	}

	var rootStat unix.Stat_t
	if err := unix.Stat(root, &rootStat); err != nil {
		t.Fatalf("stat root: %v", err)
	}
	got, err = cgroupIDFromProcCgroupData([]byte("0::/\n"), root)
	if err != nil {
		t.Fatalf("cgroupIDFromProcCgroupData root: %v", err)
	}
	if got != rootStat.Ino {
		t.Fatalf("root cgroup id = %d, want inode %d", got, rootStat.Ino)
	}

	if _, err := cgroupIDFromProcCgroupData([]byte("1:name=systemd:/ignored\n"), root); err == nil {
		t.Fatal("missing cgroup v2 entry error = nil, want error")
	}
	if _, err := cgroupIDFromProcCgroupData([]byte("0::/\n"), ""); err == nil {
		t.Fatal("empty cgroup root error = nil, want error")
	}
}
