//go:build linux

package kerneltracker

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestScanLiveCgroupIDsWithWalkDir(t *testing.T) {
	t.Parallel()

	t.Run("collects directory inodes", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		child := filepath.Join(root, "child")
		grandchild := filepath.Join(child, "grandchild")
		if err := os.MkdirAll(grandchild, 0o755); err != nil {
			t.Fatalf("mkdir cgroup tree: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}

		snapshot, err := scanLiveCgroupIDs(root)
		if err != nil {
			t.Fatalf("scanLiveCgroupIDs: %v", err)
		}
		if snapshot.DirectoryCount != 3 {
			t.Fatalf("directory count = %d, want 3", snapshot.DirectoryCount)
		}
		if snapshot.StatErrorCount != 0 {
			t.Fatalf("stat error count = %d, want 0", snapshot.StatErrorCount)
		}
		for _, path := range []string{root, child, grandchild} {
			var stat unix.Stat_t
			if err := unix.Stat(path, &stat); err != nil {
				t.Fatalf("stat %q: %v", path, err)
			}
			if _, ok := snapshot.LiveCgroupIDs[stat.Ino]; !ok {
				t.Fatalf("inode for %q not found in live cgroup IDs", path)
			}
		}
	})

	t.Run("empty root returns error", func(t *testing.T) {
		t.Parallel()

		if _, err := scanLiveCgroupIDs(""); err == nil {
			t.Fatal("scanLiveCgroupIDs empty root error = nil, want error")
		}
	})

	t.Run("root walk error returns error", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		wantErr := errors.New("walk root failed")
		_, err := scanLiveCgroupIDsWithWalkDir(root, func(path string, fn fs.WalkDirFunc) error {
			return fn(path, testDirEntry{name: filepath.Base(path), dir: true}, wantErr)
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("scan error = %v, want %v", err, wantErr)
		}
	})

	t.Run("transient non-root disappearance is counted and ignored", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		missing := filepath.Join(root, "gone")
		snapshot, err := scanLiveCgroupIDsWithWalkDir(root, func(path string, fn fs.WalkDirFunc) error {
			if err := fn(root, testDirEntry{name: filepath.Base(root), dir: true}, nil); err != nil {
				return err
			}
			return fn(missing, nil, os.ErrNotExist)
		})
		if err != nil {
			t.Fatalf("scanLiveCgroupIDsWithWalkDir: %v", err)
		}
		if snapshot.DirectoryCount != 1 {
			t.Fatalf("directory count = %d, want 1", snapshot.DirectoryCount)
		}
		if snapshot.StatErrorCount != 1 {
			t.Fatalf("stat error count = %d, want 1", snapshot.StatErrorCount)
		}
	})

	t.Run("non-ENOENT child walk error aborts scan", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		child := filepath.Join(root, "child")
		wantErr := os.ErrPermission
		_, err := scanLiveCgroupIDsWithWalkDir(root, func(path string, fn fs.WalkDirFunc) error {
			if err := fn(root, testDirEntry{name: filepath.Base(root), dir: true}, nil); err != nil {
				return err
			}
			return fn(child, nil, wantErr)
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("scan error = %v, want %v", err, wantErr)
		}
	})
}

type testDirEntry struct {
	name string
	dir  bool
}

func (entry testDirEntry) Name() string               { return entry.name }
func (entry testDirEntry) IsDir() bool                { return entry.dir }
func (entry testDirEntry) Type() fs.FileMode          { return 0 }
func (entry testDirEntry) Info() (fs.FileInfo, error) { return nil, nil }
