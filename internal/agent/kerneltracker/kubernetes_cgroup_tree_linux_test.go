//go:build linux

package kerneltracker

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestProcessCgroupPathFromProcCgroupData(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
		err  bool
	}{
		{
			name: "normalizes cgroup v2 path",
			data: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-runner.scope\n",
			want: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-runner.scope",
		},
		{
			name: "adds leading slash",
			data: "0::kubepods.slice/kubepods-podabc.slice/cri-containerd-runner.scope\n",
			want: "/kubepods.slice/kubepods-podabc.slice/cri-containerd-runner.scope",
		},
		{
			name: "accepts root cgroup",
			data: "0::/\n",
			want: "/",
		},
		{
			name: "rejects missing cgroup v2 entry",
			data: "1:name=systemd:/ignored\n",
			err:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := processCgroupPathFromProcCgroupData([]byte(tc.data))
			if tc.err {
				if err == nil {
					t.Fatal("error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("processCgroupPathFromProcCgroupData: %v", err)
			}
			if got != tc.want {
				t.Fatalf("path: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPodCgroupAncestor(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
		ok   bool
	}{
		{
			name: "burstable container scope",
			path: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123_456.slice/cri-containerd-abcdef.scope",
			want: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123_456.slice",
			ok:   true,
		},
		{
			name: "besteffort container scope without leading slash",
			path: "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice/cri-containerd-deadbeef.scope",
			want: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc.slice",
			ok:   true,
		},
		{
			name: "guaranteed pod slice",
			path: "/kubepods.slice/kubepods-podabc.slice/cri-containerd-deadbeef.scope",
			want: "/kubepods.slice/kubepods-podabc.slice",
			ok:   true,
		},
		{
			name: "docker host cgroup is not Kubernetes pod",
			path: "/system.slice/docker.service",
		},
		{
			name: "kubepods-like slice outside kubelet root is rejected",
			path: "/custom.slice/kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope",
		},
		{
			name: "custom cgroup root is unsupported",
			path: "/runtime.slice/runtime-kubepods.slice/runtime-kubepods-burstable.slice/runtime-kubepods-burstable-podabc.slice/cri-containerd-deadbeef.scope",
		},
		{
			name: "container scope without pod ancestor is rejected",
			path: "/kubepods.slice/kubepods-burstable.slice/cri-containerd-deadbeef.scope",
		},
		{
			name: "cgroupfs pod path is unsupported for v1",
			path: "/kubepods/burstable/podabc/deadbeef",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := podCgroupAncestor(tc.path)
			if ok != tc.ok {
				t.Fatalf("ok: got %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("ancestor: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCgroupIDFromCgroupPath(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "kubepods.slice", "kubepods-podabc.slice")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	got, err := cgroupIDFromCgroupPath("/kubepods.slice/kubepods-podabc.slice", root)
	if err != nil {
		t.Fatalf("cgroupIDFromCgroupPath: %v", err)
	}
	if got == 0 {
		t.Fatal("cgroup id = 0, want non-zero inode")
	}

	if _, err := cgroupIDFromCgroupPath("/kubepods.slice/kubepods-podabc.slice", ""); err == nil {
		t.Fatal("empty root error = nil, want error")
	}
	if _, err := cgroupIDFromCgroupPath("/missing.slice", root); err == nil {
		t.Fatal("missing cgroup error = nil, want error")
	}
}

func TestCgroupTreePathsSkipsDisappearingDescendant(t *testing.T) {
	root := "/sys/fs/cgroup"
	podPath := "/kubepods.slice/kubepods-podabc.slice"
	podFullPath := filepath.Join(root, "kubepods.slice", "kubepods-podabc.slice")
	walkDir := func(gotRoot string, fn fs.WalkDirFunc) error {
		if gotRoot != podFullPath {
			t.Fatalf("walk root: got %q, want %q", gotRoot, podFullPath)
		}
		if err := fn(podFullPath, fakeDirEntry{dir: true}, nil); err != nil {
			return err
		}
		if err := fn(filepath.Join(podFullPath, "gone.scope"), nil, os.ErrNotExist); err != nil {
			return err
		}
		return fn(filepath.Join(podFullPath, "alive.scope"), fakeDirEntry{dir: true}, nil)
	}

	got, err := cgroupTreePathsWithWalkDir(root, podPath, walkDir)
	if err != nil {
		t.Fatalf("cgroupTreePathsWithWalkDir: %v", err)
	}
	want := []string{
		"/kubepods.slice/kubepods-podabc.slice",
		"/kubepods.slice/kubepods-podabc.slice/alive.scope",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("paths: got %#v, want %#v", got, want)
	}
}

func TestCgroupTreePathsReturnsRootWalkError(t *testing.T) {
	root := "/sys/fs/cgroup"
	podPath := "/kubepods.slice/kubepods-podabc.slice"
	walkDir := func(root string, fn fs.WalkDirFunc) error {
		return fn(root, nil, os.ErrNotExist)
	}

	if _, err := cgroupTreePathsWithWalkDir(root, podPath, walkDir); err == nil {
		t.Fatal("error = nil, want root walk error")
	}
}

type fakeDirEntry struct {
	dir bool
}

func (f fakeDirEntry) Name() string {
	return ""
}

func (f fakeDirEntry) IsDir() bool {
	return f.dir
}

func (f fakeDirEntry) Type() fs.FileMode {
	if f.dir {
		return fs.ModeDir
	}
	return 0
}

func (f fakeDirEntry) Info() (fs.FileInfo, error) {
	return nil, nil
}

func TestCgroupTreePaths(t *testing.T) {
	root := t.TempDir()
	dirs := []string{
		"kubepods.slice",
		"kubepods.slice/kubepods-burstable.slice",
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice",
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-runner.scope",
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-dind.scope",
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-dind.scope/docker-inner.scope",
	}
	for _, dir := range dirs {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, dirs[2], "cgroup.procs"), []byte("123\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}

	got, err := cgroupTreePaths(root, "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice")
	if err != nil {
		t.Fatalf("cgroupTreePaths: %v", err)
	}
	want := []string{
		"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice",
		"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-dind.scope",
		"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-dind.scope/docker-inner.scope",
		"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-runner.scope",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("paths: got %#v, want %#v", got, want)
	}
}
