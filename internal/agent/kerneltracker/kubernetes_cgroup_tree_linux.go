//go:build linux

package kerneltracker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"golang.org/x/sys/unix"
)

const procRoot = "/proc"

// PodCgroupTreeBindResult summarizes a Kubernetes Pod cgroup tree bind attempt.
type PodCgroupTreeBindResult struct {
	PodCgroupPath    string
	CandidateCgroups int
	BoundCgroups     int
}

// BindPodCgroupTreeForProcess extends start-hook tracking from one process to
// the Kubernetes Pod cgroup tree it belongs to. ARC dind runs the Docker daemon
// as a same-Pod sidecar. Host NRI cannot see inner Docker containers, but once
// the Pod tree and dind cgroup are tracked, cgroup_mkdir/cgroup_attach_task can
// follow inner Docker cgroups created under that sidecar.
func (engine *KernelTracker) BindPodCgroupTreeForProcess(ctx context.Context, jobID jobcontext.JobIdentity, pid int32) (PodCgroupTreeBindResult, error) {
	cgroupPath, err := processCgroupPath(pid)
	if err != nil {
		return PodCgroupTreeBindResult{}, err
	}
	podPath, ok := podCgroupAncestor(cgroupPath)
	if !ok {
		return PodCgroupTreeBindResult{}, fmt.Errorf("pod cgroup ancestor not found in %q", cgroupPath)
	}

	result := PodCgroupTreeBindResult{PodCgroupPath: podPath}
	podCgroupID, err := cgroupIDFromCgroupPath(podPath, engine.cgroupV2RootPath)
	if err != nil {
		return result, err
	}
	if err := engine.bindCgroupIDToJob(ctx, jobID, podCgroupID); err != nil {
		return result, err
	}
	result.BoundCgroups++

	cgroups, err := cgroupTreePaths(engine.cgroupV2RootPath, podPath)
	if err != nil {
		return result, err
	}
	result.CandidateCgroups = len(cgroups)
	for _, cgroup := range cgroups {
		if cgroup == podPath {
			continue
		}
		cgroupID, err := cgroupIDFromCgroupPath(cgroup, engine.cgroupV2RootPath)
		if err != nil {
			engine.logger.WarnContext(ctx, "pod_cgroup_tree_bind_stat_failed",
				"job_identity", jobID,
				"cgroup_path", cgroup,
				"error", err,
			)
			continue
		}
		if err := engine.bindCgroupIDToJob(ctx, jobID, cgroupID); err != nil {
			engine.logger.WarnContext(ctx, "pod_cgroup_tree_bind_failed",
				"job_identity", jobID,
				"cgroup_path", cgroup,
				"cgroup_id", cgroupID,
				"error", err,
			)
			continue
		}
		result.BoundCgroups++
	}
	return result, nil
}

func processCgroupPath(pid int32) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d", pid)
	}
	procPath := filepath.Join(procRoot, fmt.Sprintf("%d", pid), "cgroup")
	data, err := os.ReadFile(procPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", procPath, err)
	}
	return processCgroupPathFromProcCgroupData(data)
}

func processCgroupPathFromProcCgroupData(data []byte) (string, error) {
	for len(data) > 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte{'\n'})
		if cgroupPath, ok := bytes.CutPrefix(line, []byte("0::")); ok {
			clean := path.Clean("/" + strings.TrimPrefix(string(cgroupPath), "/"))
			if clean == "." {
				clean = "/"
			}
			return clean, nil
		}
	}

	return "", errors.New("no cgroup v2 entry found")
}

func podCgroupAncestor(cgroupPath string) (string, bool) {
	// Kubernetes support targets kubelet's default systemd cgroup layout, where
	// the default pod root is "kubepods" and {"kubepods","burstable","pod<uid>"}
	// becomes:
	// /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice
	// See Kubernetes defaultNodeAllocatableCgroupName, CgroupName.ToSystemd, and
	// GetPodContainerName:
	// https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/kubelet/cm/node_container_manager_linux.go#L39-L42
	// https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/kubelet/cm/cgroup_manager_linux.go#L76-L81
	// https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/kubelet/cm/pod_container_manager_linux.go#L107-L124
	clean := path.Clean("/" + strings.TrimPrefix(cgroupPath, "/"))
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	if len(parts) == 0 || parts[0] != "kubepods.slice" {
		return "", false
	}

	for i, part := range parts {
		if isKubeletSystemdPodSlice(part) {
			return "/" + strings.Join(parts[:i+1], "/"), true
		}
	}
	return "", false
}

func isKubeletSystemdPodSlice(segment string) bool {
	return strings.HasPrefix(segment, "kubepods") &&
		strings.Contains(segment, "-pod") &&
		strings.HasSuffix(segment, ".slice")
}

func cgroupTreePaths(cgroupV2RootPath string, podPath string) ([]string, error) {
	return cgroupTreePathsWithWalkDir(cgroupV2RootPath, podPath, filepath.WalkDir)
}

func cgroupTreePathsWithWalkDir(cgroupV2RootPath string, podPath string, walkDir func(string, fs.WalkDirFunc) error) ([]string, error) {
	if cgroupV2RootPath == "" {
		return nil, fmt.Errorf("cgroup v2 root path is empty")
	}
	podFullPath := filepath.Join(cgroupV2RootPath, strings.TrimPrefix(podPath, "/"))
	paths := make([]string, 0)
	err := walkDir(podFullPath, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if current != podFullPath && errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(cgroupV2RootPath, current)
		if err != nil {
			return err
		}
		paths = append(paths, "/"+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk pod cgroup tree %q: %w", podFullPath, err)
	}
	return paths, nil
}

func cgroupIDFromCgroupPath(cgroupPath string, cgroupV2RootPath string) (uint64, error) {
	if cgroupV2RootPath == "" {
		return 0, errors.New("cgroup v2 root path is empty")
	}
	fullPath := filepath.Join(cgroupV2RootPath, strings.TrimPrefix(cgroupPath, "/"))

	var stat unix.Stat_t
	if err := unix.Stat(fullPath, &stat); err != nil {
		return 0, fmt.Errorf("stat cgroup path %q: %w", fullPath, err)
	}

	return stat.Ino, nil
}
