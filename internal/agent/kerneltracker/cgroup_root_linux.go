//go:build linux

package kerneltracker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/moby/sys/mountinfo"
)

var (
	errCgroupV2RootNotFound    = errors.New("cgroup v2 root not found")
	errHostCgroupV2RootMissing = errors.New("host cgroup v2 root missing")
)

func getCgroupV2Root() (string, error) {
	mounts, err := mountinfo.GetMounts(mountinfo.FSTypeFilter("cgroup2"))
	if err != nil {
		return "", fmt.Errorf("find cgroup v2 root from mountinfo: %w", err)
	}

	for _, mount := range mounts {
		if mount == nil || mount.Mountpoint == "" {
			continue
		}
		// Kubernetes deployments mount the host cgroup v2 root at /sys/fs/cgroup.
		// A subtree root here means the agent is in a private cgroup namespace.
		if mount.Root != "/" {
			return "", fmt.Errorf("%w: cgroup2 mount root is %q, want /", errHostCgroupV2RootMissing, mount.Root)
		}
		if _, err := os.Stat(filepath.Join(mount.Mountpoint, "cgroup.controllers")); err == nil {
			return mount.Mountpoint, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("stat cgroup controllers under %q: %w", mount.Mountpoint, err)
		}
	}
	return "", errCgroupV2RootNotFound
}
