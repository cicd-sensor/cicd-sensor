//go:build linux

package kerneltracker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/moby/sys/mountinfo"
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
		if _, err := os.Stat(filepath.Join(mount.Mountpoint, "cgroup.controllers")); err == nil {
			return mount.Mountpoint, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("stat cgroup controllers under %q: %w", mount.Mountpoint, err)
		}
	}
	return "", errors.New("cgroup v2 root not found")
}
