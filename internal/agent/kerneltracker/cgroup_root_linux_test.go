//go:build linux

package kerneltracker

import (
	"errors"
	"testing"
)

func TestCgroupV2RootDiscovery(t *testing.T) {
	root, err := getCgroupV2Root()
	if err != nil {
		if errors.Is(err, errHostCgroupV2RootMissing) || errors.Is(err, errCgroupV2RootNotFound) {
			t.Skipf("host cgroup v2 root is unavailable in this test environment: %v", err)
		}
		t.Fatalf("getCgroupV2Root: %v", err)
	}
	if root == "" {
		t.Fatal("getCgroupV2Root returned empty path")
	}
}
