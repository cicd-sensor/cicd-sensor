//go:build linux

package kerneltracker

import "testing"

func TestCgroupV2RootDiscovery(t *testing.T) {
	root, err := getCgroupV2Root()
	if err != nil {
		t.Fatalf("getCgroupV2Root: %v", err)
	}
	if root == "" {
		t.Fatal("getCgroupV2Root returned empty path")
	}
}
