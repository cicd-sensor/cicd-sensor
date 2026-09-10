//go:build linux

package httpprepare

import (
	"os"
	"path/filepath"
	"testing"
)

func testProcessRoot(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "cgroup"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestOpenProcessMembership(t *testing.T) {
	for _, tc := range []struct {
		name, root string
		wantErr    bool
	}{
		{name: "process membership opened without reading", root: "/proc/self/root"},
		{name: "plain filesystem root cannot identify process", root: "/", wantErr: true},
		{name: "exited process is rejected", root: "/proc/2147483647/root", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := openProcessMembership(tc.root)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v", err)
			}
			if f != nil {
				_ = f.Close()
			}
		})
	}
}
