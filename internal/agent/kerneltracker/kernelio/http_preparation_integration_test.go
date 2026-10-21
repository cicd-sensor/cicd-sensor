//go:build linux && bpf_integration

package kernelio

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func copyPreparationFixture(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mountPreparationOverlay(t *testing.T, lower string) string {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"upper", "work", "merged"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	merged := filepath.Join(base, "merged")
	options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, filepath.Join(base, "upper"), filepath.Join(base, "work"))
	if err := unix.Mount("overlay", merged, "overlay", 0, options); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(merged, 0); err != nil {
			t.Errorf("unmount test overlay: %v", err)
		}
	})
	return merged
}
