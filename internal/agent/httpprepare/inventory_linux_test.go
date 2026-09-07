//go:build linux

package httpprepare

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func targetFixture(t *testing.T, root, name string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(name), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFiles(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name              string
		setup             func(*testing.T, string)
		want              int
		failed, truncated bool
	}{
		{"absent targets are normal", func(*testing.T, string) {}, 0, false, false},
		{"only named files without recursion", func(t *testing.T, r string) {
			for _, n := range []string{"usr/bin/gh", "usr/bin/glab", "usr/bin/curl", "usr/bin/nested/gh", "usr/lib/libssl.so.3", "usr/lib/libnghttp2.so.14", "usr/lib/libcrypto.so.3"} {
				targetFixture(t, r, n)
			}
		}, 4, false, false},
		{"absolute symlink resolves in target root", func(t *testing.T, r string) {
			targetFixture(t, r, "opt/real-gh")
			if err := os.MkdirAll(filepath.Join(r, "usr/bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/opt/real-gh", filepath.Join(r, "usr/bin/gh")); err != nil {
				t.Fatal(err)
			}
		}, 1, false, false},
		{"directory and FIFO cannot block preparation", func(t *testing.T, r string) {
			if err := os.MkdirAll(filepath.Join(r, "usr/bin/gh"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(filepath.Join(r, "usr/bin/glab"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, 0, true, false},
		{"returned descriptors have a strict cap", func(t *testing.T, r string) {
			for i := range 60 {
				targetFixture(t, r, fmt.Sprintf("usr/lib/libssl.so.%03d", i))
			}
		}, MaxFiles, false, true},
		{"common ABI survives directory entry cap", func(t *testing.T, r string) {
			for i := range maxDirectoryEntries + 10 {
				targetFixture(t, r, fmt.Sprintf("usr/lib/other-%04d", i))
			}
			targetFixture(t, r, "usr/lib/libssl.so.3")
		}, 1, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := t.TempDir()
			tc.setup(t, r)
			files, stats, err := OpenFiles(t.Context(), r, nil)
			defer CloseFiles(files)
			if (err != nil) != tc.failed || len(files) != tc.want || stats.Truncated != tc.truncated {
				t.Fatalf("files=%d stats=%+v err=%v", len(files), stats, err)
			}
			if stats.Candidates > maxCandidateAttempts || stats.Directories > maxDirectories || stats.Entries > maxDirectories*maxDirectoryEntries {
				t.Fatalf("unbounded inventory: %+v", stats)
			}
		})
	}
	t.Run("cancel before root acquisition", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		files, _, err := OpenFiles(ctx, "/does-not-exist", nil)
		defer CloseFiles(files)
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}
