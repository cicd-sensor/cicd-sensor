//go:build linux

package httpprepare

import (
	"context"
	"errors"
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
		name   string
		setup  func(*testing.T, string)
		want   int
		failed bool
	}{
		{name: "absent targets are normal", setup: func(*testing.T, string) {}},
		{name: "only fixed names without recursion", want: 5, setup: func(t *testing.T, r string) {
			for _, n := range []string{"usr/bin/gh", "usr/bin/glab", "usr/bin/curl", "usr/bin/nested/gh", "usr/lib/libssl.so.3", "usr/lib/libssl.so.10", "usr/lib/libnghttp2.so.14", "usr/lib/libcrypto.so.3", "usr/lib/libssl.so.99", "opt/bin/gh"} {
				targetFixture(t, r, n)
			}
		}},
		{name: "absolute symlink resolves in target root", want: 1, setup: func(t *testing.T, r string) {
			targetFixture(t, r, "opt/real-gh")
			if err := os.MkdirAll(filepath.Join(r, "usr/bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/opt/real-gh", filepath.Join(r, "usr/bin/gh")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory and FIFO cannot block preparation", failed: true, setup: func(t *testing.T, r string) {
			if err := os.MkdirAll(filepath.Join(r, "usr/bin/gh"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(filepath.Join(r, "usr/bin/glab"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "returned descriptors have a strict cap", want: MaxFiles, failed: true, setup: func(t *testing.T, r string) {
			for _, dir := range []string{"lib", "lib64", "usr/lib", "usr/lib64", "usr/local/lib", "usr/local/lib64"} {
				for _, name := range []string{"libssl.so", "libssl.so.3", "libssl.so.1.1", "libssl.so.10", "libnghttp2.so", "libnghttp2.so.14"} {
					targetFixture(t, r, dir+"/"+name)
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			tc.setup(t, root)
			files, err := OpenFiles(t.Context(), root)
			defer CloseFiles(files)
			if (err != nil) != tc.failed || len(files) != tc.want {
				t.Fatalf("files=%d err=%v", len(files), err)
			}
		})
	}
	t.Run("cancel before root acquisition", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		files, err := OpenFiles(ctx, "/does-not-exist")
		defer CloseFiles(files)
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("missing root is an error", func(t *testing.T) {
		files, err := OpenFiles(t.Context(), filepath.Join(t.TempDir(), "absent"))
		defer CloseFiles(files)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	})
}
