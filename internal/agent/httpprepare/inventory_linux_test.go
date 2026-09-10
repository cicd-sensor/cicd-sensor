//go:build linux

package httpprepare

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		paths  []string
		failed bool
	}{
		{name: "absent targets are normal", setup: func(*testing.T, string) {}},
		{name: "empty library directory is normal", setup: func(t *testing.T, r string) {
			if err := os.MkdirAll(filepath.Join(r, "usr/lib"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "library wildcards without recursion or unrelated files", want: 8,
			paths: []string{"usr/bin/gh", "usr/bin/glab", "usr/lib/libnghttp2.so", "usr/lib/libnghttp2.so.99.1", "usr/lib/libssl.so", "usr/lib/libssl.so.3", "usr/lib/libssl.so.4", "usr/lib/libssl.so.99"},
			setup: func(t *testing.T, r string) {
				for _, n := range []string{"usr/bin/gh", "usr/bin/glab", "usr/bin/curl", "usr/bin/nested/gh", "usr/lib/libssl.so", "usr/lib/libssl.so.3", "usr/lib/libssl.so.4", "usr/lib/libnghttp2.so", "usr/lib/libnghttp2.so.99.1", "usr/lib/libcrypto.so.3", "usr/lib/libssl.so.99", "usr/lib/libssl.software", "usr/lib/libnghttp2.software", "usr/lib/nested/libssl.so.4", "opt/bin/gh"} {
					targetFixture(t, r, n)
				}
			}},
		{name: "library directory symlink resolves in target root", want: 1, paths: []string{"usr/lib/libssl.so.4"}, setup: func(t *testing.T, r string) {
			targetFixture(t, r, "opt/libraries/libssl.so.4")
			if err := os.MkdirAll(filepath.Join(r, "usr"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/opt/libraries", filepath.Join(r, "usr/lib")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "library symlink opens target file", want: 1, paths: []string{"usr/lib/libssl.so.4"}, setup: func(t *testing.T, r string) {
			targetFixture(t, r, "opt/real-ssl")
			if err := os.MkdirAll(filepath.Join(r, "usr/lib"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/opt/real-ssl", filepath.Join(r, "usr/lib/libssl.so.4")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "library directory must be a directory", failed: true, setup: func(t *testing.T, r string) {
			targetFixture(t, r, "usr/lib")
		}},
		{name: "library directory cannot escape to a host path", setup: func(t *testing.T, r string) {
			outside := t.TempDir()
			targetFixture(t, outside, "libssl.so.4")
			if err := os.MkdirAll(filepath.Join(r, "usr"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(r, "usr/lib")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "matching library directory and FIFO are rejected", failed: true, setup: func(t *testing.T, r string) {
			if err := os.MkdirAll(filepath.Join(r, "usr/lib/libssl.so.4"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(filepath.Join(r, "usr/lib/libnghttp2.so.99"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "exact directory limit is complete", setup: func(t *testing.T, r string) {
			for i := range maxLibraryEntries {
				targetFixture(t, r, fmt.Sprintf("usr/lib/unrelated-%d", i))
			}
		}},
		{name: "directory overflow preserves other prepared files", want: 1, failed: true, paths: []string{"usr/bin/gh"}, setup: func(t *testing.T, r string) {
			targetFixture(t, r, "usr/bin/gh")
			for i := range maxLibraryEntries + 1 {
				targetFixture(t, r, fmt.Sprintf("usr/lib/unrelated-%d", i))
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
			if tc.paths != nil {
				var paths []string
				for _, f := range files {
					paths = append(paths, strings.TrimPrefix(f.Name(), "/"))
				}
				slices.Sort(paths)
				if !slices.Equal(paths, tc.paths) {
					t.Fatalf("paths=%v want=%v", paths, tc.paths)
				}
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
	t.Run("empty root is an error", func(t *testing.T) {
		files, err := OpenFiles(t.Context(), "")
		defer CloseFiles(files)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	})
}
