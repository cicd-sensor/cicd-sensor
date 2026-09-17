//go:build linux

package httpprepare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// maxLibraryEntries bounds name matching per directory, not ELF parsing.
// One extra entry is read to detect overflow; excess entries use mapping discovery.
const maxLibraryEntries = 4096

// OpenFiles finds HTTP library and executable candidates below rootPath.
// Absolute symlinks stay inside that root; procfs magic links, which can refer
// directly to another process's files, are rejected during candidate lookup.
func OpenFiles(ctx context.Context, rootPath string) (files []*os.File, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The runtime supplies this entry point, often /proc/PID/root. Open it first;
	// the stricter openat2 rules below apply to paths found inside that root.
	root, err := os.Open(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	failed := 0
	for _, dir := range inventoryDirectories() {
		if err := ctx.Err(); err != nil {
			return files, err
		}
		names := []string{"gh", "glab"}
		if dir.library {
			fd, err := unix.Openat2(int(root.Fd()), dir.path, &unix.OpenHow{
				Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
				Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
			})
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					failed++
				}
				continue
			}
			directory := os.NewFile(uintptr(fd), dir.path)
			names, err = directory.Readdirnames(maxLibraryEntries + 1)
			_ = directory.Close()
			if err != nil && !errors.Is(err, io.EOF) {
				failed++
			}
			if len(names) > maxLibraryEntries {
				names = names[:maxLibraryEntries]
				failed++
			}
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return files, err
			}
			// The supported wildcard is a suffix after the exact soname prefix.
			if dir.library && name != "libssl.so" && name != "libnghttp2.so" &&
				!strings.HasPrefix(name, "libssl.so.") && !strings.HasPrefix(name, "libnghttp2.so.") {
				continue
			}
			if len(files) == MaxFiles {
				return files, errors.New("HTTP inventory file cap")
			}
			candidate := path.Join(dir.path, name)
			fd, err := unix.Openat2(int(root.Fd()), candidate, &unix.OpenHow{
				Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY,
				Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
			})
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					failed++
				}
				continue
			}
			f := os.NewFile(uintptr(fd), candidate)
			info, err := f.Stat()
			if err != nil || !info.Mode().IsRegular() {
				_ = f.Close()
				failed++
				continue
			}
			files = append(files, f)
		}
	}
	if failed > 0 {
		return files, fmt.Errorf("HTTP inventory: %d filesystem errors or directory overflows", failed)
	}
	return files, nil
}

type inventoryDirectory struct {
	path    string
	library bool
}

func inventoryDirectories() []inventoryDirectory {
	dirs := []inventoryDirectory{{path: "/bin"}, {path: "/usr/bin"}, {path: "/usr/local/bin"}}
	// Debian-style systems separate libraries by CPU/ABI, for example
	// /usr/lib/x86_64-linux-gnu. These names follow the Agent's architecture.
	architectureDirName := ""
	switch runtime.GOARCH {
	case "amd64":
		architectureDirName = "x86_64-linux-gnu"
	case "arm64":
		architectureDirName = "aarch64-linux-gnu"
	}
	if architectureDirName != "" {
		dirs = append(dirs, inventoryDirectory{path: "/lib/" + architectureDirName, library: true}, inventoryDirectory{path: "/usr/lib/" + architectureDirName, library: true})
	}
	for _, p := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64"} {
		dirs = append(dirs, inventoryDirectory{path: p, library: true})
	}
	return dirs
}
