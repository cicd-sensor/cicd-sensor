//go:build linux

package httpprepare

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"

	"golang.org/x/sys/unix"
)

// OpenFiles probes fixed names without reading directories. RESOLVE_IN_ROOT
// resolves absolute container symlinks inside rootPath, unlike os.Root.
func OpenFiles(ctx context.Context, rootPath string) (files []*os.File, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.Open(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	failed := 0
	for _, dir := range inventoryDirectories() {
		names := []string{"gh", "glab"}
		if dir.library {
			names = []string{"libssl.so", "libssl.so.3", "libssl.so.1.1", "libssl.so.10", "libnghttp2.so", "libnghttp2.so.14"}
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return files, err
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
		return files, fmt.Errorf("HTTP inventory: %d filesystem operations failed", failed)
	}
	return files, nil
}

type inventoryDirectory struct {
	path    string
	library bool
}

func inventoryDirectories() []inventoryDirectory {
	dirs := []inventoryDirectory{{"/bin", false}, {"/usr/bin", false}, {"/usr/local/bin", false}}
	triplet := ""
	switch runtime.GOARCH {
	case "amd64":
		triplet = "x86_64-linux-gnu"
	case "arm64":
		triplet = "aarch64-linux-gnu"
	}
	if triplet != "" {
		dirs = append(dirs, inventoryDirectory{"/lib/" + triplet, true}, inventoryDirectory{"/usr/lib/" + triplet, true})
	}
	for _, p := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64"} {
		dirs = append(dirs, inventoryDirectory{p, true})
	}
	return dirs
}
