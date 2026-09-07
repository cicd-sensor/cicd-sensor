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

// OpenFiles opens only explicit HTTP target names below rootPath. openat2's
// RESOLVE_IN_ROOT is needed because container absolute symlinks must resolve
// inside that root; os.Root's escaping-symlink rejection is not that operation.
func OpenFiles(ctx context.Context, rootPath string, extraBinDirectories []string) (files []*os.File, stats InventoryStats, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	root, err := os.Open(rootPath)
	if err != nil {
		return nil, stats, err
	}
	defer root.Close()
	open := func(p string) (*os.File, error) {
		fd, e := unix.Openat2(int(root.Fd()), p, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
		if e != nil {
			return nil, e
		}
		return os.NewFile(uintptr(fd), p), nil
	}
	seenPaths := make(map[string]bool)
	candidate := func(p string) {
		if seenPaths[p] {
			return
		}
		seenPaths[p] = true
		if stats.Candidates >= maxCandidateAttempts {
			stats.Truncated = true
			return
		}
		stats.Candidates++
		if len(files) >= MaxFiles {
			stats.Truncated = true
			return
		}
		if ctx.Err() != nil {
			return
		}
		f, e := open(p)
		if e != nil {
			if errors.Is(e, os.ErrNotExist) {
				stats.Missing++
			} else {
				stats.Failed++
			}
			return
		}
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			stats.Failed++
			return
		}
		files = append(files, f)
		stats.Opened++
	}
	for _, dir := range inventoryDirectories(extraBinDirectories) {
		if err = ctx.Err(); err != nil {
			return
		}
		if len(files) >= MaxFiles {
			stats.Truncated = true
			break
		}
		stats.Directories++
		if !dir.library {
			candidate(path.Join(dir.path, "gh"))
			candidate(path.Join(dir.path, "glab"))
			continue
		}
		f, e := open(dir.path)
		if e != nil {
			if errors.Is(e, os.ErrNotExist) {
				stats.Missing++
			} else {
				stats.Failed++
			}
			continue
		}
		// Probe common ABI names before bounded enumeration: a large multiarch
		// directory must not hide libssl.so.3 merely due to readdir order.
		for _, name := range []string{"libssl.so", "libssl.so.3", "libssl.so.1.1", "libnghttp2.so", "libnghttp2.so.14"} {
			candidate(path.Join(dir.path, name))
		}
		// ReadDir(-1) followed by sorting/truncation would leave work unbounded.
		entries, e := f.ReadDir(maxDirectoryEntries)
		_ = f.Close()
		stats.Entries += len(entries)
		if e != nil && !errors.Is(e, io.EOF) {
			stats.Failed++
			continue
		}
		if len(entries) == maxDirectoryEntries {
			stats.Truncated = true
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				break
			}
			if libraryTarget(entry.Name()) {
				candidate(path.Join(dir.path, entry.Name()))
			}
			if len(files) >= MaxFiles {
				stats.Truncated = true
				break
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return
	}
	if stats.Failed > 0 {
		err = fmt.Errorf("HTTP inventory: %d filesystem operations failed", stats.Failed)
	}
	return
}

type inventoryDirectory struct {
	path    string
	library bool
}

func inventoryDirectories(extra []string) []inventoryDirectory {
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
	seen := map[string]bool{"/bin": true, "/usr/bin": true, "/usr/local/bin": true}
	// Bound examining supplied entries too, including invalid/duplicate ones.
	for i, p := range extra {
		if i >= maxDirectories || len(dirs) >= maxDirectories {
			break
		}
		if !path.IsAbs(p) || strings.IndexByte(p, 0) >= 0 {
			continue
		}
		p = path.Clean(p)
		if !seen[p] {
			dirs = append(dirs, inventoryDirectory{p, false})
			seen[p] = true
		}
	}
	return dirs
}
func libraryTarget(name string) bool {
	return name == "libssl.so" || strings.HasPrefix(name, "libssl.so.") || name == "libnghttp2.so" || strings.HasPrefix(name, "libnghttp2.so.")
}
