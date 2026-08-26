//go:build linux

package kernelio

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHTTPUprobeDiscoveryQueueMapping(t *testing.T) {
	t.Parallel()
	mapping := httpUprobeMapping{tgid: 4321, vmStart: 0x400000, vmEnd: 0x401000}

	t.Run("available queue records the mapping", func(t *testing.T) {
		t.Parallel()
		d := &httpUprobeDiscovery{mappingRequests: make(chan httpUprobeMapping, 1)}
		d.queueMapping(mapping)
		select {
		case got := <-d.mappingRequests:
			if got != mapping {
				t.Fatalf("queued mapping = %+v, want %+v", got, mapping)
			}
		default:
			t.Fatal("expected a mapping request, queue was empty")
		}
	})

	t.Run("full queue drops the request without blocking", func(t *testing.T) {
		t.Parallel()
		d := &httpUprobeDiscovery{mappingRequests: make(chan httpUprobeMapping, 1)}
		d.queueMapping(mapping)
		d.queueMapping(httpUprobeMapping{tgid: 9876})
		if len(d.mappingRequests) != 1 {
			t.Fatalf("queue len = %d, want 1", len(d.mappingRequests))
		}
		if d.mappingQueueDropped != 1 {
			t.Fatalf("mappingQueueDropped = %d, want 1", d.mappingQueueDropped)
		}
	})
}

func TestParseExecMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		line        string
		wantOK      bool
		wantRange   string
		wantMapping mappedFileIdentity
	}{
		{
			name:        "executable file-backed mapping",
			line:        "55a1b2c00000-55a1b2c21000 r-xp 00000000 fd:01 1443212 /usr/lib/x86_64-linux-gnu/libssl.so.3",
			wantOK:      true,
			wantRange:   "55a1b2c00000-55a1b2c21000",
			wantMapping: mappedFileIdentity{deviceMajor: 0xfd, deviceMinor: 1, inode: 1443212},
		},
		{
			name:        "low executable address is normalized for map_files",
			line:        "00400000-066a1000 r-xp 00000000 08:01 1443212 /usr/bin/node",
			wantOK:      true,
			wantRange:   "400000-66a1000",
			wantMapping: mappedFileIdentity{deviceMajor: 8, deviceMinor: 1, inode: 1443212},
		},
		{name: "non-executable mapping is skipped", line: "55a1b2c21000-55a1b2c25000 r--p 00021000 fd:01 1443212 /usr/lib/libssl.so.3"},
		{name: "anonymous mapping is skipped", line: "7f0000000000-7f0000001000 r-xp 00000000 00:00 0 "},
		{name: "special mapping is skipped", line: "7ffff7fce000-7ffff7fd0000 r-xp 00000000 00:00 1 [vdso]"},
		{name: "no pathname field is skipped", line: "7ffff7fce000-7ffff7fd0000 r-xp 00000000 00:00 12345"},
		{name: "invalid address range is skipped", line: "not-hex r-xp 00000000 08:01 1443212 /usr/bin/node"},
		{name: "invalid device is skipped", line: "400000-401000 r-xp 00000000 invalid 1443212 /usr/bin/node"},
		{name: "invalid inode is skipped", line: "400000-401000 r-xp 00000000 08:01 invalid /usr/bin/node"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rng, mapped, ok := parseExecMapping(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if rng != tt.wantRange {
				t.Fatalf("range = %q, want %q", rng, tt.wantRange)
			}
			if mapped != tt.wantMapping {
				t.Fatalf("mapping = %+v, want %+v", mapped, tt.wantMapping)
			}
		})
	}
}

func TestClassificationKeyFromFile(t *testing.T) {
	t.Parallel()
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatalf("open self executable: %v", err)
	}
	defer f.Close()

	got, err := classificationKeyFromFile(f)
	if err != nil {
		t.Fatalf("classificationKeyFromFile: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatalf("fstat self executable: %v", err)
	}
	want := fileClassificationKey{
		mappedFile: mappedFileIdentity{
			deviceMajor: uint32(unix.Major(uint64(st.Dev))),
			deviceMinor: uint32(unix.Minor(uint64(st.Dev))),
			inode:       st.Ino,
		},
		ctimeSec:  st.Ctim.Sec,
		ctimeNsec: uint32(st.Ctim.Nsec),
	}
	if got != want {
		t.Fatalf("classification key = %+v, want %+v", got, want)
	}
}

func TestMappedFilePath(t *testing.T) {
	t.Parallel()
	if got, want := mappedFilePath(123, 0x00400000, 0x066a1000), "/proc/123/map_files/400000-66a1000"; got != want {
		t.Fatalf("mappedFilePath = %q, want %q", got, want)
	}
}

func TestProcessIsGone(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		&os.PathError{Op: "open", Path: "/proc/1/maps", Err: os.ErrNotExist},
		&os.PathError{Op: "open", Path: "/proc/1/maps", Err: unix.ESRCH},
	} {
		if !processIsGone(err) {
			t.Fatalf("processIsGone(%v) = false, want true", err)
		}
	}
	if processIsGone(&os.PathError{Op: "open", Path: filepath.Join("proc", "1", "maps"), Err: os.ErrPermission}) {
		t.Fatal("permission error reported as a gone process")
	}
}

func TestDefinedHTTPUprobeSymbols(t *testing.T) {
	t.Parallel()

	t.Run("ELF without a selected C symbol is definitive", func(t *testing.T) {
		t.Parallel()
		f, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatalf("open self executable: %v", err)
		}
		defer f.Close()
		got, definitive, err := definedHTTPUprobeSymbols(f, []httpUprobeSymbol{{name: "not.a.real.symbol"}})
		if err != nil || !definitive || len(got) != 0 {
			t.Fatalf("definedHTTPUprobeSymbols = %+v, %v, %v", got, definitive, err)
		}
	})

	t.Run("non ELF is a definitive non-target", func(t *testing.T) {
		t.Parallel()
		path := t.TempDir() + "/not-elf"
		if err := os.WriteFile(path, []byte("plain text"), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		got, definitive, err := definedHTTPUprobeSymbols(f, []httpUprobeSymbol{{name: "SSL_write"}})
		if err != nil || !definitive || len(got) != 0 {
			t.Fatalf("definedHTTPUprobeSymbols = %+v, %v, %v", got, definitive, err)
		}
	})

	t.Run("reader failure remains retryable", func(t *testing.T) {
		t.Parallel()
		got, definitive, err := definedHTTPUprobeSymbols(failingReaderAt{}, []httpUprobeSymbol{{name: "SSL_write"}})
		if err == nil || definitive || len(got) != 0 {
			t.Fatalf("definedHTTPUprobeSymbols = %+v, %v, %v; want empty, false, error", got, definitive, err)
		}
	})

	t.Run("undefined import is not selected", func(t *testing.T) {
		t.Parallel()
		f, err := os.Open("/bin/sh")
		if err != nil {
			t.Fatalf("open /bin/sh: %v", err)
		}
		defer f.Close()
		parsed, err := elf.NewFile(f)
		if err != nil {
			t.Fatalf("parse /bin/sh: %v", err)
		}
		defer parsed.Close()
		symbols, err := parsed.DynamicSymbols()
		if err != nil {
			t.Fatalf("dynamic symbols: %v", err)
		}
		var imported string
		for _, symbol := range symbols {
			if symbol.Name != "" && symbol.Section == elf.SHN_UNDEF && elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
				imported = symbol.Name
				break
			}
		}
		if imported == "" {
			t.Skip("/bin/sh has no undefined function import")
		}

		got, definitive, err := definedHTTPUprobeSymbols(f, []httpUprobeSymbol{{name: imported}})
		if err != nil || !definitive || len(got) != 0 {
			t.Fatalf("definedHTTPUprobeSymbols(%q) = %+v, %v, %v", imported, got, definitive, err)
		}
	})
}

type failingReaderAt struct{}

func (failingReaderAt) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("test read failure")
}
