//go:build linux

package kernelio

import (
	"bytes"
	"debug/elf"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestResolveGoFunctionOffset(t *testing.T) {
	tests := []struct {
		name      string
		buildMode string
	}{
		{name: "stripped executable resolves roundTrip implementation", buildMode: "exe"},
		{name: "stripped PIE resolves roundTrip implementation", buildMode: "pie"},
		{name: "stripped externally linked PIE resolves roundTrip implementation", buildMode: "external-pie"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binaryPath := buildGoHTTPTestClient(t, test.buildMode)
			file, err := os.Open(binaryPath)
			if err != nil {
				t.Fatalf("open fixture: %v", err)
			}
			defer file.Close()

			fileOffset, found, err := resolveGoFunctionOffset(file, goNetHTTPRoundTripFunction)
			if err != nil {
				t.Fatalf("resolveGoFunctionOffset: %v", err)
			}
			if !found {
				t.Fatal("resolveGoFunctionOffset did not find roundTrip")
			}
			if fileOffset == 0 {
				t.Fatal("resolved file offset is zero")
			}

			code := make([]byte, 16)
			if _, err := file.ReadAt(code, int64(fileOffset)); err != nil {
				t.Fatalf("read resolved code: %v", err)
			}
			if bytes.Equal(code, make([]byte, len(code))) {
				t.Fatal("resolved code is all zero bytes")
			}

			elfFile, err := elf.NewFile(file)
			if err != nil {
				t.Fatalf("parse fixture ELF: %v", err)
			}
			defer elfFile.Close()
			if _, err := elfFile.Symbols(); !errors.Is(err, elf.ErrNoSymbols) {
				t.Fatalf("fixture Symbols() error = %v, want elf.ErrNoSymbols", err)
			}
			if test.buildMode == "external-pie" {
				libraries, err := elfFile.ImportedLibraries()
				if err != nil {
					t.Fatalf("read imported libraries: %v", err)
				}
				if len(libraries) == 0 {
					t.Fatal("external PIE has no imported libraries")
				}
			}
		})
	}

	t.Run("missing function is a definitive non-target", func(t *testing.T) {
		binaryPath := buildGoHTTPTestClient(t, "exe")
		file, err := os.Open(binaryPath)
		if err != nil {
			t.Fatalf("open fixture: %v", err)
		}
		defer file.Close()
		_, found, err := resolveGoFunctionOffset(file, "not/a/real.GoFunction")
		if err != nil || found {
			t.Fatalf("resolve missing function = found %v, error %v; want false, nil", found, err)
		}
	})

	t.Run("non-ELF input is a definitive non-target", func(t *testing.T) {
		_, found, err := resolveGoFunctionOffset(bytes.NewReader([]byte("not an ELF")), goNetHTTPRoundTripFunction)
		if err != nil || found {
			t.Fatalf("resolve non-ELF = found %v, error %v; want false, nil", found, err)
		}
	})

	t.Run("ELF without pclntab is a definitive non-target", func(t *testing.T) {
		file, err := os.Open("/bin/sh")
		if err != nil {
			t.Fatalf("open /bin/sh: %v", err)
		}
		defer file.Close()
		_, found, err := resolveGoFunctionOffset(file, goNetHTTPRoundTripFunction)
		if err != nil || found {
			t.Fatalf("resolve /bin/sh = found %v, error %v; want false, nil", found, err)
		}
	})

	t.Run("ELF read failure remains retryable", func(t *testing.T) {
		_, found, err := resolveGoFunctionOffset(failingReaderAt{}, goNetHTTPRoundTripFunction)
		if err == nil || found || errors.Is(err, errUnsupportedGoPclntab) {
			t.Fatalf("resolve read failure = found %v, error %v; want retryable error", found, err)
		}
	})

	t.Run("malformed pclntab is a cacheable unsupported file", func(t *testing.T) {
		binaryPath := buildGoHTTPTestClient(t, "exe")
		data, err := os.ReadFile(binaryPath)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		elfFile, err := elf.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("parse fixture ELF: %v", err)
		}
		section := elfFile.Section(".gopclntab")
		if section == nil {
			t.Fatal("fixture has no .gopclntab")
		}
		clear(data[section.Offset : section.Offset+16])
		_, found, err := resolveGoFunctionOffset(bytes.NewReader(data), goNetHTTPRoundTripFunction)
		if found || !errors.Is(err, errUnsupportedGoPclntab) {
			t.Fatalf("resolve malformed pclntab = found %v, error %v", found, err)
		}
	})
}

func TestGoHTTPObjectOffsets(t *testing.T) {
	var request http.Request
	var parsedURL url.URL
	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "Request.Method", got: unsafe.Offsetof(request.Method), want: 0},
		{name: "Request.URL", got: unsafe.Offsetof(request.URL), want: 16},
		{name: "Request.Host", got: unsafe.Offsetof(request.Host), want: 128},
		{name: "URL.Scheme", got: unsafe.Offsetof(parsedURL.Scheme), want: 0},
		{name: "URL.Host", got: unsafe.Offsetof(parsedURL.Host), want: 40},
		{name: "URL.Path", got: unsafe.Offsetof(parsedURL.Path), want: 56},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("offset = %d, want %d", test.got, test.want)
			}
		})
	}
}

func TestExecutableFileOffset(t *testing.T) {
	tests := []struct {
		name    string
		program elf.ProgHeader
		address uint64
		want    uint64
		wantOK  bool
	}{
		{
			name:    "executable segment translates virtual address",
			program: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0x1000, Vaddr: 0x400000, Filesz: 0x2000},
			address: 0x400123,
			want:    0x1123,
			wantOK:  true,
		},
		{
			name:    "non-executable segment cannot host a hook",
			program: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Off: 0x1000, Vaddr: 0x400000, Filesz: 0x2000},
			address: 0x400123,
		},
		{
			name:    "address at file-backed end is outside segment",
			program: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0x1000, Vaddr: 0x400000, Filesz: 0x2000},
			address: 0x402000,
		},
		{
			name:    "file offset overflow is rejected",
			program: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: ^uint64(0), Vaddr: 0x400000, Filesz: 0x2000},
			address: 0x400001,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file := &pfelf.File{Progs: []pfelf.Prog{{ProgHeader: test.program}}}
			got, ok := executableFileOffset(file, test.address)
			if got != test.want || ok != test.wantOK {
				t.Fatalf("executableFileOffset() = (%#x, %v), want (%#x, %v)", got, ok, test.want, test.wantOK)
			}
		})
	}
}

func buildGoHTTPTestClient(t *testing.T, buildMode string) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), "go-http-client")
	commandEnv := os.Environ()
	ldflags := "-s -w"
	var buildModeArgs []string
	switch buildMode {
	case "exe":
		commandEnv = append(commandEnv, "CGO_ENABLED=0")
	case "pie":
		commandEnv = append(commandEnv, "CGO_ENABLED=0")
		buildModeArgs = []string{"-buildmode=pie"}
	case "external-pie":
		compiler, err := exec.LookPath("cc")
		if err != nil {
			t.Skipf("C compiler is required for an externally linked fixture: %v", err)
		}
		ldflags += " -linkmode=external"
		buildModeArgs = []string{"-buildmode=pie"}
		commandEnv = append(commandEnv, "CGO_ENABLED=1", "CC="+compiler)
	default:
		t.Fatalf("unknown Go HTTP fixture build mode %q", buildMode)
	}
	args := []string{"build", "-buildvcs=false", "-trimpath", "-ldflags=" + ldflags, "-o", output}
	args = append(args, buildModeArgs...)
	args = append(args, "../testdata/go_http_client")
	command := exec.Command("go", args...)
	command.Env = commandEnv
	outputBytes, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s Go HTTP fixture: %v: %s", buildMode, err, outputBytes)
	}
	return output
}
