//go:build linux

package kernelio

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
)

const goNetHTTPRoundTripFunction = "net/http.(*Transport).roundTrip"

var errUnsupportedGoPclntab = errors.New("unsupported Go pclntab")

// resolveGoFunctionOffset delegates Go metadata layout handling to the
// OpenTelemetry eBPF Profiler and only converts its virtual address to the
// absolute ELF file offset expected by cilium/ebpf.
func resolveGoFunctionOffset(reader io.ReaderAt, name string) (
	fileOffset uint64,
	found bool,
	err error,
) {
	defer func() {
		if recovered := recover(); recovered != nil {
			fileOffset = 0
			found = false
			err = fmt.Errorf("%w: %v", errUnsupportedGoPclntab, recovered)
		}
	}()

	file, err := pfelf.NewFile(reader, 0, false)
	if err != nil {
		if errors.Is(err, pfelf.ErrNotELF) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer file.Close()
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return 0, false, nil
	}
	if !file.IsGolang() {
		return 0, false, nil
	}

	pcln, err := elfunwindinfo.NewGopclntab(file)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %v", errUnsupportedGoPclntab, err)
	}
	defer pcln.Close()

	symbol, err := pcln.LookupSymbol(libpf.SymbolName(name))
	if errors.Is(err, libpf.ErrSymbolNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("%w: %v", errUnsupportedGoPclntab, err)
	}

	address := uint64(symbol.Address)
	fileOffset, ok := executableFileOffset(file, address)
	if !ok {
		return 0, false, fmt.Errorf("%w: Go function %q address %#x is outside executable file segments", errUnsupportedGoPclntab, name, address)
	}
	return fileOffset, true, nil
}

// executableFileOffset converts the virtual address reported by Go metadata
// into the absolute ELF file offset required by cilium/ebpf's address-based
// uprobe attach. Only executable, file-backed PT_LOAD bytes are valid targets:
// file offset = segment offset + (virtual address - segment virtual address).
func executableFileOffset(file *pfelf.File, address uint64) (uint64, bool) {
	for i := range file.Progs {
		program := &file.Progs[i]
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 || address < program.Vaddr {
			continue
		}
		relative := address - program.Vaddr
		if relative >= program.Filesz {
			continue
		}
		if relative > ^uint64(0)-program.Off {
			return 0, false
		}
		return program.Off + relative, true
	}
	return 0, false
}
