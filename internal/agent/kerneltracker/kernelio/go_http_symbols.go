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

const goHTTPRoundTripFunction = "net/http.(*Transport).roundTrip"

var errUnsupportedGoPCLN = errors.New("unsupported Go pclntab")

type resolvedGoHTTPFunction struct {
	name       string
	fileOffset uint64
}

// resolveGoHTTPFunction delegates Go metadata layout handling to the
// OpenTelemetry eBPF Profiler and only converts its virtual address to the
// absolute ELF file offset expected by cilium/ebpf.
func resolveGoHTTPFunction(reader io.ReaderAt, name string) (
	resolved resolvedGoHTTPFunction,
	found bool,
	err error,
) {
	defer func() {
		if recovered := recover(); recovered != nil {
			resolved = resolvedGoHTTPFunction{}
			found = false
			err = fmt.Errorf("%w: %v", errUnsupportedGoPCLN, recovered)
		}
	}()

	file, err := pfelf.NewFile(reader, 0, false)
	if err != nil {
		if errors.Is(err, pfelf.ErrNotELF) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return resolvedGoHTTPFunction{}, false, nil
		}
		return resolvedGoHTTPFunction{}, false, err
	}
	defer file.Close()
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return resolvedGoHTTPFunction{}, false, nil
	}
	if !file.IsGolang() {
		return resolvedGoHTTPFunction{}, false, nil
	}

	pcln, err := elfunwindinfo.NewGopclntab(file)
	if err != nil {
		return resolvedGoHTTPFunction{}, false, fmt.Errorf("%w: %v", errUnsupportedGoPCLN, err)
	}
	defer pcln.Close()

	symbol, err := pcln.LookupSymbol(libpf.SymbolName(name))
	if errors.Is(err, libpf.ErrSymbolNotFound) {
		return resolvedGoHTTPFunction{}, false, nil
	}
	if err != nil {
		return resolvedGoHTTPFunction{}, false, fmt.Errorf("%w: %v", errUnsupportedGoPCLN, err)
	}

	address := uint64(symbol.Address)
	fileOffset, ok := executableFileOffset(file, address)
	if !ok {
		return resolvedGoHTTPFunction{}, false, fmt.Errorf("%w: Go function %q address %#x is outside executable file segments", errUnsupportedGoPCLN, name, address)
	}
	return resolvedGoHTTPFunction{name: name, fileOffset: fileOffset}, true, nil
}

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
