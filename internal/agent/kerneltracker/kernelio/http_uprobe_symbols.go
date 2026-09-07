//go:build linux

package kernelio

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

// definedSymbolTargets returns selected symbol-based targets that this ELF defines.
// Undefined imports are not attach targets and may be cached as a non-target.
func definedSymbolTargets(
	reader io.ReaderAt,
	candidates []symbolUprobeTarget,
) (selected []symbolUprobeTarget, definitive bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			selected = nil
			definitive = false
			err = fmt.Errorf("parse ELF symbols: %v", recovered)
		}
	}()

	file, err := elf.NewFile(reader)
	if err != nil {
		var formatErr *elf.FormatError
		if errors.As(err, &formatErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, true, nil
		}
		return nil, false, err
	}
	defer file.Close()
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return nil, true, nil
	}

	wanted := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		wanted[candidate.symbol] = struct{}{}
	}
	found := make(map[string]uint64, len(candidates))
	collect := func(symbols []elf.Symbol) {
		for _, symbol := range symbols {
			if _, ok := wanted[symbol.Name]; !ok ||
				elf.ST_TYPE(symbol.Info) != elf.STT_FUNC ||
				symbol.Section == elf.SHN_UNDEF || symbol.Value == 0 {
				continue
			}
			// st_value is a virtual address; UprobeOptions.Address needs a file offset.
			for _, segment := range file.Progs {
				if segment.Type == elf.PT_LOAD && segment.Flags&elf.PF_X != 0 &&
					symbol.Value >= segment.Vaddr && symbol.Value-segment.Vaddr < segment.Filesz &&
					symbol.Value-segment.Vaddr <= ^uint64(0)-segment.Off {
					found[symbol.Name] = segment.Off + symbol.Value - segment.Vaddr
					break
				}
			}
		}
	}
	for _, readSymbols := range []func() ([]elf.Symbol, error){file.Symbols, file.DynamicSymbols} {
		symbols, readErr := readSymbols()
		switch {
		case readErr == nil:
			collect(symbols)
		case errors.Is(readErr, elf.ErrNoSymbols):
			continue
		default:
			return nil, false, readErr
		}
	}

	for _, candidate := range candidates {
		if offset, ok := found[candidate.symbol]; ok {
			candidate.offset = offset
			selected = append(selected, candidate)
		}
	}
	return selected, true, nil
}
