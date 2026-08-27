//go:build linux

package kernelio

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

// definedHTTPUprobeSymbols returns selected symbols that this ELF defines.
// Undefined imports are not attach targets and may be cached as a non-target.
func definedHTTPUprobeSymbols(
	reader io.ReaderAt,
	candidates []httpUprobeSymbol,
) (selected []httpUprobeSymbol, definitive bool, err error) {
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
		wanted[candidate.name] = struct{}{}
	}
	found := make(map[string]struct{}, len(candidates))
	collect := func(symbols []elf.Symbol) {
		for _, symbol := range symbols {
			if _, ok := wanted[symbol.Name]; !ok ||
				elf.ST_TYPE(symbol.Info) != elf.STT_FUNC ||
				symbol.Section == elf.SHN_UNDEF || symbol.Value == 0 {
				continue
			}
			found[symbol.Name] = struct{}{}
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
		if _, ok := found[candidate.name]; ok {
			selected = append(selected, candidate)
		}
	}
	return selected, true, nil
}
