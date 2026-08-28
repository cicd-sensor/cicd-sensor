//go:build linux

package kernelio

import (
	"debug/elf"
	"errors"
	"os"
	"testing"
)

func TestDefinedSymbolTargets(t *testing.T) {
	t.Parallel()

	t.Run("ELF without a selected C symbol is definitive", func(t *testing.T) {
		t.Parallel()
		f, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatalf("open self executable: %v", err)
		}
		defer f.Close()
		got, definitive, err := definedSymbolTargets(f, []symbolUprobeTarget{{symbol: "not.a.real.symbol"}})
		if err != nil || !definitive || len(got) != 0 {
			t.Fatalf("definedSymbolTargets = %+v, %v, %v", got, definitive, err)
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
		got, definitive, err := definedSymbolTargets(f, []symbolUprobeTarget{{symbol: "SSL_write"}})
		if err != nil || !definitive || len(got) != 0 {
			t.Fatalf("definedSymbolTargets = %+v, %v, %v", got, definitive, err)
		}
	})

	t.Run("reader failure remains retryable", func(t *testing.T) {
		t.Parallel()
		got, definitive, err := definedSymbolTargets(failingReaderAt{}, []symbolUprobeTarget{{symbol: "SSL_write"}})
		if err == nil || definitive || len(got) != 0 {
			t.Fatalf("definedSymbolTargets = %+v, %v, %v; want empty, false, error", got, definitive, err)
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

		got, definitive, err := definedSymbolTargets(f, []symbolUprobeTarget{{symbol: imported}})
		if err != nil || !definitive || len(got) != 0 {
			t.Fatalf("definedSymbolTargets(%q) = %+v, %v, %v", imported, got, definitive, err)
		}
	})
}

type failingReaderAt struct{}

func (failingReaderAt) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("test read failure")
}
