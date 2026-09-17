//go:build linux

package kernelio

import (
	"debug/elf"
	"encoding/hex"
	"testing"
)

func TestGoHTTPBodyOffset(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		machine elf.Machine
		code    string
		want    uint64
		valid   bool
	}{
		{name: "amd64 gh Go1.22 stack check", machine: elf.EM_X86_64, code: "4c8da42460feffff4d3b66100f86540d000055", want: 18, valid: true},
		{name: "amd64 short frame displacement", machine: elf.EM_X86_64, code: "4c8d6424c04d3b6610762055", want: 11, valid: true},
		{name: "amd64 small frame with short branch", machine: elf.EM_X86_64, code: "493b6610762055", want: 6, valid: true},
		{name: "amd64 small frame with near branch", machine: elf.EM_X86_64, code: "493b66100f862000000055", want: 10, valid: true},
		{name: "amd64 truncated instruction is rejected", machine: elf.EM_X86_64, code: "4c8da42460feffff4d3b66100f86", want: 0, valid: false},
		{name: "amd64 missing body is rejected", machine: elf.EM_X86_64, code: "493b66107620", want: 0, valid: false},
		{name: "amd64 backward branch is rejected", machine: elf.EM_X86_64, code: "493b661076fe55", want: 0, valid: false},
		{name: "amd64 wrong condition is rejected", machine: elf.EM_X86_64, code: "493b6610752055", want: 0, valid: false},
		{name: "amd64 wrong guard register is rejected", machine: elf.EM_X86_64, code: "493b6710762055", want: 0, valid: false},
		{name: "amd64 increasing stack address is rejected", machine: elf.EM_X86_64, code: "4c8da424600100004d3b66100f86540d000055", want: 0, valid: false},
		{name: "arm64 Go1.26 stack check", machine: elf.EM_AARCH64, code: "900b40f9f18305d13f0210eb29610054f48307d1", want: 16, valid: true},
		{name: "arm64 small frame stack check", machine: elf.EM_AARCH64, code: "900b40f9ff6330eb09010054fd7bbfa9", want: 12, valid: true},
		{name: "arm64 truncated body is rejected", machine: elf.EM_AARCH64, code: "900b40f9f18305d13f0210eb29610054", want: 0, valid: false},
		{name: "arm64 wrong guard load is rejected", machine: elf.EM_AARCH64, code: "910b40f9f18305d13f0210eb29610054f48307d1", want: 0, valid: false},
		{name: "arm64 wrong scratch register is rejected", machine: elf.EM_AARCH64, code: "900b40f9f08305d13f0210eb29610054f48307d1", want: 0, valid: false},
		{name: "arm64 wrong comparison is rejected", machine: elf.EM_AARCH64, code: "900b40f9f18305d13f0211eb29610054f48307d1", want: 0, valid: false},
		{name: "arm64 wrong condition is rejected", machine: elf.EM_AARCH64, code: "900b40f9f18305d13f0210eb28610054f48307d1", want: 0, valid: false},
		{name: "arm64 backward branch is rejected", machine: elf.EM_AARCH64, code: "900b40f9f18305d13f0210ebe9ffff54f48307d1", want: 0, valid: false},
		{name: "unknown architecture is rejected", machine: elf.EM_386, code: "493b6610762055", want: 0, valid: false},
		{name: "empty code is rejected", machine: elf.EM_X86_64, code: "", want: 0, valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			code, err := hex.DecodeString(test.code)
			if err != nil {
				t.Fatal(err)
			}
			got, valid := goHTTPBodyOffset(test.machine, code)
			if got != test.want || valid != test.valid {
				t.Fatalf("offset=%d valid=%v, want %d %v", got, valid, test.want, test.valid)
			}
		})
	}
}
