//go:build linux

package kernelio

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
)

// goHTTPBodyOffset recognizes the ABIInternal small/medium stack check, before
// any argument register or stack-frame changes. morestack jumps back to entry,
// so probing entry itself can report one request twice. Unknown code is rejected.
// Compiler definitions: Go src/cmd/internal/obj/{x86/obj6,arm64/obj7}.go, stacksplit.
func goHTTPBodyOffset(machine elf.Machine, code []byte) (uint64, bool) {
	switch machine {
	case elf.EM_X86_64:
		pos := 0
		switch {
		case bytes.HasPrefix(code, []byte{0x49, 0x3b, 0x66, 0x10}): // CMP RSP, [R14+16]
			pos = 4
		case len(code) >= 12 && bytes.Equal(code[:4], []byte{0x4c, 0x8d, 0xa4, 0x24}) &&
			bytes.Equal(code[8:12], []byte{0x4d, 0x3b, 0x66, 0x10}): // LEA R12, [RSP+disp32]; CMP R12, [R14+16]
			if int32(binary.LittleEndian.Uint32(code[4:8])) >= 0 {
				return 0, false
			}
			pos = 12
		case len(code) >= 9 && bytes.Equal(code[:4], []byte{0x4c, 0x8d, 0x64, 0x24}) &&
			bytes.Equal(code[5:9], []byte{0x4d, 0x3b, 0x66, 0x10}): // Same LEA/CMP with disp8.
			if int8(code[4]) >= 0 {
				return 0, false
			}
			pos = 9
		default:
			return 0, false
		}
		// JBE morestack. Require a forward branch and a following body byte.
		if len(code) > pos+6 && code[pos] == 0x0f && code[pos+1] == 0x86 && int32(binary.LittleEndian.Uint32(code[pos+2:pos+6])) > 0 {
			return uint64(pos + 6), true
		}
		if len(code) > pos+2 && code[pos] == 0x76 && int8(code[pos+1]) > 0 {
			return uint64(pos + 2), true
		}
	case elf.EM_AARCH64:
		if len(code) < 16 || binary.LittleEndian.Uint32(code[:4]) != 0xf9400b90 { // LDR X16, [X28+16]
			return 0, false
		}
		pos := 8
		if binary.LittleEndian.Uint32(code[4:8]) != 0xeb3063ff { // CMP SP, X16
			if len(code) < 20 || binary.LittleEndian.Uint32(code[4:8])&0xffc003ff != 0xd10003f1 || // SUB X17, SP, #imm12
				binary.LittleEndian.Uint32(code[8:12]) != 0xeb10023f { // CMP X17, X16
				return 0, false
			}
			pos = 12
		}
		branch := binary.LittleEndian.Uint32(code[pos : pos+4])
		if branch&0xff00001f == 0x54000009 && int32(branch<<8)>>13 > 0 { // B.LS morestack, signed imm19
			return uint64(pos + 4), true
		}
	}
	return 0, false
}
