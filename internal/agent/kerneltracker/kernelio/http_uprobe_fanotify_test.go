//go:build linux

package kernelio

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDecodeFanotifyMetadata(t *testing.T) {
	t.Parallel()

	valid := make([]byte, unix.FAN_EVENT_METADATA_LEN)
	binary.LittleEndian.PutUint32(valid[0:4], unix.FAN_EVENT_METADATA_LEN)
	valid[4] = unix.FANOTIFY_METADATA_VERSION
	binary.LittleEndian.PutUint16(valid[6:8], unix.FAN_EVENT_METADATA_LEN)
	binary.LittleEndian.PutUint64(valid[8:16], unix.FAN_OPEN_EXEC_PERM)
	binary.LittleEndian.PutUint32(valid[16:20], 42)
	binary.LittleEndian.PutUint32(valid[20:24], 1234)

	tests := []struct {
		name    string
		raw     []byte
		wantErr bool
	}{
		{name: "valid permission event", raw: valid},
		{name: "short metadata", raw: valid[:unix.FAN_EVENT_METADATA_LEN-1], wantErr: true},
		{name: "event exceeds buffer", raw: withUint32(valid, 0, unix.FAN_EVENT_METADATA_LEN+1), wantErr: true},
		{name: "metadata length too small", raw: withUint16(valid, 6, unix.FAN_EVENT_METADATA_LEN-1), wantErr: true},
		{name: "unsupported version", raw: withByte(valid, 4, unix.FANOTIFY_METADATA_VERSION+1), wantErr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, length, err := decodeFanotifyMetadata(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatal("decodeFanotifyMetadata() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeFanotifyMetadata() error = %v", err)
			}
			if length != unix.FAN_EVENT_METADATA_LEN {
				t.Fatalf("event length = %d, want %d", length, unix.FAN_EVENT_METADATA_LEN)
			}
			if got.Fd != 42 || got.Pid != 1234 || got.Mask != unix.FAN_OPEN_EXEC_PERM {
				t.Fatalf("metadata = %+v", got)
			}
		})
	}
}

func TestCgroupV2Path(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
		want string
		ok   bool
	}{
		{name: "root", data: "0::/\n", want: "/", ok: true},
		{name: "nested", data: "0::/actions/job.scope\n", want: "/actions/job.scope", ok: true},
		{name: "hybrid line before v2", data: "2:cpu:/legacy\n0::/job\n", want: "/job", ok: true},
		{name: "missing unified entry", data: "2:cpu:/legacy\n"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, ok := cgroupV2Path([]byte(test.data))
			if got != test.want || ok != test.ok {
				t.Fatalf("cgroupV2Path() = %q, %v, want %q, %v", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestMappedIdentityFromKernelDevice(t *testing.T) {
	t.Parallel()
	const (
		major = uint64(252)
		minor = uint64(19)
		inode = uint64(12345)
	)
	got := mappedIdentityFromKernelDevice((major<<20)|minor, inode)
	want := mappedFileIdentity{deviceMajor: uint32(major), deviceMinor: uint32(minor), inode: inode}
	if got != want {
		t.Fatalf("mappedIdentityFromKernelDevice() = %+v, want %+v", got, want)
	}
}

func withUint32(source []byte, offset int, value uint32) []byte {
	result := append([]byte(nil), source...)
	binary.LittleEndian.PutUint32(result[offset:offset+4], value)
	return result
}

func withUint16(source []byte, offset int, value uint16) []byte {
	result := append([]byte(nil), source...)
	binary.LittleEndian.PutUint16(result[offset:offset+2], value)
	return result
}

func withByte(source []byte, offset int, value byte) []byte {
	result := append([]byte(nil), source...)
	result[offset] = value
	return result
}
