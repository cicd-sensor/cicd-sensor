//go:build linux

package kerneltracker

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	bpfprog "github.com/cicd-sensor/cicd-sensor/internal/agent/bpf/generated"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
)

func TestDecodeUnixSocketConnectSample(t *testing.T) {
	t.Parallel()

	type sampleOpts struct {
		kind             uint32
		sunPath          []byte
		sunPathLen       uint32
		isAbstract       uint8
		sockType         uint8
		sunPathTruncated uint8
		cwd              string
		cwdTruncated     uint8
		cwdUnavailable   uint8
	}

	buildSample := func(t *testing.T, opts sampleOpts) []byte {
		t.Helper()

		sample := bpfprog.BPFProgramUnixSocketConnectSample{
			Kind:             opts.kind,
			SocketType:       opts.sockType,
			IsAbstract:       opts.isAbstract,
			SunPathTruncated: opts.sunPathTruncated,
			CwdTruncated:     opts.cwdTruncated,
			CwdUnavailable:   opts.cwdUnavailable,
			TsNs:             701,
			CgroupId:         801,
			StartBoottime:    901,
			Tgid:             1001,
			SunPathLen:       opts.sunPathLen,
		}
		copy(sample.SunPath[:], opts.sunPath)

		// Place cwd right-aligned in sample.Cwd[] with a trailing NUL,
		// matching what resolve_dentry_into_sample produces.
		if opts.cwd != "" {
			cwdBytes := []byte(opts.cwd)
			bufLen := len(sample.Cwd)
			start := bufLen - len(cwdBytes) - 1
			if start < 0 {
				t.Fatalf("cwd %q exceeds sample.Cwd buffer", opts.cwd)
			}
			for i, b := range cwdBytes {
				sample.Cwd[start+i] = int8(b)
			}
			// Trailing byte is already zero (struct zero-initialized).
			sample.CwdOffset = uint16(start)
		}

		var buffer bytes.Buffer
		if err := binary.Write(&buffer, binary.LittleEndian, sample); err != nil {
			t.Fatalf("binary.Write() error = %v", err)
		}
		return buffer.Bytes()
	}

	fsPath := []byte("/run/systemd/journal/socket")
	abstractPath := append([]byte{0x00}, []byte("dbus-7")...)
	relPath := []byte("./docker.sock")

	tests := []struct {
		name       string
		sample     []byte
		want       unixSocketConnectSample
		wantErrSub string
	}{
		{
			name: "absolute_filesystem",
			sample: buildSample(t, sampleOpts{
				kind: kernelio.SampleKindUnixSocketConnect, sunPath: fsPath,
				sunPathLen: uint32(len(fsPath)), sockType: 1,
			}),
			want: unixSocketConnectSample{
				Identity:   processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID:   801,
				TsNs:       701,
				SunPath:    fsPath,
				SunPathLen: uint32(len(fsPath)),
				SocketType: 1,
			},
		},
		{
			name: "abstract_seqpacket",
			sample: buildSample(t, sampleOpts{
				kind: kernelio.SampleKindUnixSocketConnect, sunPath: abstractPath,
				sunPathLen: uint32(len(abstractPath)),
				isAbstract: 1, sockType: 5,
			}),
			want: unixSocketConnectSample{
				Identity:   processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID:   801,
				TsNs:       701,
				SunPath:    abstractPath,
				SunPathLen: uint32(len(abstractPath)),
				SocketType: 5,
				IsAbstract: true,
			},
		},
		{
			name: "relative_with_cwd",
			sample: buildSample(t, sampleOpts{
				kind: kernelio.SampleKindUnixSocketConnect, sunPath: relPath,
				sunPathLen: uint32(len(relPath)), sockType: 1,
				cwd: "/run",
			}),
			want: unixSocketConnectSample{
				Identity:   processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID:   801,
				TsNs:       701,
				SunPath:    relPath,
				SunPathLen: uint32(len(relPath)),
				SocketType: 1,
				Cwd:        "/run",
			},
		},
		{
			name: "sun_path_truncated_flag",
			sample: buildSample(t, sampleOpts{
				kind: kernelio.SampleKindUnixSocketConnect, sunPath: fsPath,
				sunPathLen: uint32(len(fsPath)), sockType: 1,
				sunPathTruncated: 1,
			}),
			want: unixSocketConnectSample{
				Identity:         processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID:         801,
				TsNs:             701,
				SunPath:          fsPath,
				SunPathLen:       uint32(len(fsPath)),
				SocketType:       1,
				SunPathTruncated: true,
			},
		},
		{
			name: "cwd_unavailable_flag",
			sample: buildSample(t, sampleOpts{
				kind: kernelio.SampleKindUnixSocketConnect, sunPath: relPath,
				sunPathLen: uint32(len(relPath)), sockType: 1,
				cwdUnavailable: 1,
			}),
			want: unixSocketConnectSample{
				Identity:       processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID:       801,
				TsNs:           701,
				SunPath:        relPath,
				SunPathLen:     uint32(len(relPath)),
				SocketType:     1,
				CwdUnavailable: true,
			},
		},
		{
			name: "cwd_truncated_flag",
			sample: buildSample(t, sampleOpts{
				kind: kernelio.SampleKindUnixSocketConnect, sunPath: relPath,
				sunPathLen: uint32(len(relPath)), sockType: 1,
				cwd: "/run", cwdTruncated: 1,
			}),
			want: unixSocketConnectSample{
				Identity:     processIdentity{PID: 1001, StartBoottime: 901},
				CgroupID:     801,
				TsNs:         701,
				SunPath:      relPath,
				SunPathLen:   uint32(len(relPath)),
				SocketType:   1,
				Cwd:          "/run",
				CwdTruncated: true,
			},
		},
		{
			name: "unexpected_size",
			sample: buildSample(t, sampleOpts{
				kind: kernelio.SampleKindUnixSocketConnect, sunPath: fsPath,
				sunPathLen: uint32(len(fsPath)), sockType: 1,
			})[:binary.Size(bpfprog.BPFProgramUnixSocketConnectSample{})-1],
			wantErrSub: "unexpected unix socket connect sample size",
		},
		{
			name: "unexpected_kind",
			sample: buildSample(t, sampleOpts{
				kind: 99, sunPath: fsPath,
				sunPathLen: uint32(len(fsPath)), sockType: 1,
			}),
			wantErrSub: "unexpected unix socket connect sample kind",
		},
		{
			name: "sun_path_len_exceeds_buffer",
			sample: buildSample(t, sampleOpts{
				kind: kernelio.SampleKindUnixSocketConnect, sunPath: fsPath,
				sunPathLen: uint32(len(bpfprog.BPFProgramUnixSocketConnectSample{}.SunPath)) + 1,
				sockType:   1,
			}),
			wantErrSub: "unix socket sun_path_len",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeUnixSocketConnectSample(test.sample)
			if test.wantErrSub != "" {
				if err == nil {
					t.Fatalf("decodeUnixSocketConnectSample() error = nil, want substring %q", test.wantErrSub)
				}
				if !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("decodeUnixSocketConnectSample() error = %q, want substring %q", err, test.wantErrSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("decodeUnixSocketConnectSample() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("decodeUnixSocketConnectSample() = %#v, want %#v", got, test.want)
			}
		})
	}
}
