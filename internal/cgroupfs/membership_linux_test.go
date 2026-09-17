//go:build linux

package cgroupfs

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestID(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name, body                      string
		emptyRoot, readerError, wantErr bool
	}{
		{name: "unified membership resolves", body: "0::/\n"},
		{name: "legacy entries are ignored", body: "2:cpu:/old\n0::/\n"},
		{name: "missing membership rejected", body: "2:cpu:/old\n", wantErr: true},
		{name: "outside namespace rejected", body: "0::/../other\n", wantErr: true},
		{name: "relative membership rejected", body: "0::relative\n", wantErr: true},
		{name: "empty mount rejected", body: "0::/\n", emptyRoot: true, wantErr: true},
		{name: "deleted membership rejected", body: "0::/ (deleted)\n", wantErr: true},
		{name: "removed path rejected", body: "0::/absent\n", wantErr: true},
		{name: "read error returned", readerError: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r io.Reader = strings.NewReader(tc.body)
			if tc.readerError {
				r = iotest.ErrReader(errors.New("read failed"))
			}
			mount := root
			if tc.emptyRoot {
				mount = ""
			}
			id, err := ID(r, mount)
			if (err != nil) != tc.wantErr || err == nil && id == 0 {
				t.Fatalf("id=%d err=%v", id, err)
			}
		})
	}
}
