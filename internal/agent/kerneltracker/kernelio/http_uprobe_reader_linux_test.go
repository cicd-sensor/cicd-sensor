//go:build linux

package kernelio

import (
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMappedFileReader(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		offset  int64
		size, n int
		want    error
	}{
		{"bounded read", 1, 2, 2, nil},
		{"short read reports EOF", 2, 4, 1, io.EOF},
		{"end of mapping", 3, 1, 0, io.EOF},
		{"empty request at EOF", 3, 0, 0, nil},
		{"negative offset rejected", -1, 1, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n, err := (mappedFileReader{data: []byte("abc")}).ReadAt(make([]byte, tc.size), tc.offset)
			if n != tc.n || tc.offset < 0 && err == nil || tc.offset >= 0 && !errors.Is(err, tc.want) {
				t.Fatalf("n=%d err=%v", n, err)
			}
		})
	}
	t.Run("concurrent truncate becomes a read error", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "mapped")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := f.Truncate(4096); err != nil {
			t.Fatal(err)
		}
		data, err := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ, unix.MAP_PRIVATE)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Munmap(data)
		if err := f.Truncate(0); err != nil {
			t.Fatal(err)
		}
		if _, err := (mappedFileReader{data: data}).ReadAt(make([]byte, 1), 0); !errors.Is(err, errMappedReadFault) {
			t.Fatalf("fault not contained: %v", err)
		}
	})
}
