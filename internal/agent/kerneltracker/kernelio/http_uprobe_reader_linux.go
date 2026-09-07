//go:build linux

package kernelio

import (
	"errors"
	"fmt"
	"io"
	"runtime/debug"
)

var errMappedReadFault = errors.New("mapped file read fault")

// mappedFileReader reads the same mapping whose backing identity was checked.
// A concurrent truncate can fault: convert only this read's fault to an error,
// without globally changing panic behavior or claiming immutable contents.
type mappedFileReader struct{ data []byte }

func (r mappedFileReader) ReadAt(p []byte, offset int64) (n int, err error) {
	if offset < 0 {
		return 0, errors.New("negative mapped file read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if offset >= int64(len(r.data)) {
		return 0, io.EOF
	}
	previous := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(previous)
	defer func() {
		if fault := recover(); fault != nil {
			n = 0
			err = fmt.Errorf("%w: %v", errMappedReadFault, fault)
		}
	}()
	n = copy(p, r.data[offset:])
	if n < len(p) {
		err = io.EOF
	}
	return
}
