//go:build linux && bpf_integration

package kernelio

import (
	"os/exec"
	"testing"
)

func requireTestBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is required: %v", name, err)
	}
	return path
}

func newReclaimTestWorker(t *testing.T) *httpUprobeWorker {
	t.Helper()
	config := testLinuxConfig(t)
	config.EnableHTTPRequest = true
	ki, err := NewLinux(nil, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ki.httpUprobeWorker.closeAll(); _ = ki.Close() })
	return ki.httpUprobeWorker
}
