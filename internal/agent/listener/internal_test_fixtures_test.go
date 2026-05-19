package listener

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

func newTestSocketDir(t *testing.T, prefix string) string {
	t.Helper()

	dir, err := os.MkdirTemp(testSocketBaseDir(), prefix)
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	return dir
}

func testSocketBaseDir() string {
	if base := os.Getenv("CICD_SENSOR_TEST_SOCKET_DIR"); base != "" {
		return base
	}
	if runtime.GOOS == "darwin" {
		return "/private/tmp"
	}
	return ""
}

func skipIfListenPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("unix socket listen is not permitted in this test environment: %v", err)
	}
}
