package manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink/sinktest"
)

func TestServerRun_StopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manager.yaml"), []byte("bind:\n  address: 127.0.0.1\n  port: 0\n"), 0o644); err != nil {
		t.Fatalf("write startup config: %v", err)
	}
	startupCfg, err := LoadStartupConfig(filepath.Join(dir, "manager.yaml"))
	if err != nil {
		t.Fatalf("load startup config: %v", err)
	}
	dst := sinktest.New("primary")
	router := newOutputRouterForTest(map[logtype.LogType]sink.Sink{
		logtype.Detection: dst,
	})
	server := NewServer(testLogger, startupCfg.BindAddress(), testManagerTokens, &ServedConfig{ConfigRevision: startupCfg.Revision}, "", &startupCfg, router)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Run(ctx)
	}()

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("server run: %v", err)
	}
	if got := dst.Closes(); got != 1 {
		t.Fatalf("sink closes: got %d, want 1", got)
	}
}
