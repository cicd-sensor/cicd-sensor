package job

import (
	"context"
	"io"
	"log/slog"
)

var (
	testCtx    = context.Background()
	testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
)

const testEventChannelSize = 4096
