package job_test

import (
	"context"
	"io"
	"log/slog"
)

var (
	externalTestCtx    = context.Background()
	externalTestLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
)

const externalTestEventChannelSize = 4096
