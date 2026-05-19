package managerclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1/managerv1connect"
)

const (
	collectorServiceRequestTimeout = 30 * time.Second
	collectorServiceRetryBase      = time.Second
	collectorServiceRetryMax       = 30 * time.Second
	collectorServiceRetryAttempts  = 5
)

type CollectorServiceClient struct {
	client managerv1connect.CollectorServiceClient
	token  string
	logger *slog.Logger
	sleep  sleepFunc
	jitter jitterFunc
}

func NewCollectorServiceClient(logger *slog.Logger, httpClient *http.Client, conn Connection) *CollectorServiceClient {
	return newCollectorServiceClient(logger, httpClient, conn, sleepContext, jitterHalf)
}

func newCollectorServiceClient(logger *slog.Logger, httpClient *http.Client, conn Connection, sleep sleepFunc, jitter jitterFunc) *CollectorServiceClient {
	if httpClient == nil {
		httpClient = NewConnectHTTPClient()
	}
	return &CollectorServiceClient{
		client: managerv1connect.NewCollectorServiceClient(
			httpClient,
			conn.BaseURL,
			ConnectClientOptions(conn.Token)...,
		),
		token:  conn.Token,
		logger: collectorServiceLogger(logger),
		sleep:  sleep,
		jitter: jitter,
	}
}

func (c *CollectorServiceClient) SendLogBatch(ctx context.Context, batch LogBatch) error {
	msg, err := BuildCollectorIngestLogBatch(batch)
	if err != nil {
		return err
	}
	return c.sendIngestLogBatch(ctx, msg)
}

func (c *CollectorServiceClient) sendIngestLogBatch(ctx context.Context, batch *managerv1.IngestLogBatch) error {
	if c == nil {
		return fmt.Errorf("collector service client is nil")
	}
	if !managerauth.IsValidToken(c.token) {
		return fmt.Errorf("%s", managerauth.ValidTokenDescription())
	}
	if batch == nil {
		return fmt.Errorf("collector ingest log batch is nil")
	}

	delay := collectorServiceRetryBase
	attempt := 0
	for {
		reqCtx, cancel := context.WithTimeout(ctx, collectorServiceRequestTimeout)
		req := connect.NewRequest(&managerv1.IngestLogRequest{Batch: batch})
		_, err := c.client.IngestLog(reqCtx, req)
		cancel()
		if err == nil {
			return nil
		}
		if !isCollectorServiceRetryable(err) {
			return fmt.Errorf("send collector ingest log batch: %w", err)
		}
		if attempt >= collectorServiceRetryAttempts {
			return fmt.Errorf("send collector ingest log batch after %d retries: %w", attempt, err)
		}
		if c.logger != nil {
			c.logger.WarnContext(ctx, "agent_ingest_request_retry",
				"reason", connect.CodeOf(err).String(),
				"error", err,
			)
		}
		attempt++
		if sleepErr := c.sleep(ctx, c.jitter(delay)); sleepErr != nil {
			return fmt.Errorf("send collector ingest log batch: %w", errors.Join(err, sleepErr))
		}
		delay *= 2
		if delay > collectorServiceRetryMax {
			delay = collectorServiceRetryMax
		}
	}
}

func isCollectorServiceRetryable(err error) bool {
	switch connect.CodeOf(err) {
	case connect.CodeResourceExhausted, connect.CodeUnavailable, connect.CodeDeadlineExceeded:
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func collectorServiceLogger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return logger.With("component", "manager_collector_service_client")
}

type sleepFunc func(context.Context, time.Duration) error

type jitterFunc func(time.Duration) time.Duration

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func jitterHalf(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(d)))
}
