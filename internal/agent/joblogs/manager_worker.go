package joblogs

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

const (
	managerOutputChannelCap             = 10_000
	runtimeEventManagerOutputChannelCap = 65_536
)

type managerWorkerConfig struct {
	logger    *slog.Logger
	sendBatch func(context.Context, managerclient.LogBatch) error
	identity  jobcontext.JobIdentity
	scope     managerv1beta1.Scope
	logType   managerv1beta1.LogType
	setting   *managerv1beta1.OutputSetting
	now       func() time.Time
}

type managerWorker struct {
	logger    *slog.Logger
	sendBatch func(context.Context, managerclient.LogBatch) error
	identity  jobcontext.JobIdentity
	scope     managerv1beta1.Scope
	logType   managerv1beta1.LogType
	setting   *managerv1beta1.OutputSetting
	now       func() time.Time
}

type managerOutputRequest struct {
	ctx     context.Context
	payload []byte
	close   bool
	reply   chan error
}

func newManagerWorker(cfg managerWorkerConfig) *managerWorker {
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &managerWorker{
		logger:    componentLogger(cfg.logger, "manager_output_worker"),
		sendBatch: cfg.sendBatch,
		identity:  cfg.identity,
		scope:     cfg.scope,
		logType:   cfg.logType,
		setting:   cfg.setting,
		now:       cfg.now,
	}
}

func (w *managerWorker) run(requests <-chan managerOutputRequest, done chan<- struct{}) {
	defer close(done)

	// Snapshot the flush policy once; workers are scope-local and immutable.
	var flushThresholdBytes int
	var flushInterval time.Duration
	if w.setting != nil {
		flushThresholdBytes = int(w.setting.GetFlushThresholdBytes())
		flushInterval = time.Duration(w.setting.GetFlushIntervalSeconds()) * time.Second
	}

	var records [][]byte
	var bufferedBytes int
	var timer *time.Timer
	var timerC <-chan time.Time

	// Timer is armed only while buffered records are waiting.
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer = nil
		timerC = nil
	}
	startTimer := func() {
		if timer != nil || flushInterval == 0 || len(records) == 0 {
			return
		}
		timer = time.NewTimer(flushInterval)
		timerC = timer.C
	}
	recordBytes := func(record []byte) int {
		// BuildCollectorIngestLogBatch writes each record plus one trailing
		// newline into the gzip stream, so thresholds use uncompressed JSONL bytes.
		return len(record) + 1
	}
	appendRecord := func(record []byte) {
		records = append(records, record)
		bufferedBytes += recordBytes(record)
	}
	// Flush keeps the buffered slice until SendLogBatch accepts the batch so a
	// transient manager-side failure does not silently drop runtime event.
	flush := func(ctx context.Context) error {
		stopTimer()
		if len(records) == 0 {
			return nil
		}
		if err := w.sendBatchToManager(ctx, records, w.now().UTC()); err != nil {
			startTimer()
			return err
		}
		records = nil
		bufferedBytes = 0
		return nil
	}
	logFlushError := func(ctx context.Context, err error) {
		if err != nil && w.logger != nil {
			w.logger.ErrorContext(ctx, "agent_ingest_send_failed",
				"log_type", w.logType.String(),
				"scope", w.scope.String(),
				"error", err,
			)
		}
	}

	for {
		select {
		case req := <-requests:
			// Close carries the final optional record and drains the buffer.
			if req.close {
				if len(req.payload) > 0 {
					if flushThresholdBytes > 0 && bufferedBytes > 0 && bufferedBytes+recordBytes(req.payload) > flushThresholdBytes {
						if err := flush(req.ctx); err != nil {
							req.reply <- err
							return
						}
					}
					appendRecord(req.payload)
				}
				req.reply <- flush(req.ctx)
				return
			}
			if len(req.payload) == 0 {
				continue
			}
			if flushThresholdBytes > 0 && bufferedBytes > 0 && bufferedBytes+recordBytes(req.payload) > flushThresholdBytes {
				logFlushError(req.ctx, flush(req.ctx))
			}
			appendRecord(req.payload)
			// Size threshold keeps manager-bound runtime event batches bounded.
			if flushThresholdBytes > 0 && bufferedBytes >= flushThresholdBytes {
				logFlushError(req.ctx, flush(req.ctx))
				continue
			}
			startTimer()
		case <-timerC:
			ctx := context.Background()
			logFlushError(ctx, flush(ctx))
		}
	}
}

func (w *managerWorker) sendBatchToManager(ctx context.Context, records [][]byte, flushAt time.Time) error {
	return w.sendBatch(ctx, managerclient.LogBatch{
		Identity: w.identity,
		Scope:    w.scope,
		Type:     w.logType,
		Records:  records,
		FlushAt:  flushAt,
	})
}

var (
	errManagerOutputClosed      = errors.New("manager output is closed")
	errManagerOutputBacklogFull = errors.New("manager output backlog is full")
)
