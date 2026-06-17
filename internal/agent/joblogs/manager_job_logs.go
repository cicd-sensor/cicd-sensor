// Package joblogs owns per-scope job log output workers.
package joblogs

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

// ManagerJobLogs owns the manager collector workers for one scope.
type ManagerJobLogs struct {
	logger     *slog.Logger
	connection managerclient.Connection
	sendBatch  func(context.Context, managerclient.LogBatch) error

	detection    *managerOutput
	runtimeEvent *managerOutput
	summaryLog   *managerOutput
}

// ManagerJobLogsConfig carries the inputs needed to start manager job logs.
type ManagerJobLogsConfig struct {
	Logger         *slog.Logger
	Connection     managerclient.Connection
	Identity       jobcontext.JobIdentity
	Type           jobcontext.ScopeType
	OutputSettings *managerv1beta1.OutputSettings
}

// NewManagerJobLogs starts workers for enabled manager job log settings.
func NewManagerJobLogs(cfg ManagerJobLogsConfig) ManagerJobLogs {
	logs := ManagerJobLogs{
		logger:     cfg.Logger,
		connection: cfg.Connection,
	}
	logs.start(cfg.Identity, cfg.Type, cfg.OutputSettings)
	return logs
}

// NewForTesting delivers each batch to sendBatch instead of dialing a manager.
func NewForTesting(logger *slog.Logger, sendBatch func(context.Context, managerclient.LogBatch) error) ManagerJobLogs {
	return ManagerJobLogs{
		logger:    logger,
		sendBatch: sendBatch,
	}
}

// HasWorkersForTesting reports whether any manager log worker is active.
func (o *ManagerJobLogs) HasWorkersForTesting() bool {
	return o != nil && (o.detection != nil || o.runtimeEvent != nil || o.summaryLog != nil)
}

func newManagerJobLogsWithSender(logger *slog.Logger, sendBatch func(context.Context, managerclient.LogBatch) error, identity jobcontext.JobIdentity, scopeType jobcontext.ScopeType, settings *managerv1beta1.OutputSettings) ManagerJobLogs {
	logs := ManagerJobLogs{
		logger:    logger,
		sendBatch: sendBatch,
	}
	logs.start(identity, scopeType, settings)
	return logs
}

func (o *ManagerJobLogs) start(identity jobcontext.JobIdentity, scopeType jobcontext.ScopeType, settings *managerv1beta1.OutputSettings) {
	if settings == nil {
		return
	}
	detection := settings.GetDetection()
	runtimeEvent := settings.GetRuntimeEvent()
	summary := settings.GetSummary()
	if !detection.GetEnabled() &&
		!runtimeEvent.GetEnabled() &&
		!summary.GetEnabled() {
		return
	}

	sendBatch := o.ensureManagerSender()
	if sendBatch == nil {
		return
	}

	if detection.GetEnabled() {
		o.detection = newManagerOutput(
			o.logger,
			sendBatch,
			identity,
			scopeType,
			managerv1beta1.LogType_LOG_TYPE_DETECTION,
			detection,
			managerOutputChannelCap,
		)
	}
	if runtimeEvent.GetEnabled() {
		o.runtimeEvent = newManagerOutput(
			o.logger,
			sendBatch,
			identity,
			scopeType,
			managerv1beta1.LogType_LOG_TYPE_RUNTIME_EVENT,
			runtimeEvent,
			runtimeEventManagerOutputChannelCap,
		)
	}
	if summary.GetEnabled() {
		o.summaryLog = newManagerOutput(
			o.logger,
			sendBatch,
			identity,
			scopeType,
			managerv1beta1.LogType_LOG_TYPE_SUMMARY,
			summary,
			managerOutputChannelCap,
		)
	}
}

func (o *ManagerJobLogs) ensureManagerSender() func(context.Context, managerclient.LogBatch) error {
	if o.sendBatch != nil {
		return o.sendBatch
	}
	if o.connection.BaseURL == "" || o.connection.Token == "" {
		return nil
	}
	logger := componentLogger(o.logger, "manager_output")
	client := managerclient.NewCollectorServiceClient(logger, managerclient.NewConnectHTTPClient(), o.connection)
	o.sendBatch = client.SendLogBatch
	return o.sendBatch
}

// WriteDetectionPayload enqueues one detection log entry.
func (o *ManagerJobLogs) WriteDetectionPayload(ctx context.Context, payload []byte) error {
	if o.detection == nil {
		return nil
	}
	return o.detection.Emit(ctx, payload)
}

// WriteRuntimeEventPayload enqueues one runtime event log entry.
func (o *ManagerJobLogs) WriteRuntimeEventPayload(ctx context.Context, payload []byte) error {
	if o.runtimeEvent == nil {
		return nil
	}
	return o.runtimeEvent.Emit(ctx, payload)
}

// EmitAndCloseSummaryLog writes the final summary_log payload.
func (o *ManagerJobLogs) EmitAndCloseSummaryLog(ctx context.Context, payload []byte) error {
	if o.summaryLog == nil {
		return nil
	}
	return o.summaryLog.EmitAndClose(ctx, payload)
}

// HasSummaryLog reports whether a summary_log destination is configured.
func (o *ManagerJobLogs) HasSummaryLog() bool {
	return o != nil && o.summaryLog != nil
}

// DroppedLogRecords returns the number of streaming records dropped because
// the manager output backlog was full. Close-after-emit errors are not drops.
func (o *ManagerJobLogs) DroppedLogRecords(logType managerv1beta1.LogType) uint64 {
	if o == nil {
		return 0
	}
	switch logType {
	case managerv1beta1.LogType_LOG_TYPE_DETECTION:
		return o.detection.droppedCount()
	case managerv1beta1.LogType_LOG_TYPE_RUNTIME_EVENT:
		return o.runtimeEvent.droppedCount()
	case managerv1beta1.LogType_LOG_TYPE_SUMMARY:
		return o.summaryLog.droppedCount()
	default:
		return 0
	}
}

// FinalizeStreamingLogs closes detection and runtime event logs.
func (o *ManagerJobLogs) FinalizeStreamingLogs(ctx context.Context) error {
	var errs []error
	if o.detection != nil {
		if err := o.detection.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if o.runtimeEvent != nil {
		if err := o.runtimeEvent.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
