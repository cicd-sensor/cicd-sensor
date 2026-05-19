// Package joblogs owns per-scope job log output workers.
package joblogs

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

// ManagerJobLogs owns the manager collector workers for one scope.
type ManagerJobLogs struct {
	logger     *slog.Logger
	connection managerclient.Connection
	sendBatch  func(context.Context, managerclient.LogBatch) error

	detection        *managerOutput
	runtimeTelemetry *managerOutput
	jobResultLog     *managerOutput
}

// ManagerJobLogsConfig carries the inputs needed to start manager job logs.
type ManagerJobLogsConfig struct {
	Logger         *slog.Logger
	Connection     managerclient.Connection
	Identity       jobcontext.JobIdentity
	Kind           jobcontext.ScopeKind
	OutputSettings *managerv1.OutputSettings
}

// NewManagerJobLogs starts workers for enabled manager job log settings.
func NewManagerJobLogs(cfg ManagerJobLogsConfig) ManagerJobLogs {
	logs := ManagerJobLogs{
		logger:     cfg.Logger,
		connection: cfg.Connection,
	}
	logs.start(cfg.Identity, cfg.Kind, cfg.OutputSettings)
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
	return o != nil && (o.detection != nil || o.runtimeTelemetry != nil || o.jobResultLog != nil)
}

func newManagerJobLogsWithSender(logger *slog.Logger, sendBatch func(context.Context, managerclient.LogBatch) error, identity jobcontext.JobIdentity, kind jobcontext.ScopeKind, settings *managerv1.OutputSettings) ManagerJobLogs {
	logs := ManagerJobLogs{
		logger:    logger,
		sendBatch: sendBatch,
	}
	logs.start(identity, kind, settings)
	return logs
}

func (o *ManagerJobLogs) start(identity jobcontext.JobIdentity, kind jobcontext.ScopeKind, settings *managerv1.OutputSettings) {
	if settings == nil {
		return
	}
	detection := settings.GetJobDetectionLog()
	runtimeTelemetry := settings.GetJobRuntimeTelemetryLog()
	jobResult := settings.GetJobResultLog()
	if !detection.GetEnabled() &&
		!runtimeTelemetry.GetEnabled() &&
		!jobResult.GetEnabled() {
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
			kind,
			managerv1.LogKind_LOG_KIND_JOB_DETECTION,
			detection,
		)
	}
	if runtimeTelemetry.GetEnabled() {
		o.runtimeTelemetry = newManagerOutput(
			o.logger,
			sendBatch,
			identity,
			kind,
			managerv1.LogKind_LOG_KIND_JOB_RUNTIME_TELEMETRY,
			runtimeTelemetry,
		)
	}
	if jobResult.GetEnabled() {
		o.jobResultLog = newManagerOutput(
			o.logger,
			sendBatch,
			identity,
			kind,
			managerv1.LogKind_LOG_KIND_JOB_RESULT,
			jobResult,
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

// WriteRuntimeTelemetryPayload enqueues one runtime telemetry log entry.
func (o *ManagerJobLogs) WriteRuntimeTelemetryPayload(ctx context.Context, payload []byte) error {
	if o.runtimeTelemetry == nil {
		return nil
	}
	return o.runtimeTelemetry.Emit(ctx, payload)
}

// EmitAndCloseJobResultLog writes the final job_result_log payload.
func (o *ManagerJobLogs) EmitAndCloseJobResultLog(ctx context.Context, payload []byte) error {
	if o.jobResultLog == nil {
		return nil
	}
	return o.jobResultLog.EmitAndClose(ctx, payload)
}

// HasJobResultLog reports whether a job_result_log destination is configured.
func (o *ManagerJobLogs) HasJobResultLog() bool {
	return o != nil && o.jobResultLog != nil
}

// DroppedLogRecords returns the number of streaming records dropped because
// the manager output backlog was full. Close-after-emit errors are not drops.
func (o *ManagerJobLogs) DroppedLogRecords(kind managerv1.LogKind) uint64 {
	if o == nil {
		return 0
	}
	switch kind {
	case managerv1.LogKind_LOG_KIND_JOB_DETECTION:
		return o.detection.droppedCount()
	case managerv1.LogKind_LOG_KIND_JOB_RUNTIME_TELEMETRY:
		return o.runtimeTelemetry.droppedCount()
	case managerv1.LogKind_LOG_KIND_JOB_RESULT:
		return o.jobResultLog.droppedCount()
	default:
		return 0
	}
}

// FinalizeStreamingLogs closes detection and runtime telemetry logs.
func (o *ManagerJobLogs) FinalizeStreamingLogs(ctx context.Context) error {
	var errs []error
	if o.detection != nil {
		if err := o.detection.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if o.runtimeTelemetry != nil {
		if err := o.runtimeTelemetry.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
