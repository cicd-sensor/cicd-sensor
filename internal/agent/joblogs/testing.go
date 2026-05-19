package joblogs

import (
	"context"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

// AttachDetectionRecorderForTesting wires the detection output of o to deliver
// each batch to sendBatch. Each enqueued payload triggers an immediate flush
// (FlushThresholdBytes=1) so tests can assert on individual records without timing.
func (o *ManagerJobLogs) AttachDetectionRecorderForTesting(identity jobcontext.JobIdentity, kind jobcontext.ScopeKind, sendBatch func(context.Context, managerclient.LogBatch) error) {
	o.attachRecorderForTesting(identity, kind, managerv1.LogKind_LOG_KIND_JOB_DETECTION, sendBatch, func(out *managerOutput) { o.detection = out })
}

// AttachRuntimeTelemetryRecorderForTesting wires the runtime telemetry output
// of o to deliver each batch to sendBatch. See AttachDetectionRecorderForTesting.
func (o *ManagerJobLogs) AttachRuntimeTelemetryRecorderForTesting(identity jobcontext.JobIdentity, kind jobcontext.ScopeKind, sendBatch func(context.Context, managerclient.LogBatch) error) {
	o.attachRecorderForTesting(identity, kind, managerv1.LogKind_LOG_KIND_JOB_RUNTIME_TELEMETRY, sendBatch, func(out *managerOutput) { o.runtimeTelemetry = out })
}

// AttachJobResultRecorderForTesting wires the final job result output of o to
// deliver each batch to sendBatch.
func (o *ManagerJobLogs) AttachJobResultRecorderForTesting(identity jobcontext.JobIdentity, kind jobcontext.ScopeKind, sendBatch func(context.Context, managerclient.LogBatch) error) {
	o.attachRecorderForTesting(identity, kind, managerv1.LogKind_LOG_KIND_JOB_RESULT, sendBatch, func(out *managerOutput) { o.jobResultLog = out })
}

func (o *ManagerJobLogs) attachRecorderForTesting(identity jobcontext.JobIdentity, scope jobcontext.ScopeKind, kind managerv1.LogKind, sendBatch func(context.Context, managerclient.LogBatch) error, assign func(*managerOutput)) {
	assign(newManagerOutput(o.logger, sendBatch, identity, scope, kind, &managerv1.OutputSetting{Enabled: true, FlushThresholdBytes: 1}))
}
