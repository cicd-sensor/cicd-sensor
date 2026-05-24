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
func (o *ManagerJobLogs) AttachDetectionRecorderForTesting(identity jobcontext.JobIdentity, scopeType jobcontext.ScopeType, sendBatch func(context.Context, managerclient.LogBatch) error) {
	o.attachRecorderForTesting(identity, scopeType, managerv1.LogType_LOG_TYPE_DETECTION, sendBatch, func(out *managerOutput) { o.detection = out })
}

// AttachRuntimeEventRecorderForTesting wires the runtime event output
// of o to deliver each batch to sendBatch. See AttachDetectionRecorderForTesting.
func (o *ManagerJobLogs) AttachRuntimeEventRecorderForTesting(identity jobcontext.JobIdentity, scopeType jobcontext.ScopeType, sendBatch func(context.Context, managerclient.LogBatch) error) {
	o.attachRecorderForTesting(identity, scopeType, managerv1.LogType_LOG_TYPE_RUNTIME_EVENT, sendBatch, func(out *managerOutput) { o.runtimeEvent = out })
}

// AttachSummaryRecorderForTesting wires the final summary output of o to
// deliver each batch to sendBatch.
func (o *ManagerJobLogs) AttachSummaryRecorderForTesting(identity jobcontext.JobIdentity, scopeType jobcontext.ScopeType, sendBatch func(context.Context, managerclient.LogBatch) error) {
	o.attachRecorderForTesting(identity, scopeType, managerv1.LogType_LOG_TYPE_SUMMARY, sendBatch, func(out *managerOutput) { o.summaryLog = out })
}

func (o *ManagerJobLogs) attachRecorderForTesting(identity jobcontext.JobIdentity, scope jobcontext.ScopeType, logType managerv1.LogType, sendBatch func(context.Context, managerclient.LogBatch) error, assign func(*managerOutput)) {
	assign(newManagerOutput(o.logger, sendBatch, identity, scope, logType, &managerv1.OutputSetting{Enabled: true, FlushThresholdBytes: 1}))
}
