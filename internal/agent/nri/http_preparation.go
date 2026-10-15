package nri

import (
	"context"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/httpprepare"

	nriapi "github.com/containerd/nri/pkg/api"
)

type httpPreparer interface {
	Prepare(context.Context, httpprepare.Process) error
}

// StartContainer prepares the final init root before containerd/CRI task.Start.
// It changes no cgroup attribution and never fails workload startup. The NRI
// observer must run in the node PID/mount view used by the existing deployment.
func (o *Observer) StartContainer(ctx context.Context, pod *nriapi.PodSandbox, container *nriapi.Container) error {
	if container == nil || container.GetPid() == 0 || o.preparation == nil {
		return nil
	}
	event := NormalizeCreateContainer(pod, container)
	_, eligible := stagingDecisionForCreateContainer(o.provider, event)
	if !eligible {
		return nil
	}
	if err := o.preparation.Prepare(ctx, httpprepare.Process{PID: int(container.GetPid())}); err != nil && o.logger != nil {
		o.logger.WarnContext(ctx, "nri_http_preparation_incomplete", "container_id", container.GetId(), "error", err)
	}
	return nil
}
