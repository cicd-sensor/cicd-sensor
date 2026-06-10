//go:build !linux

package jobregistry

import (
	"context"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func (jr *JobRegistry) bindPodCgroupTreeForProcess(context.Context, jobcontext.JobIdentity, int32) {
}
