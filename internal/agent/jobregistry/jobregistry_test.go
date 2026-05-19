package jobregistry_test

import (
	"context"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/managerauth"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

var testCtx = context.Background()

const testManagerToken = managerauth.TokenPrefix + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newJobRegistry(t *testing.T) *jobregistry.JobRegistry {
	t.Helper()
	return jobregistry.New(testLogger)
}

func registeredJob(jr *jobregistry.JobRegistry, identity jobcontext.JobIdentity) *job.Job {
	for _, j := range jr.All() {
		if j.Identity() == identity {
			return j
		}
	}
	return nil
}

func mustManagerClient(t *testing.T, baseURL string) *managerclient.ConfigClient {
	t.Helper()
	client, err := managerclient.NewConfigClient(testLogger, managerclient.Connection{
		BaseURL: baseURL,
		Token:   testManagerToken,
	})
	if err != nil {
		t.Fatalf("new manager client: %v", err)
	}
	return client
}

// slowFetcher holds a start flow inside manager config fetch, before the Job
// becomes visible. Tests use it to exercise duplicate-start barriers.
type slowFetcher struct {
	started chan struct{}
	release chan struct{}
}

func (f *slowFetcher) FetchConfig(ctx context.Context, _ *managerv1.FetchConfigRequest) (*managerclient.FetchResult, error) {
	close(f.started)
	select {
	case <-f.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &managerclient.FetchResult{}, nil
}
