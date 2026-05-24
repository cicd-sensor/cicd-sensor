package jobregistry

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1"
)

func TestStartManagerJobLogs_AttachesOnlyWhenOutputSettingsExist(t *testing.T) {
	jr := newTestJobRegistry()
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")

	withoutOutputSettings := jobscope.NewProject()
	jr.startManagerJobLogs(withoutOutputSettings, id, managerclient.Connection{})
	if withoutOutputSettings.ManagerJobLogsForTesting().HasWorkersForTesting() {
		t.Fatal("manager job logs attached without output settings")
	}

	withOutputSettings := jobscope.NewProject()
	withOutputSettings.OutputSettings = &managerv1.OutputSettings{
		SummaryLog: &managerv1.OutputSetting{Enabled: true},
	}
	jr.startManagerJobLogs(withOutputSettings, id, managerclient.Connection{
		BaseURL: "https://manager.example.test",
		Token:   "token",
	})
	if !withOutputSettings.ManagerJobLogsForTesting().HasWorkersForTesting() {
		t.Fatal("manager job logs were not attached")
	}
}
