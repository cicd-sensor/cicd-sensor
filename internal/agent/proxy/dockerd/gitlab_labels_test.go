package dockerd

import (
	"strings"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
)

func TestJobIdentityFromGitLabRunnerLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		labels    map[string]string
		want      jobcontext.JobIdentity
		wantErr   bool
		errSubstr string
	}{
		{
			name: "complete labels yield gitlab identity",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/cicd-sensor/cicd-sensor-testing/-/jobs/14202203981",
				gitLabRunnerJobIDLabel:  "14202203981",
			},
			want: jobcontext.GitLabJobIdentity("gitlab.com", "cicd-sensor/cicd-sensor-testing", "14202203981"),
		},
		{
			name: "self-hosted host with subgroup",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.example.com/group/sub/project/-/jobs/42",
				gitLabRunnerJobIDLabel:  "42",
			},
			want: jobcontext.GitLabJobIdentity("gitlab.example.com", "group/sub/project", "42"),
		},
		{
			name: "deeply nested subgroups are preserved verbatim",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.example.com/top/sub1/sub2/sub3/project/-/jobs/123",
				gitLabRunnerJobIDLabel:  "123",
			},
			want: jobcontext.GitLabJobIdentity("gitlab.example.com", "top/sub1/sub2/sub3/project", "123"),
		},
		{
			name: "host is normalized to lower case",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://GitLab.Example.COM/group/project/-/jobs/7",
				gitLabRunnerJobIDLabel:  "7",
			},
			want: jobcontext.GitLabJobIdentity("gitlab.example.com", "group/project", "7"),
		},
		{
			name:      "nil labels rejected",
			labels:    nil,
			wantErr:   true,
			errSubstr: "labels are required",
		},
		{
			name: "missing job url label rejected",
			labels: map[string]string{
				gitLabRunnerJobIDLabel: "42",
			},
			wantErr:   true,
			errSubstr: "job.url",
		},
		{
			name: "missing job id label rejected",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/g/p/-/jobs/42",
			},
			wantErr:   true,
			errSubstr: "job.id",
		},
		{
			name: "url without /-/jobs/ segment rejected",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/group/project/pipelines/100",
				gitLabRunnerJobIDLabel:  "42",
			},
			wantErr:   true,
			errSubstr: "unsupported job URL path",
		},
		{
			name: "url with empty project path rejected",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/-/jobs/42",
				gitLabRunnerJobIDLabel:  "42",
			},
			wantErr:   true,
			errSubstr: "empty project path",
		},
		{
			name: "url with empty job id rejected",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/g/p/-/jobs/",
				gitLabRunnerJobIDLabel:  "42",
			},
			wantErr:   true,
			errSubstr: "empty job id",
		},
		{
			name: "url job id mismatch with label job id rejected",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/g/p/-/jobs/100",
				gitLabRunnerJobIDLabel:  "200",
			},
			wantErr:   true,
			errSubstr: "does not match",
		},
		{
			name: "non-numeric job id rejected by Validate",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/g/p/-/jobs/abc",
				gitLabRunnerJobIDLabel:  "abc",
			},
			wantErr:   true,
			errSubstr: "positive integer",
		},
		{
			name: "unparseable url rejected",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "://bad",
				gitLabRunnerJobIDLabel:  "1",
			},
			wantErr:   true,
			errSubstr: "parse",
		},
		{
			name: "url with no host rejected",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https:///g/p/-/jobs/1",
				gitLabRunnerJobIDLabel:  "1",
			},
			wantErr:   true,
			errSubstr: "no host",
		},
		{
			name: "trailing slash on job id is tolerated and matched",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/g/p/-/jobs/42/",
				gitLabRunnerJobIDLabel:  "42",
			},
			want: jobcontext.GitLabJobIdentity("gitlab.com", "g/p", "42"),
		},
		{
			name: "query and fragment are ignored",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/g/p/-/jobs/42?foo=bar#trace",
				gitLabRunnerJobIDLabel:  "42",
			},
			want: jobcontext.GitLabJobIdentity("gitlab.com", "g/p", "42"),
		},
		{
			name: "extra job url path segment rejected",
			labels: map[string]string{
				gitLabRunnerJobURLLabel: "https://gitlab.com/g/p/-/jobs/42/extra",
				gitLabRunnerJobIDLabel:  "42",
			},
			wantErr:   true,
			errSubstr: "unsupported job URL path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jobIdentityFromGitLabLabels(tc.labels)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got nil err, want error containing %q", tc.errSubstr)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("identity: got %+v, want %+v", got, tc.want)
			}
		})
	}
}
