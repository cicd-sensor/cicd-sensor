package report_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/ctl/report"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

func renderString(t *testing.T, log *resultdoc.JobEventSummaryForReport) string {
	t.Helper()

	var buf bytes.Buffer
	if err := report.Render(&buf, log); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.String()
}

func embeddedJSONFragment(fragment string) string {
	return strings.ReplaceAll(fragment, `"`, `\"`)
}

func sampleResultLog() resultdoc.JobEventSummaryForReport {
	return resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity(
			"github.com", "acme/example", "123", "build", "1", "runner-1",
		),
		Metadata:       jobcontext.JobMetadata{},
		RunnerType:     "machine",
		StartedAt:      time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
		GeneratedAt:    time.Date(2026, 4, 30, 12, 5, 0, 0, time.UTC),
		FinalizeReason: "shutdown",
		ResultSummary: resultdoc.ResultSummary{
			Result:    resultdoc.ResultDetected,
			HitsCount: 1,
		},
		NetworkConnections: []resultdoc.NetworkConnection{{
			RemoteIP:   "8.8.8.8",
			RemotePort: 443,
			Protocol:   "tcp",
			Processes:  []resultdoc.ObservationProcess{{PID: 42, ExecPath: "/usr/bin/curl"}},
		}},
		DomainObservations: []resultdoc.DomainObservation{{
			Domain:    "dns.google",
			Processes: []resultdoc.ObservationProcess{{PID: 43, ExecPath: "/usr/bin/dig"}},
		}},
		Hits: []resultdoc.HitRecord{
			{
				RulesetID: "set",
				RuleID:    "curl-egress",
				RuleName:  "curl egress",
				Action:    "detect",
				Timestamp: time.Date(2026, 4, 30, 12, 3, 0, 0, time.UTC),
			},
		},
	}
}

func TestRender_HappyPath(t *testing.T) {
	t.Parallel()

	log := &resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity(
			"github.com", "acme/example", "123", "build", "1", "runner-1",
		),
		Metadata:    jobcontext.JobMetadata{},
		StartedAt:   time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
		GeneratedAt: time.Date(2026, 4, 30, 12, 5, 0, 0, time.UTC),
		ResultSummary: resultdoc.ResultSummary{
			Result:    resultdoc.ResultDetected,
			HitsCount: 1,
		},
		NetworkConnections: []resultdoc.NetworkConnection{{
			RemoteIP:   "1.1.1.1",
			RemotePort: 443,
			Protocol:   "tcp",
			Processes:  []resultdoc.ObservationProcess{{PID: 42, ExecPath: "/usr/bin/curl"}},
		}},
		DomainObservations: []resultdoc.DomainObservation{{
			Domain:    "dns.google",
			Processes: []resultdoc.ObservationProcess{{PID: 43, ExecPath: "/usr/bin/dig"}},
		}},
		Hits: []resultdoc.HitRecord{{
			Timestamp: time.Date(2026, 4, 30, 12, 3, 0, 0, time.UTC),
			RulesetID: "set",
			RuleID:    "curl-egress",
			RuleName:  "curl egress",
			RuleType:  "event",
			RuleCondition: `process.exec_path.endsWith("/curl") &&
remote_ip == "1.1.1.1"`,
			Action:    "detect",
			EventType: "network_connect",
			Process: &resultdoc.ProcessSummary{
				PID:      42,
				ExecPath: "/usr/bin/curl",
				Argv:     []string{"curl", "-X", "POST", "https://1.1.1.1"},
				Ancestors: []resultdoc.AncestorProcess{
					{ExecPath: "/bin/bash"},
					{ExecPath: "/sbin/init"},
				},
			},
		}},
	}

	html := renderString(t, log)

	for _, want := range []string{
		"<!doctype html>",
		"window.REPORT_DATA",
		"JSON.parse(",
		"2026-04-30 acme/example - cicd-sensor",
		"time (UTC)",
		"rule",
		"payload",
		"process",
		"proto",
		"netgrid",
		"domgrid",
		"connDetail",
		`<template id="cicd-sensor-logo"><svg`,
		`fill="#019f5f"`,
		"data-search",
		// embedded JSON pieces
		embeddedJSONFragment(`"ruleset_id":"set"`),
		embeddedJSONFragment(`"rule_id":"curl-egress"`),
		embeddedJSONFragment(`"curl egress"`),
		embeddedJSONFragment(`"rule_type":"event"`),
		`process.exec_path.endsWith(\\\"/curl\\\")`,
		`remote_ip == \\\"1.1.1.1\\\"`,
		embeddedJSONFragment(`"event_type":"network_connect"`),
		embeddedJSONFragment(`"action":"detect"`),
		embeddedJSONFragment(`"/usr/bin/curl"`),
		embeddedJSONFragment(`"1.1.1.1"`),
		embeddedJSONFragment(`"protocol":"tcp"`),
		embeddedJSONFragment(`"/usr/bin/dig"`),
		embeddedJSONFragment(`"acme/example"`),
		embeddedJSONFragment(`"github.com"`),
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in HTML output", want)
		}
	}
	for _, forbidden := range []string{
		"External endpoints",
		"EXT",
		"PROTO",
		"unique binaries",
		"return 'file';",
		"return 'network';",
		"text: 'Condition'",
	} {
		if strings.Contains(html, forbidden) {
			t.Errorf("unexpected legacy report label %q in HTML output", forbidden)
		}
	}
}

func TestRender_CorrelationHitShowsRuleMetadataForDetail(t *testing.T) {
	t.Parallel()

	log := &resultdoc.JobEventSummaryForReport{
		JobIdentity:   jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "r"),
		ResultSummary: resultdoc.ResultSummary{Result: resultdoc.ResultDetected, HitsCount: 1},
		Hits: []resultdoc.HitRecord{{
			Timestamp:     time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
			RulesetID:     "ci-invariant",
			RuleID:        "literal_ipv4_egress_burst",
			RuleName:      "literal ipv4 egress burst",
			RuleType:      "correlation",
			RuleCondition: "rule.first.total_count >= 1 && rule.second.total_count >= 1",
			Action:        "detect",
			EventType:     "network_connect",
		}},
	}

	html := renderString(t, log)
	for _, want := range []string{
		embeddedJSONFragment(`"rule_type":"correlation"`),
		embeddedJSONFragment(`"rule_condition":`),
		"rule.first.total_count",
		"rule.second.total_count",
		embeddedJSONFragment(`"event_type":"network_connect"`),
		"typeLabel = isCorr ? 'correlation'",
		"ruleCondNode(h.rule_condition, true)",
		"row('event_type', codeVal(h.event_type))",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in HTML output", want)
		}
	}
}

func TestRender_AncestorArgvEmbedded(t *testing.T) {
	t.Parallel()

	log := &resultdoc.JobEventSummaryForReport{
		JobIdentity:   jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "r"),
		ResultSummary: resultdoc.ResultSummary{Result: resultdoc.ResultDetected, HitsCount: 1},
		Hits: []resultdoc.HitRecord{{
			RulesetID: "set",
			RuleID:    "curl",
			Action:    "detect",
			Timestamp: time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
			Process: &resultdoc.ProcessSummary{
				ExecPath: "/usr/bin/curl",
				Argv:     []string{"curl", "https://example.com"},
				Ancestors: []resultdoc.AncestorProcess{
					{ExecPath: "/bin/bash", Argv: []string{"bash", "-c", "curl https://example.com"}},
					{ExecPath: "/sbin/init"},
				},
			},
		}},
	}

	html := renderString(t, log)

	// Ancestor argv flows through the embedded JSON; the JSX reads it at
	// runtime to populate the lineage row in the detection detail view.
	for _, want := range []string{
		embeddedJSONFragment(`"/bin/bash"`),
		embeddedJSONFragment(`"bash"`),
		embeddedJSONFragment(`"-c"`),
		embeddedJSONFragment(`"curl https://example.com"`),
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in HTML JSON, got:\n%s", want, html)
		}
	}
}

func TestRender_ObservationProcessContextUsesPathsOnly(t *testing.T) {
	t.Parallel()

	log := &resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "r"),
		NetworkConnections: []resultdoc.NetworkConnection{{
			RemoteIP: "203.0.113.10",
			Processes: []resultdoc.ObservationProcess{{
				PID:      42,
				ExecPath: "/usr/bin/curl",
				Ancestors: []resultdoc.ObservationAncestorProcess{{
					ExecPath: "/bin/bash",
				}},
			}},
		}},
		DomainObservations: []resultdoc.DomainObservation{{
			Domain: "example.com",
			Processes: []resultdoc.ObservationProcess{{
				PID:      43,
				ExecPath: "/usr/bin/dig",
			}},
		}},
	}

	html := renderString(t, log)
	if !strings.Contains(html, "/usr/bin/curl") || !strings.Contains(html, "/usr/bin/dig") || !strings.Contains(html, "/bin/bash") {
		t.Fatalf("observation process paths should remain in report HTML")
	}
}

func TestRender_NetworkIPv6PortDataIsEmbedded(t *testing.T) {
	t.Parallel()

	log := &resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "r"),
		NetworkConnections: []resultdoc.NetworkConnection{{
			RemoteIP:   "2606:4700::6810:122",
			RemotePort: 443,
			Protocol:   "udp",
		}},
	}

	html := renderString(t, log)
	for _, want := range []string{
		embeddedJSONFragment(`"remote_ip":"2606:4700::6810:122"`),
		embeddedJSONFragment(`"remote_port":443`),
		embeddedJSONFragment(`"protocol":"udp"`),
		"text: 'remote'",
		"text: 'port'",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in HTML output", want)
		}
	}
}

func TestRender_HTMLReportInteractionAffordances(t *testing.T) {
	t.Parallel()

	log := sampleResultLog()
	html := renderString(t, &log)
	for _, want := range []string{
		"IntersectionObserver",
		"function setActiveSection(id)",
		"scrollIntoView",
		"row.setAttribute('role', 'button')",
		"row.setAttribute('tabindex', '0')",
		"row.addEventListener('keydown'",
		":focus-visible",
		"content: '›'",
		"overflow-wrap: anywhere",
		"word-break: break-all",
		"white-space: normal",
		"minmax(0, 320px)",
		"minmax(0, 240px)",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected report interaction/wrapping affordance %q in HTML output", want)
		}
	}
}

func TestRender_EmptySectionsShowFallbackMessages(t *testing.T) {
	t.Parallel()

	html := renderString(t, &resultdoc.JobEventSummaryForReport{})
	for _, want := range []string{
		"No rule matches in this job.",
		"No resolved domains observed.",
		"No network connections observed.",
		"class: 'empty-state'",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected empty-section fallback %q in HTML output", want)
		}
	}
}

func TestRender_TopbarVerdictAndLogoStyles(t *testing.T) {
	t.Parallel()

	log := sampleResultLog()
	html := renderString(t, &log)
	for _, want := range []string{
		"function verdictClass(result)",
		"return 'no-alert'",
		"class: 'topbar-verdict ' + verdictClass",
		".topbar-verdict.detected",
		".topbar-verdict.terminated",
		".topbar-logo { color: var(--green); width: 42px; height: 42px;",
		".topbar-logo svg { width: 42px; height: 42px;",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected topbar verdict/logo marker %q in HTML output", want)
		}
	}
}

func TestRender_TruncationMarkerEmbedded(t *testing.T) {
	t.Parallel()

	log := &resultdoc.JobEventSummaryForReport{
		JobIdentity:   jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "r"),
		ResultSummary: resultdoc.ResultSummary{Result: resultdoc.ResultDetected, HitsCount: 1},
		Hits: []resultdoc.HitRecord{{
			RulesetID:       "set",
			RuleID:          "curl",
			Action:          "detect",
			Timestamp:       time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
			AlertTruncation: resultdoc.AlertTruncationMaxAlertsReached,
			AlertCap:        3,
			AlertDropped:    7,
		}},
	}

	html := renderString(t, log)

	// The truncation marker travels through the embedded JSON; the JSX
	// reads it at runtime to render the warning row.
	for _, want := range []string{
		embeddedJSONFragment(`"alert_dropped":7`),
		embeddedJSONFragment(`"alert_cap":3`),
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in HTML JSON, got:\n%s", want, html)
		}
	}
}

func TestRender_EscapesUntrustedReportData(t *testing.T) {
	t.Parallel()

	breakout := `</script><script>alert("xss")</script><img src=x onerror=alert(1)>`
	commentBreakout := `<!--</script><script>alert("comment")</script>-->`
	lineSeparators := "line\u2028separator\u2029paragraph"
	log := &resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity(
			"github.com", "acme/"+breakout, "run-"+breakout, "job", "1", "runner",
		),
		Metadata: jobcontext.JobMetadata{
			CommitSHA:         breakout,
			RefName:           commentBreakout,
			Trigger:           lineSeparators,
			ActorName:         `attacker@example.com`,
			GitHubWorkflowRef: `refs/heads/feature<script>`,
			GitHubWorkflowSHA: `sha&value`,
			GitHubWorkflow:    `workflow "quoted"`,
		},
		ResultSummary: resultdoc.ResultSummary{Result: resultdoc.ResultDetected, HitsCount: 1},
		NetworkConnections: []resultdoc.NetworkConnection{{
			RemoteIP:   `10.0.0.1"><svg/onload=alert(1)>`,
			RemotePort: 443,
			Protocol:   "tcp",
			Processes: []resultdoc.ObservationProcess{{
				PID:      55,
				ExecPath: `/usr/bin/curl"><svg/onload=alert(1)>`,
			}},
		}},
		DomainObservations: []resultdoc.DomainObservation{{
			Domain: `evil.example</script><script>alert(1)</script>`,
			Processes: []resultdoc.ObservationProcess{{
				PID:      56,
				ExecPath: `/usr/bin/dig</script>`,
			}},
		}},
		Hits: []resultdoc.HitRecord{{
			Timestamp: time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
			RulesetID: `set<script>`,
			RuleID:    `rule</script>`,
			RuleName:  `name<img src=x onerror=alert(1)>`,
			Action:    "detect",
			EventType: "process_exec",
			Process: &resultdoc.ProcessSummary{
				PID:      100,
				ExecPath: `/tmp/evil"><script>alert(1)</script>`,
				Argv: []string{
					"node",
					breakout,
					lineSeparators,
				},
				Ancestors: []resultdoc.AncestorProcess{{
					ExecPath: `/bin/sh<script>`,
					Argv:     []string{"sh", "-c", commentBreakout},
				}},
			},
			Payload: map[string]any{
				"domain":  breakout,
				"comment": commentBreakout,
				"unicode": lineSeparators,
			},
		}},
	}

	html := renderString(t, log)

	for _, forbidden := range []string{
		breakout,
		commentBreakout,
		`<img src=x`,
		`<svg/onload`,
		lineSeparators,
	} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("HTML contains unescaped attacker-controlled string %q", forbidden)
		}
	}
	for _, want := range []string{
		`JSON.parse("`,
		`\\u003c/script\\u003e`,
		`\\u003cimg`,
		`\\u003c!--`,
		`\\u2028`,
		`\\u2029`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected escaped marker %q in HTML output", want)
		}
	}
}

func TestRender_DoesNotUseHTMLInjectionSinks(t *testing.T) {
	t.Parallel()

	html := renderString(t, &resultdoc.JobEventSummaryForReport{})

	for _, sink := range []string{
		".innerHTML",
		"insertAdjacentHTML",
		"document.write",
		"dangerouslySetInnerHTML",
	} {
		if strings.Contains(html, sink) {
			t.Errorf("HTML report uses DOM injection sink %q", sink)
		}
	}
}

// reportFailingWriter is a Writer that fails on the first byte so tests can
// verify Render surfaces writer errors. Kept distinct from the attestation
// test helper to avoid coupling the two test files.
type reportFailingWriter struct {
	err error
}

func (w reportFailingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRender_PropagatesWriterError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("write failed")
	log := &resultdoc.JobEventSummaryForReport{
		JobIdentity: jobcontext.GitHubJobIdentity(
			"github.com", "acme/example", "1", "build", "1", "runner",
		),
	}
	err := report.Render(reportFailingWriter{err: wantErr}, log)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Render: got %v, want wrapping %v", err, wantErr)
	}
}

func TestRender_ZeroValueLogProducesValidHTML(t *testing.T) {
	t.Parallel()

	html := renderString(t, &resultdoc.JobEventSummaryForReport{})

	// A zero-value document still gives the page enough structure to load:
	// the doctype, embedded data hook, and the no-input fallback title.
	for _, want := range []string{
		"<!doctype html>",
		"window.REPORT_DATA",
		"JSON.parse(",
		"cicd-sensor report",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in HTML output, got:\n%s", want, html[:min(len(html), 1024)])
		}
	}
}

func TestRender_TitleVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		log  *resultdoc.JobEventSummaryForReport
		want string
	}{
		{
			name: "both date and project path are emitted in the title",
			log: &resultdoc.JobEventSummaryForReport{
				JobIdentity: jobcontext.GitHubJobIdentity(
					"github.com", "acme/example", "1", "b", "1", "r",
				),
				GeneratedAt: time.Date(2026, 5, 9, 8, 15, 0, 0, time.UTC),
			},
			want: "2026-05-09 acme/example - cicd-sensor",
		},
		{
			name: "missing generated_at falls back to project-only title",
			log: &resultdoc.JobEventSummaryForReport{
				JobIdentity: jobcontext.GitHubJobIdentity(
					"github.com", "acme/example", "1", "b", "1", "r",
				),
			},
			want: "acme/example - cicd-sensor",
		},
		{
			name: "missing project path falls back to date-only title",
			log: &resultdoc.JobEventSummaryForReport{
				GeneratedAt: time.Date(2026, 5, 9, 23, 30, 0, 0, time.UTC),
			},
			want: "2026-05-09 - cicd-sensor",
		},
		{
			name: "zero-value document falls back to the package title",
			log:  &resultdoc.JobEventSummaryForReport{},
			want: "cicd-sensor report",
		},
		{
			name: "generated_at is rendered in UTC even when source carries an offset",
			log: &resultdoc.JobEventSummaryForReport{
				JobIdentity: jobcontext.GitHubJobIdentity(
					"github.com", "acme/example", "1", "b", "1", "r",
				),
				// 00:30 JST on the 10th -> 15:30 UTC on the 9th.
				GeneratedAt: time.Date(
					2026, 5, 10, 0, 30, 0, 0,
					time.FixedZone("JST", 9*60*60),
				),
			},
			want: "2026-05-09 acme/example - cicd-sensor",
		},
		{
			name: "whitespace-only project path is treated as missing",
			log: &resultdoc.JobEventSummaryForReport{
				JobIdentity: jobcontext.JobIdentity{ProjectPath: "   "},
				GeneratedAt: time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC),
			},
			want: "2026-05-09 - cicd-sensor",
		},
		{
			name: "gitlab identity also flows through the title",
			log: &resultdoc.JobEventSummaryForReport{
				JobIdentity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "1"),
				GeneratedAt: time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC),
			},
			want: "2026-05-09 group/project - cicd-sensor",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			html := renderString(t, tc.log)
			if !strings.Contains(html, "<title>"+tc.want+"</title>") {
				t.Fatalf("title not found: want <title>%s</title>", tc.want)
			}
		})
	}
}

func TestRender_HTMLTemplateEscapesJSONParseArgument(t *testing.T) {
	t.Parallel()

	log := &resultdoc.JobEventSummaryForReport{
		JobIdentity:   jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "r"),
		ResultSummary: resultdoc.ResultSummary{Result: resultdoc.ResultDetected},
		DomainObservations: []resultdoc.DomainObservation{{
			Domain: `x</script>x`,
		}},
	}

	html := renderString(t, log)
	if strings.Contains(html, `x</script>x`) {
		t.Fatalf("embedded JSON was not escaped as a JavaScript string")
	}
	if !strings.Contains(html, `x\\u003c/script\\u003ex`) && !strings.Contains(html, `x\u003c/script\u003ex`) {
		t.Fatalf("expected escaped script close marker in JSON.parse argument")
	}
}
