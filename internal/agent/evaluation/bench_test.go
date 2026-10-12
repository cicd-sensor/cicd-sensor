package evaluation

// CEL evaluation microbenchmark using production rules from rules/.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

const productionRulesRelativePath = "../../../rules"

var benchEvalIdentity = jobcontext.GitHubJobIdentity(
	"github.com", "acme/example", "123", "build", "1", "runner-1",
)

func BenchmarkEvaluateFileOpen(b *testing.B) { runEvalBench(b, fileOpenBenchEvent()) }
func BenchmarkEvaluateFileOpenDeepLineage(b *testing.B) {
	runEvalBench(b, fileOpenDeepLineageBenchEvent())
}
func BenchmarkEvaluateProcessExec(b *testing.B)       { runEvalBench(b, processExecBenchEvent()) }
func BenchmarkEvaluateDomain(b *testing.B)            { runEvalBench(b, domainBenchEvent()) }
func BenchmarkEvaluateUnixSocketConnect(b *testing.B) { runEvalBench(b, unixSocketConnectBenchEvent()) }

func runEvalBench(b *testing.B, event jobevent.EventRecord) {
	b.Helper()

	host := setupHostScopeFromProductionRules(b)
	eval := NewEvaluationState(scopeResolvedRules(host), nil)
	activation := celengine.NewEventActivation(celengine.CELInputEvent{})

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		EvaluateEvent(testCtx, eval, event, benchEvalIdentity, jobcontext.JobMetadata{}, "machine", host, nil, testLogger, activation)
	}
}

func setupHostScopeFromProductionRules(tb testing.TB) *jobscope.JobScopeState {
	tb.Helper()

	scope := jobscope.NewHost()
	for _, source := range loadProductionRuleSources(tb) {
		scope.RuleSets = append(scope.RuleSets, source.RuleSets...)
		scope.RuleModifiers = append(scope.RuleModifiers, source.RuleModifiers...)
	}
	if len(scope.RuleSets) == 0 {
		tb.Fatalf("no rule sets loaded from %s", productionRulesRelativePath)
	}
	scope.ResolveRules(benchEvalIdentity)
	return scope
}

func loadProductionRuleSources(tb testing.TB) []rulesource.LoadedRules {
	tb.Helper()

	abs, err := filepath.Abs(productionRulesRelativePath)
	if err != nil {
		tb.Fatalf("resolve rules dir: %v", err)
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		tb.Fatalf("read rules dir %s: %v", abs, err)
	}

	out := make([]rulesource.LoadedRules, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !rulesource.IsRuleFileName(entry.Name()) {
			continue
		}
		loaded, err := rulesource.LoadRulesFile(filepath.Join(abs, entry.Name()))
		if err != nil {
			tb.Fatalf("load %s: %v", entry.Name(), err)
		}
		if err := loaded.Validate(); err != nil {
			tb.Fatalf("validate %s: %v", entry.Name(), err)
		}
		out = append(out, *loaded)
	}
	return out
}

var benchEventTime = time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC)

func fileOpenBenchEvent() jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.FileOpen,
		Timestamp: benchEventTime,
		Process: jobevent.ProcessSummary{
			PID:      4242,
			ExecPath: "/usr/bin/cc1",
			Argv:     []string{"cc1", "-o", "foo.o", "foo.c"},
		},
		Payload: map[string]any{
			"path":     "/usr/include/stdio.h",
			"is_read":  true,
			"is_write": false,
			"flags":    int64(0),
		},
		Tags: map[string]string{},
	}
}

// fileOpenDeepLineageBenchEvent mirrors the p90 shape of a GitHub-hosted
// build job (nginx-build, #200): 11 ancestors and ~180 argv strings in
// total. The shallow fileOpenBenchEvent hides any cost that grows with
// lineage depth, which is where the event worker was starving.
func fileOpenDeepLineageBenchEvent() jobevent.EventRecord {
	event := fileOpenBenchEvent()
	event.Process.Argv = []string{
		"cc1", "-quiet", "-I", ".", "-I", "include", "-I", "apps/include", "-I", "providers/common/include",
		"-D", "OPENSSL_BUILDING_OPENSSL", "-D", "NDEBUG", "-D", "AES_ASM", "-D", "ECP_NISTZ256_ASM",
	}
	chain := []string{
		"/usr/bin/gcc", "/bin/sh", "/usr/bin/make", "/bin/sh", "/usr/bin/make", "/bin/bash",
		"/home/runner/work/nginx-build/nginx-build", "/bin/bash",
		"/home/runner/actions-runner/cached/2.337.0/bin/Runner.Worker",
		"/home/runner/actions-runner/cached/2.337.0/bin/Runner.Listener", "/usr/bin/bash",
	}
	event.Process.Ancestors = make([]jobevent.AncestorProcess, len(chain))
	for i, execPath := range chain {
		argv := make([]string, 0, 15)
		argv = append(argv, execPath)
		for j := 1; j < 15; j++ {
			argv = append(argv, "-D")
			argv = append(argv, "OPENSSL_SETTING_"+string(rune('A'+j)))
		}
		event.Process.Ancestors[i] = jobevent.AncestorProcess{ExecPath: execPath, Argv: argv[:15]}
	}
	return event
}

func processExecBenchEvent() jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.ProcessExec,
		Timestamp: benchEventTime,
		Process: jobevent.ProcessSummary{
			PID:      4242,
			ExecPath: "/usr/bin/cc1",
			Argv:     []string{"cc1", "-o", "foo.o", "foo.c"},
		},
		Payload: map[string]any{
			"is_memfd": false,
		},
		Tags: map[string]string{},
	}
}

func domainBenchEvent() jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.Domain,
		Timestamp: benchEventTime,
		Process: jobevent.ProcessSummary{
			PID:      4242,
			ExecPath: "/usr/bin/curl",
		},
		Payload: map[string]any{
			"domain": "registry.npmjs.org",
			"source": "udp",
		},
		Tags: map[string]string{},
	}
}

func unixSocketConnectBenchEvent() jobevent.EventRecord {
	return jobevent.EventRecord{
		EventType: jobevent.UnixSocketConnect,
		Timestamp: benchEventTime,
		Process: jobevent.ProcessSummary{
			PID:      4242,
			ExecPath: "/usr/bin/git",
		},
		Payload: map[string]any{
			"path":        "/run/user/1000/bus",
			"socket_type": "stream",
			"is_abstract": false,
		},
		Tags: map[string]string{},
	}
}
