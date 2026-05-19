package jobevent

import (
	"fmt"
	"strings"
)

const (
	argvDisplayLimit = 12
	redactedMarker   = "<redacted>"
)

var tokenFlagPrefixes = []string{
	"--token",
	"--pass",
	"--secret",
	"--api",
	"--key",
	"--auth",
	"--header",
	"-p",
	"-t",
	"-H",
}

var tokenSubstringsLower = []string{
	"token",
	"pass",
	"key",
	"auth",
	"secret",
	"cred",
	"bearer ",
	"akia",
	"asia",
	"aiza",
	"gocspx-",
	"ghp_",
	"gho_",
	"ghu_",
	"ghs_",
	"ghr_",
	"github_pat_",
	"glpat-",
	"glptt-",
}

func RedactArgvForOutput(argv []string) []string {
	if argv == nil {
		return nil
	}
	out := make([]string, len(argv))
	for i, item := range argv {
		var prev string
		if i > 0 {
			prev = argv[i-1]
		}
		out[i] = redactArgvItem(item, prev)
	}
	return out
}

func RedactProcessSummaryForOutput(ps ProcessSummary) ProcessSummary {
	out := ProcessSummary{
		PID:           ps.PID,
		StartBoottime: ps.StartBoottime,
		ExecPath:      ps.ExecPath,
		Argv:          RedactArgvForOutput(ps.Argv),
	}
	if len(ps.Ancestors) > 0 {
		out.Ancestors = make([]AncestorProcess, len(ps.Ancestors))
		for i, anc := range ps.Ancestors {
			out.Ancestors[i] = AncestorProcess{
				ExecPath: anc.ExecPath,
				Argv:     RedactArgvForOutput(anc.Argv),
			}
		}
	}
	return out
}

func redactArgvItem(item, prev string) string {
	baseline := item
	if len(item) > argvDisplayLimit {
		baseline = item[:argvDisplayLimit] + truncationSuffix(len(item))
	}
	if matchesTokenFlagPrefix(prev) {
		return redactedMarker
	}
	if containsTokenSubstring(item) {
		return redactedMarker
	}
	return baseline
}

func truncationSuffix(n int) string {
	return fmt.Sprintf("<truncated, %d bytes>", n)
}

func matchesTokenFlagPrefix(prev string) bool {
	if prev == "" {
		return false
	}
	for _, p := range tokenFlagPrefixes {
		if strings.HasPrefix(prev, p) {
			return true
		}
	}
	return false
}

func containsTokenSubstring(item string) bool {
	if item == "" {
		return false
	}
	lower := strings.ToLower(item)
	for _, p := range tokenSubstringsLower {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
