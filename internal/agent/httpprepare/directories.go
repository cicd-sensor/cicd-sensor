package httpprepare

import (
	"path"
	"strings"
)

// BinDirectories selects a bounded set of absolute directories from runtime
// context. It never logs or retains the remaining environment or arguments.
func BinDirectories(args, environment []string) []string {
	var out []string
	if len(args) > 0 && path.IsAbs(args[0]) {
		out = append(out, path.Dir(args[0]))
	}
	for i, entry := range environment {
		if i >= 256 {
			break
		}
		if value, ok := strings.CutPrefix(entry, "PATH="); ok {
			if len(value) > 8192 {
				// Do not turn a truncated component into a different directory.
				prefix := value[:8192]
				end := strings.LastIndexByte(prefix, ':')
				if end < 0 {
					break
				}
				value = prefix[:end]
			}
			for dir := range strings.SplitSeq(value, ":") {
				if len(out) >= maxDirectories {
					return out
				}
				if path.IsAbs(dir) {
					out = append(out, dir)
				}
			}
			break
		}
	}
	return out
}
