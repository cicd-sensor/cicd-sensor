package httpprepare

import (
	"slices"
	"strings"
	"testing"
)

func TestBinDirectories(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		args, env, want []string
	}{
		{"empty context", nil, nil, nil},
		{"absolute command and PATH only", []string{"/tools/gh", "secret"}, []string{"TOKEN=secret", "PATH=.:/usr/bin:relative:/tools/bin:"}, []string{"/tools", "/usr/bin", "/tools/bin"}},
		{"relative command is not a root path", []string{"gh"}, nil, nil},
		{"oversized component is not invented", nil, []string{"PATH=/safe:/" + strings.Repeat("x", 8192)}, []string{"/safe"}},
		{"single oversized component is ignored", nil, []string{"PATH=/" + strings.Repeat("x", 8192)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := BinDirectories(tc.args, tc.env); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
