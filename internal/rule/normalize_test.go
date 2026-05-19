package rule_test

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

func TestNormalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "lowercases ascii", input: "/USR/BIN/BASH", want: "/usr/bin/bash"},
		{name: "normalizes unicode nfc", input: "CAFE\u0301", want: "café"},
		{name: "keeps already normalized string", input: "registry.npmjs.org", want: "registry.npmjs.org"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := rule.NormalizeString(tt.input); got != tt.want {
				t.Fatalf("NormalizeString(%q): got %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizePredefinedLists(t *testing.T) {
	t.Parallel()

	got := rule.NormalizePredefinedLists(map[string][]string{
		"domains": {"EXAMPLE.COM", "CAFE\u0301.example"},
	})
	want := []string{"example.com", "café.example"}
	if len(got) != 1 {
		t.Fatalf("list count: got %d, want 1", len(got))
	}
	for i := range want {
		if got["domains"][i] != want[i] {
			t.Fatalf("domains[%d]: got %q, want %q", i, got["domains"][i], want[i])
		}
	}

	got["domains"][0] = "mutated"
	again := rule.NormalizePredefinedLists(map[string][]string{"domains": {"EXAMPLE.COM"}})
	if again["domains"][0] != "example.com" {
		t.Fatalf("NormalizePredefinedLists should return an independent copy, got %#v", again)
	}
}

func TestNormalizePredefinedListsEmpty(t *testing.T) {
	t.Parallel()

	if got := rule.NormalizePredefinedLists(nil); len(got) != 0 {
		t.Fatalf("nil lists: got %#v, want empty map", got)
	}
}
