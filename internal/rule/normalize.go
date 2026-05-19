package rule

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// NormalizeString lowercases and NFC-normalizes strings used in rule evaluation.
// CEL input values, predefined list values, and ordinary CEL string literals
// all use this same normalization contract.
func NormalizeString(s string) string {
	return norm.NFC.String(strings.ToLower(s))
}
