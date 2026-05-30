package rule

// PredefinedLists holds rule-set-defined lists after lowercasing and NFC
// normalization. It is rule data, not a CEL list<T> value, and lives in the
// rule domain package so rule resolution and CEL engine can both depend on it
// without forming a cycle.
type PredefinedLists map[string][]string

// NormalizePredefinedLists deep-copies predefined lists and lowercases plus
// NFC-normalizes every value.
func NormalizePredefinedLists(lists map[string][]string) PredefinedLists {
	if len(lists) == 0 {
		return PredefinedLists{}
	}
	out := make(PredefinedLists, len(lists))
	for key, values := range lists {
		normalized := make([]string, 0, len(values))
		for _, value := range values {
			normalized = append(normalized, NormalizeString(value))
		}
		out[key] = normalized
	}
	return out
}
