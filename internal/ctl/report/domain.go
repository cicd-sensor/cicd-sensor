package report

import "golang.org/x/net/idna"

// displayDomain is a *visual-spoofing* mitigation, not an XSS / code-exec
// defense. XSS is already handled by html/template's auto-escape and the
// HTML report's textContent-only JS. The risk this addresses is human
// reviewers being deceived by IDN homograph attacks (e.g., Cyrillic `а` vs
// Latin `a`): we force the observed domain through IDNA so a homograph
// surfaces as a visible `xn--…` Punycode label in the report. Falls back
// to the raw input when IDNA cannot process the string.
func displayDomain(s string) string {
	if s == "" {
		return s
	}
	out, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return s
	}
	return out
}
