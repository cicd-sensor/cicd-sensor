// Package report renders derived artifacts from project result documents.
//
// HTML is self-contained so GitHub Actions can preview it as a plain artifact.
// The page reads the embedded JSON document's snake_case fields directly.
package report

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
	"strings"

	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

//go:embed report.tmpl.html
var tmplSrc string

//go:embed logo.svg
var logoSVG string

// Non-default delimiters avoid collisions with JavaScript object literals.
var tmpl = template.Must(template.New("report").Delims("<<{", "}>>").Parse(tmplSrc))

// Render writes a single self-contained HTML report for log to w.
func Render(w io.Writer, log *resultdoc.JobEventSummaryForReport) error {
	js, err := json.Marshal(log)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, struct {
		Title string
		JSON  string
		Logo  template.HTML
	}{Title: reportTitle(log), JSON: string(js), Logo: template.HTML(logoSVG)})
}

func reportTitle(log *resultdoc.JobEventSummaryForReport) string {
	if log == nil {
		return "cicd-sensor report"
	}
	parts := make([]string, 0, 2)
	if !log.GeneratedAt.IsZero() {
		parts = append(parts, log.GeneratedAt.UTC().Format("2006-01-02"))
	}
	if projectPath := strings.TrimSpace(log.JobIdentity.ProjectPath); projectPath != "" {
		parts = append(parts, projectPath)
	}
	if len(parts) == 0 {
		return "cicd-sensor report"
	}
	return strings.Join(parts, " ") + " - cicd-sensor"
}
