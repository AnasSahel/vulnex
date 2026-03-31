package cra

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	_ "embed"
)

//go:embed templates/report.html.tmpl
var reportTemplate string

// Render writes the CRA evidence pack to w in the requested format.
// Supported formats: "html" (default) and "json".
func Render(w io.Writer, report *Report, format string) error {
	if report == nil {
		return fmt.Errorf("report must not be nil")
	}
	if report.GeneratedAt == "" {
		report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	switch strings.ToLower(format) {
	case "json":
		return renderJSON(w, report)
	case "html", "":
		return renderHTML(w, report)
	default:
		return fmt.Errorf("unsupported format %q: use html or json", format)
	}
}

func renderHTML(w io.Writer, report *Report) error {
	tmpl, err := template.New("report").
		Option("missingkey=error").
		Funcs(template.FuncMap{
			"statusClass": statusClass,
			"statusLabel": statusLabel,
			"upper":       strings.ToUpper,
			"lower":       strings.ToLower,
		}).
		Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("parsing report template: %w", err)
	}
	return tmpl.Execute(w, report)
}

func renderJSON(w io.Writer, report *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// statusClass maps an AnnexI status to a CSS class name.
func statusClass(status string) string {
	switch status {
	case "covered":
		return "status-covered"
	case "partial":
		return "status-partial"
	case "not_covered":
		return "status-not-covered"
	case "manual_input":
		return "status-manual"
	default:
		return "status-unknown"
	}
}

// statusLabel maps an AnnexI status to a human-readable label.
func statusLabel(status string) string {
	switch status {
	case "covered":
		return "Covered"
	case "partial":
		return "Partial"
	case "not_covered":
		return "Not Covered"
	case "manual_input":
		return "Manual Input"
	default:
		return "Unknown"
	}
}
