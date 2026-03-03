package output

import (
	"fmt"
	"io"

	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

// Formatter defines the interface for rendering CVE data in different output formats.
type Formatter interface {
	FormatCVE(w io.Writer, cve *model.EnrichedCVE) error
	FormatCVEList(w io.Writer, cves []*model.EnrichedCVE) error
	FormatKEVList(w io.Writer, entries []model.KEVEntry) error
	FormatEPSSScores(w io.Writer, scores map[string]*model.EPSSScore) error
	FormatAdvisory(w io.Writer, advisory *model.EnrichedAdvisory) error
	FormatAdvisories(w io.Writer, advisories []model.Advisory) error
	FormatSBOMResult(w io.Writer, result *model.SBOMResult) error
	FormatSBOMDiffResult(w io.Writer, result *model.SBOMDiffResult) error
	FormatCacheStats(w io.Writer, stats *cache.Stats) error
}

// formatterOpts holds configuration shared across all formatters.
type formatterOpts struct {
	NoColor bool
	Compact bool     // for JSON compact mode
	Fields  []string // for CSV field selection
	Long    bool     // show full descriptions instead of truncated
}

// FormatterOption is a functional option for configuring formatters.
type FormatterOption func(*formatterOpts)

// WithNoColor disables color output (primarily affects table formatter).
func WithNoColor() FormatterOption {
	return func(o *formatterOpts) {
		o.NoColor = true
	}
}

// WithCompact enables compact output (primarily affects JSON formatter).
func WithCompact() FormatterOption {
	return func(o *formatterOpts) {
		o.Compact = true
	}
}

// WithLong enables full-length descriptions instead of truncated output.
func WithLong() FormatterOption {
	return func(o *formatterOpts) {
		o.Long = true
	}
}

// WithFields sets the fields to include in the output (primarily affects CSV formatter).
func WithFields(fields []string) FormatterOption {
	return func(o *formatterOpts) {
		o.Fields = fields
	}
}

// NewFormatter creates a new Formatter for the given format string.
// Supported formats: "table", "json", "csv", "markdown", "yaml".
func NewFormatter(format string, opts ...FormatterOption) (Formatter, error) {
	o := &formatterOpts{}
	for _, opt := range opts {
		opt(o)
	}

	switch format {
	case "table":
		return newTableFormatter(o), nil
	case "json":
		return newJSONFormatter(o), nil
	case "csv":
		return newCSVFormatter(o), nil
	case "markdown", "md":
		return &markdownFormatter{}, nil
	case "yaml":
		return &yamlFormatter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %q (supported: table, json, csv, markdown, yaml)", format)
	}
}

// NewTemplateFormatter creates a formatter using a Go template string.
func NewTemplateFormatter(tmpl string) Formatter {
	return newTemplateFormatter(tmpl)
}
