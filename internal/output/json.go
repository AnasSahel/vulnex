package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

// jsonFormatter renders data as JSON output.
type jsonFormatter struct {
	compact bool
}

func newJSONFormatter(opts *formatterOpts) *jsonFormatter {
	return &jsonFormatter{
		compact: opts.Compact,
	}
}

// marshal encodes a value as JSON, using indentation for pretty-print
// unless compact mode is enabled.
func (jf *jsonFormatter) marshal(v interface{}) ([]byte, error) {
	if jf.compact {
		return json.Marshal(v)
	}
	return json.MarshalIndent(v, "", "  ")
}

// FormatCVE renders a single enriched CVE as JSON.
func (jf *jsonFormatter) FormatCVE(w io.Writer, cve *model.EnrichedCVE) error {
	data, err := jf.marshal(cve)
	if err != nil {
		return fmt.Errorf("marshaling CVE to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatCVEList renders a list of enriched CVEs as a JSON array.
func (jf *jsonFormatter) FormatCVEList(w io.Writer, cves []*model.EnrichedCVE) error {
	data, err := jf.marshal(cves)
	if err != nil {
		return fmt.Errorf("marshaling CVE list to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatKEVList renders a list of KEV entries as a JSON array.
func (jf *jsonFormatter) FormatKEVList(w io.Writer, entries []model.KEVEntry) error {
	data, err := jf.marshal(entries)
	if err != nil {
		return fmt.Errorf("marshaling KEV list to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatEPSSScores renders EPSS scores as a JSON object keyed by CVE ID.
func (jf *jsonFormatter) FormatEPSSScores(w io.Writer, scores map[string]*model.EPSSScore) error {
	data, err := jf.marshal(scores)
	if err != nil {
		return fmt.Errorf("marshaling EPSS scores to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatAdvisory renders a single enriched advisory as JSON.
func (jf *jsonFormatter) FormatAdvisory(w io.Writer, advisory *model.EnrichedAdvisory) error {
	data, err := jf.marshal(advisory)
	if err != nil {
		return fmt.Errorf("marshaling advisory to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatAdvisories renders advisory data as a JSON array.
func (jf *jsonFormatter) FormatAdvisories(w io.Writer, advisories []model.Advisory) error {
	data, err := jf.marshal(advisories)
	if err != nil {
		return fmt.Errorf("marshaling advisories to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatSBOMResult renders SBOM check results as JSON.
func (jf *jsonFormatter) FormatSBOMResult(w io.Writer, result *model.SBOMResult) error {
	data, err := jf.marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling SBOM result to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatSBOMDiffResult renders SBOM diff results as JSON.
func (jf *jsonFormatter) FormatSBOMDiffResult(w io.Writer, result *model.SBOMDiffResult) error {
	data, err := jf.marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling SBOM diff result to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatExploitResult renders a single exploit result as JSON.
func (jf *jsonFormatter) FormatExploitResult(w io.Writer, result *model.ExploitResult) error {
	data, err := jf.marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling exploit result to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatExploitResults renders multiple exploit results as a JSON array.
func (jf *jsonFormatter) FormatExploitResults(w io.Writer, results []*model.ExploitResult) error {
	data, err := jf.marshal(results)
	if err != nil {
		return fmt.Errorf("marshaling exploit results to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// FormatCVEHistory renders CVE history as JSON (same as FormatCVE).
func (jf *jsonFormatter) FormatCVEHistory(w io.Writer, cve *model.EnrichedCVE) error {
	return jf.FormatCVE(w, cve)
}

// FormatCacheStats renders cache statistics as JSON.
func (jf *jsonFormatter) FormatCacheStats(w io.Writer, stats *cache.Stats) error {
	data, err := jf.marshal(stats)
	if err != nil {
		return fmt.Errorf("marshaling cache stats to JSON: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
