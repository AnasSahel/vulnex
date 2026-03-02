package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

type yamlFormatter struct{}

// toYAML converts any JSON-serializable value to a simple YAML representation.
// Uses JSON as an intermediate format to avoid adding a YAML dependency.
func toYAML(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	writeYAMLValue(w, obj, 0)
	return nil
}

func writeYAMLValue(w io.Writer, v interface{}, indent int) {
	prefix := strings.Repeat("  ", indent)

	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := val[k]
			switch child.(type) {
			case map[string]interface{}:
				fmt.Fprintf(w, "%s%s:\n", prefix, k)
				writeYAMLValue(w, child, indent+1)
			case []interface{}:
				fmt.Fprintf(w, "%s%s:\n", prefix, k)
				writeYAMLValue(w, child, indent+1)
			default:
				fmt.Fprintf(w, "%s%s: %s\n", prefix, k, formatYAMLScalar(child))
			}
		}
	case []interface{}:
		for _, item := range val {
			switch item.(type) {
			case map[string]interface{}, []interface{}:
				fmt.Fprintf(w, "%s-\n", prefix)
				writeYAMLValue(w, item, indent+1)
			default:
				fmt.Fprintf(w, "%s- %s\n", prefix, formatYAMLScalar(item))
			}
		}
	default:
		fmt.Fprintf(w, "%s%s\n", prefix, formatYAMLScalar(val))
	}
}

func formatYAMLScalar(v interface{}) string {
	if v == nil {
		return "null"
	}
	switch val := v.(type) {
	case string:
		if val == "" {
			return `""`
		}
		if strings.ContainsAny(val, ":#{}[]|>&*!%@`") || strings.Contains(val, "\n") {
			return fmt.Sprintf("%q", val)
		}
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", val)
	}
}

func (f *yamlFormatter) FormatCVE(w io.Writer, cve *model.EnrichedCVE) error {
	return toYAML(w, cve)
}

func (f *yamlFormatter) FormatCVEList(w io.Writer, cves []*model.EnrichedCVE) error {
	return toYAML(w, cves)
}

func (f *yamlFormatter) FormatKEVList(w io.Writer, entries []model.KEVEntry) error {
	return toYAML(w, entries)
}

func (f *yamlFormatter) FormatEPSSScores(w io.Writer, scores map[string]*model.EPSSScore) error {
	return toYAML(w, scores)
}

func (f *yamlFormatter) FormatAdvisory(w io.Writer, advisory *model.EnrichedAdvisory) error {
	return toYAML(w, advisory)
}

func (f *yamlFormatter) FormatAdvisories(w io.Writer, advisories []model.Advisory) error {
	return toYAML(w, advisories)
}

func (f *yamlFormatter) FormatCacheStats(w io.Writer, stats *cache.Stats) error {
	return toYAML(w, stats)
}
