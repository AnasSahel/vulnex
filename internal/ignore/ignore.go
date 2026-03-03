package ignore

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/trustin-tech/vulnex/internal/model"
	"gopkg.in/yaml.v3"
)

// Suppression represents a single suppression entry in a .vulnexignore file.
type Suppression struct {
	ID         string `yaml:"id"`
	Package    string `yaml:"package,omitempty"`
	Reason     string `yaml:"reason"`
	Expires    string `yaml:"expires,omitempty"`
	ApprovedBy string `yaml:"approved_by,omitempty"`
}

// File represents the parsed contents of a .vulnexignore file.
type File struct {
	Suppressions []Suppression `yaml:"suppressions"`
}

// Load reads and parses a .vulnexignore YAML file from the given path.
// If the file does not exist, it returns an empty File (not an error).
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &File{}, nil
		}
		return nil, err
	}

	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// Apply partitions findings into active and suppressed slices based on the
// suppression rules. Expired suppressions (expires < now) are ignored, leaving
// the finding active. Malformed expiry dates are treated as no-expiry (always
// suppresses).
func (f *File) Apply(findings []model.SBOMFinding, now time.Time) (active, suppressed []model.SBOMFinding) {
	if len(f.Suppressions) == 0 {
		return findings, nil
	}

	for _, finding := range findings {
		if f.isSuppressed(finding, now) {
			suppressed = append(suppressed, finding)
		} else {
			active = append(active, finding)
		}
	}
	return active, suppressed
}

// isSuppressed checks whether a finding matches any non-expired suppression.
func (f *File) isSuppressed(finding model.SBOMFinding, now time.Time) bool {
	for _, s := range f.Suppressions {
		if !strings.EqualFold(s.ID, finding.Advisory.ID) {
			continue
		}

		if s.Package != "" && !strings.EqualFold(s.Package, finding.Name) {
			continue
		}

		if s.Expires != "" {
			if expires, err := time.Parse("2006-01-02", s.Expires); err == nil {
				if now.After(expires) {
					continue
				}
			}
			// malformed date → treat as no-expiry → suppresses
		}

		return true
	}
	return false
}
