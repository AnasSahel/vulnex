package vulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/model"
)

const baseURL = "https://api.vulncheck.com/v3"

// Client provides access to the VulnCheck vulnerability intelligence API.
// This is an optional fallback data source that supplements the primary
// NVD, EPSS, KEV, GHSA, and OSV clients.
type Client struct {
	http *api.Client
}

// NewClient creates a new VulnCheck API client.
func NewClient(httpClient *api.Client) *Client {
	return &Client{http: httpClient}
}

// GetCVE retrieves vulnerability data for a specific CVE ID from VulnCheck
// and converts it to the standard EnrichedCVE model.
func (c *Client) GetCVE(ctx context.Context, cveID string) (*model.EnrichedCVE, error) {
	url := fmt.Sprintf("%s/cve/%s", baseURL, cveID)

	resp, err := c.http.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching VulnCheck data for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("CVE %s not found in VulnCheck", cveID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VulnCheck API returned status %d for %s", resp.StatusCode, cveID)
	}

	var vcResp VulnCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&vcResp); err != nil {
		return nil, fmt.Errorf("decoding VulnCheck response for %s: %w", cveID, err)
	}

	if len(vcResp.Data) == 0 {
		return nil, fmt.Errorf("no VulnCheck data found for %s", cveID)
	}

	return toEnrichedCVE(&vcResp.Data[0]), nil
}

// toEnrichedCVE converts a VulnCheckVuln to the standard EnrichedCVE model.
func toEnrichedCVE(vuln *VulnCheckVuln) *model.EnrichedCVE {
	cve := &model.EnrichedCVE{
		ID:          vuln.CVEID,
		DataSources: []string{"vulncheck"},
		FetchedAt:   time.Now(),
	}

	// Map description
	if vuln.Description != "" {
		cve.Descriptions = []model.LangString{
			{Lang: "en", Value: vuln.Description},
		}
	}

	// Map CVSS score
	if vuln.CVSS.BaseScore > 0 {
		cve.CVSS = []model.CVSSScore{
			{
				Version:      vuln.CVSS.Version,
				VectorString: vuln.CVSS.VectorString,
				BaseScore:    vuln.CVSS.BaseScore,
				Severity:     vuln.CVSS.Severity,
				Source:        "vulncheck",
				Type:         "Secondary",
			},
		}
	}

	// Map references
	for _, ref := range vuln.References {
		cve.References = append(cve.References, model.Reference{
			URL:    ref.URL,
			Source: ref.Source,
			Tags:   []string{ref.Type},
		})
	}

	return cve
}
