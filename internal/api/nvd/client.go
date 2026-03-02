package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/model"
)

// maxDateRange is the maximum date span allowed by the NVD API (120 days).
const maxDateRange = 120 * 24 * time.Hour

const baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// nvdTimeFormat is the timestamp layout used by the NVD API.
const nvdTimeFormat = "2006-01-02T15:04:05.000"

// Client provides access to the NVD CVE API 2.0.
type Client struct {
	http *api.Client
}

// NewClient creates a new NVD API client backed by the given HTTP client.
func NewClient(httpClient *api.Client) *Client {
	return &Client{http: httpClient}
}

// SearchParams holds parameters for the CVE search endpoint.
type SearchParams struct {
	KeywordSearch    string
	CvssV3Severity   string // LOW, MEDIUM, HIGH, CRITICAL
	CweID            string // e.g. CWE-79
	HasKev           bool
	PubStartDate     string // ISO-8601 e.g. "2024-01-01T00:00:00.000"
	PubEndDate       string
	LastModStartDate string
	LastModEndDate   string
	NoRejected       bool
	StartIndex       int
	ResultsPerPage   int
}

// SearchResult holds a page of enriched CVE results.
type SearchResult struct {
	TotalResults int
	StartIndex   int
	CVEs         []*model.EnrichedCVE
}

// GetCVE fetches a single CVE by its ID and returns it as an EnrichedCVE.
func (c *Client) GetCVE(ctx context.Context, cveID string) (*model.EnrichedCVE, error) {
	u := baseURL + "?cveId=" + url.QueryEscape(cveID)

	resp, err := c.http.Get(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("nvd: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if len(body) > 0 {
			return nil, fmt.Errorf("nvd: status %d for CVE %s: %s", resp.StatusCode, cveID, string(body))
		}
		return nil, fmt.Errorf("nvd: unexpected status %d for CVE %s", resp.StatusCode, cveID)
	}

	var cveResp CVEResponse
	if err := json.NewDecoder(resp.Body).Decode(&cveResp); err != nil {
		return nil, fmt.Errorf("nvd: decoding response: %w", err)
	}

	if len(cveResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("nvd: CVE %s not found", cveID)
	}

	return convertCVE(&cveResp.Vulnerabilities[0].CVE), nil
}

// SearchCVEs searches for CVEs using the given parameters.
// If the date range exceeds the NVD API's 120-day limit, the request is
// automatically split into consecutive windows and results are merged.
func (c *Client) SearchCVEs(ctx context.Context, params SearchParams) (*SearchResult, error) {
	windows, err := splitDateWindows(params)
	if err != nil {
		return nil, err
	}

	merged := &SearchResult{}
	for _, win := range windows {
		result, err := c.searchCVEsSingle(ctx, win)
		if err != nil {
			return nil, err
		}
		merged.TotalResults += result.TotalResults
		merged.CVEs = append(merged.CVEs, result.CVEs...)
	}
	return merged, nil
}

// searchCVEsSingle performs a single NVD search request (date range must be <= 120 days).
func (c *Client) searchCVEsSingle(ctx context.Context, params SearchParams) (*SearchResult, error) {
	u, err := buildSearchURL(params)
	if err != nil {
		return nil, fmt.Errorf("nvd: building search URL: %w", err)
	}

	resp, err := c.http.Get(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("nvd: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if len(body) > 0 {
			return nil, fmt.Errorf("nvd: status %d: %s", resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("nvd: unexpected status %d for search", resp.StatusCode)
	}

	var cveResp CVEResponse
	if err := json.NewDecoder(resp.Body).Decode(&cveResp); err != nil {
		return nil, fmt.Errorf("nvd: decoding response: %w", err)
	}

	return convertResponse(&cveResp), nil
}

// splitDateWindows breaks a SearchParams into multiple requests if the
// publication or last-modified date range exceeds 120 days.
func splitDateWindows(p SearchParams) ([]SearchParams, error) {
	// Only split if both start and end dates are provided for publication dates.
	if p.PubStartDate == "" || p.PubEndDate == "" {
		return []SearchParams{p}, nil
	}

	start, err := time.Parse(nvdTimeFormat, p.PubStartDate)
	if err != nil {
		return nil, fmt.Errorf("nvd: invalid pubStartDate %q: %w", p.PubStartDate, err)
	}
	end, err := time.Parse(nvdTimeFormat, p.PubEndDate)
	if err != nil {
		return nil, fmt.Errorf("nvd: invalid pubEndDate %q: %w", p.PubEndDate, err)
	}

	if end.Sub(start) <= maxDateRange {
		return []SearchParams{p}, nil
	}

	var windows []SearchParams
	cursor := start
	for cursor.Before(end) {
		winEnd := cursor.Add(maxDateRange)
		if winEnd.After(end) {
			winEnd = end
		}
		win := p
		win.PubStartDate = cursor.Format(nvdTimeFormat)
		win.PubEndDate = winEnd.Format(nvdTimeFormat)
		windows = append(windows, win)
		cursor = winEnd.Add(time.Second) // avoid overlap
	}
	return windows, nil
}

// ListCVEs returns a paginated list of all CVEs.
func (c *Client) ListCVEs(ctx context.Context, startIndex, resultsPerPage int) (*SearchResult, error) {
	params := url.Values{}
	params.Set("startIndex", strconv.Itoa(startIndex))
	if resultsPerPage > 0 {
		params.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	}

	u := baseURL + "?" + params.Encode()

	resp, err := c.http.Get(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("nvd: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if len(body) > 0 {
			return nil, fmt.Errorf("nvd: status %d for list: %s", resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("nvd: unexpected status %d for list", resp.StatusCode)
	}

	var cveResp CVEResponse
	if err := json.NewDecoder(resp.Body).Decode(&cveResp); err != nil {
		return nil, fmt.Errorf("nvd: decoding response: %w", err)
	}

	return convertResponse(&cveResp), nil
}

// buildSearchURL constructs the full NVD API URL from search parameters.
func buildSearchURL(p SearchParams) (string, error) {
	params := url.Values{}

	if p.KeywordSearch != "" {
		params.Set("keywordSearch", p.KeywordSearch)
	}
	if p.CvssV3Severity != "" {
		params.Set("cvssV3Severity", p.CvssV3Severity)
	}
	if p.CweID != "" {
		params.Set("cweId", p.CweID)
	}
	if p.HasKev {
		params.Set("hasKev", "")
	}
	if p.PubStartDate != "" {
		params.Set("pubStartDate", p.PubStartDate)
	}
	if p.PubEndDate != "" {
		params.Set("pubEndDate", p.PubEndDate)
	}
	if p.LastModStartDate != "" {
		params.Set("lastModStartDate", p.LastModStartDate)
	}
	if p.LastModEndDate != "" {
		params.Set("lastModEndDate", p.LastModEndDate)
	}
	if p.NoRejected {
		params.Set("noRejected", "")
	}
	if p.StartIndex > 0 {
		params.Set("startIndex", strconv.Itoa(p.StartIndex))
	}
	if p.ResultsPerPage > 0 {
		params.Set("resultsPerPage", strconv.Itoa(p.ResultsPerPage))
	}

	return baseURL + "?" + params.Encode(), nil
}

// convertResponse converts an NVD CVEResponse into a SearchResult with enriched CVEs.
func convertResponse(resp *CVEResponse) *SearchResult {
	result := &SearchResult{
		TotalResults: resp.TotalResults,
		StartIndex:   resp.StartIndex,
		CVEs:         make([]*model.EnrichedCVE, 0, len(resp.Vulnerabilities)),
	}
	for i := range resp.Vulnerabilities {
		result.CVEs = append(result.CVEs, convertCVE(&resp.Vulnerabilities[i].CVE))
	}
	return result
}

// convertCVE maps an NVD CVE record to the universal EnrichedCVE model.
func convertCVE(c *CVE) *model.EnrichedCVE {
	enriched := &model.EnrichedCVE{
		ID:           c.ID,
		SourceID:     c.SourceIdentifier,
		Status:       c.VulnStatus,
		Descriptions: convertDescriptions(c.Descriptions),
		CVSS:         convertMetrics(&c.Metrics),
		CWEs:         convertWeaknesses(c.Weaknesses),
		CPEs:         convertConfigurations(c.Configurations),
		References:   convertReferences(c.References),
		DataSources:  []string{"nvd"},
		FetchedAt:    time.Now().UTC(),
	}

	if t, err := time.Parse(nvdTimeFormat, c.Published); err == nil {
		enriched.Published = t.UTC()
	}
	if t, err := time.Parse(nvdTimeFormat, c.LastModified); err == nil {
		enriched.LastModified = t.UTC()
	}

	return enriched
}

// convertDescriptions maps NVD LangStrings to model LangStrings.
func convertDescriptions(descs []LangString) []model.LangString {
	out := make([]model.LangString, len(descs))
	for i, d := range descs {
		out[i] = model.LangString{
			Lang:  d.Lang,
			Value: d.Value,
		}
	}
	return out
}

// convertMetrics extracts all CVSS scores from the NVD metrics block.
func convertMetrics(m *Metrics) []model.CVSSScore {
	var scores []model.CVSSScore

	for _, v40 := range m.CvssMetricV40 {
		scores = append(scores, model.CVSSScore{
			Version:      v40.CvssData.Version,
			VectorString: v40.CvssData.VectorString,
			BaseScore:    v40.CvssData.BaseScore,
			Severity:     v40.CvssData.BaseSeverity,
			Source:       v40.Source,
			Type:         v40.Type,
		})
	}

	for _, v31 := range m.CvssMetricV31 {
		scores = append(scores, model.CVSSScore{
			Version:      v31.CvssData.Version,
			VectorString: v31.CvssData.VectorString,
			BaseScore:    v31.CvssData.BaseScore,
			Severity:     v31.CvssData.BaseSeverity,
			Source:       v31.Source,
			Type:         v31.Type,
		})
	}

	for _, v2 := range m.CvssMetricV2 {
		scores = append(scores, model.CVSSScore{
			Version:      v2.CvssData.Version,
			VectorString: v2.CvssData.VectorString,
			BaseScore:    v2.CvssData.BaseScore,
			Severity:     model.SeverityFromScore(v2.CvssData.BaseScore),
			Source:       v2.Source,
			Type:         v2.Type,
		})
	}

	return scores
}

// convertWeaknesses extracts CWE entries from NVD weakness data.
func convertWeaknesses(weaknesses []Weakness) []model.CWEEntry {
	var entries []model.CWEEntry
	for _, w := range weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && d.Value != "NVD-CWE-noinfo" && d.Value != "NVD-CWE-Other" {
				entries = append(entries, model.CWEEntry{
					ID:     d.Value,
					Source: w.Source,
				})
			}
		}
	}
	return entries
}

// convertConfigurations extracts CPE match entries from NVD configuration nodes.
func convertConfigurations(configs []Configuration) []model.CPEMatch {
	var matches []model.CPEMatch
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			for _, m := range node.CpeMatch {
				matches = append(matches, model.CPEMatch{
					CPE23URI:         m.Criteria,
					Vulnerable:       m.Vulnerable,
					VersionStartIncl: m.VersionStartIncluding,
					VersionStartExcl: m.VersionStartExcluding,
					VersionEndIncl:   m.VersionEndIncluding,
					VersionEndExcl:   m.VersionEndExcluding,
				})
			}
		}
	}
	return matches
}

// convertReferences maps NVD references to model references.
func convertReferences(refs []NVDReference) []model.Reference {
	out := make([]model.Reference, len(refs))
	for i, r := range refs {
		out[i] = model.Reference{
			URL:    r.URL,
			Source: r.Source,
			Tags:   r.Tags,
		}
	}
	return out
}
