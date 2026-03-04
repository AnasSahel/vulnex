package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

// OSV.dev API endpoint base URLs, overridable in tests.
var (
	// queryURL is the OSV.dev single-query endpoint.
	queryURL = "https://api.osv.dev/v1/query"

	// vulnURL is the OSV.dev single-vulnerability lookup endpoint.
	// The vulnerability ID is appended to this base path.
	vulnURL = "https://api.osv.dev/v1/vulns/"

	// batchURL is the OSV.dev batch query endpoint.
	batchURL = "https://api.osv.dev/v1/querybatch"
)

const osvCacheTTL = 4 * time.Hour

// Client provides access to the OSV.dev vulnerability database.
type Client struct {
	http  *api.Client
	cache cache.Cache
}

// NewClient creates a new OSV.dev client backed by the given HTTP client and cache.
func NewClient(httpClient *api.Client, c cache.Cache) *Client {
	return &Client{
		http:  httpClient,
		cache: c,
	}
}

// osvQueryByCVEResult is used for caching QueryByCVE results.
type osvQueryByCVEResult struct {
	Advisories []model.Advisory    `json:"advisories"`
	Packages   []model.AffectedPkg `json:"packages"`
}

// QueryByCVE queries OSV.dev for vulnerabilities matching the given CVE alias
// and converts the results to the internal model types.
//
// It first attempts a direct lookup via /v1/vulns/{cveID}, which supports
// alias resolution for CVE IDs. If that returns a record whose primary ID
// differs from the queried CVE (i.e. the CVE was an alias), it also fetches
// any sibling aliases referenced in the result to provide complete coverage.
func (c *Client) QueryByCVE(ctx context.Context, cveID string) ([]model.Advisory, []model.AffectedPkg, error) {
	cacheKey := "osv:cve:" + cveID

	// Check cache first
	if c.cache != nil {
		entry, err := c.cache.GetAdvisory(ctx, cacheKey)
		if err == nil && entry != nil && time.Now().Before(entry.ExpiresAt) {
			var cached osvQueryByCVEResult
			if err := json.Unmarshal(entry.Data, &cached); err == nil {
				slog.Debug("OSV QueryByCVE cache hit", "cve", cveID)
				return cached.Advisories, cached.Packages, nil
			}
		}
	}

	// Try fetching the CVE ID directly as a vulnerability ID.
	vuln, err := c.GetVulnerability(ctx, cveID)
	if err != nil {
		return nil, nil, fmt.Errorf("querying OSV for %s: %w", cveID, err)
	}
	if vuln == nil {
		return nil, nil, nil
	}

	vulns := []OSVVulnerability{*vuln}

	if vuln.ID != cveID {
		for _, alias := range vuln.Aliases {
			if alias == cveID || alias == vuln.ID {
				continue
			}
			sibling, err := c.GetVulnerability(ctx, alias)
			if err != nil || sibling == nil {
				continue
			}
			vulns = append(vulns, *sibling)
		}
	}

	advisories := convertToAdvisories(vulns)
	affected := convertToAffectedPkgs(vulns)

	// Store in cache
	if c.cache != nil {
		cached := osvQueryByCVEResult{Advisories: advisories, Packages: affected}
		if data, err := json.Marshal(cached); err == nil {
			_ = c.cache.SetAdvisory(ctx, cacheKey, data, "osv", osvCacheTTL)
		}
	}

	return advisories, affected, nil
}

// QueryByPackage queries OSV.dev for vulnerabilities affecting the given
// package at the specified version.
func (c *Client) QueryByPackage(ctx context.Context, ecosystem, name, version string) ([]OSVVulnerability, error) {
	reqBody := QueryRequest{
		Version: version,
		Package: &QueryPackage{
			Name:      name,
			Ecosystem: ecosystem,
		},
	}

	vulns, err := c.doQuery(ctx, reqBody)
	if err != nil {
		return nil, fmt.Errorf("querying OSV for package %s/%s@%s: %w", ecosystem, name, version, err)
	}

	return vulns, nil
}

// GetVulnerability fetches a single vulnerability record by its OSV ID.
func (c *Client) GetVulnerability(ctx context.Context, id string) (*OSVVulnerability, error) {
	// Check cache first
	if c.cache != nil {
		entry, err := c.cache.GetAdvisory(ctx, id)
		if err == nil && entry != nil && time.Now().Before(entry.ExpiresAt) {
			var vuln OSVVulnerability
			if err := json.Unmarshal(entry.Data, &vuln); err == nil {
				slog.Debug("OSV cache hit", "id", id)
				return &vuln, nil
			}
		}
	}

	endpoint := vulnURL + id

	resp, err := c.http.Get(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("fetching OSV vulnerability %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d for vulnerability %s", resp.StatusCode, id)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading OSV response body: %w", err)
	}

	var vuln OSVVulnerability
	if err := json.Unmarshal(body, &vuln); err != nil {
		return nil, fmt.Errorf("decoding OSV vulnerability %s: %w", id, err)
	}

	// Store in cache
	if c.cache != nil {
		if err := c.cache.SetAdvisory(ctx, id, body, "osv", osvCacheTTL); err != nil {
			slog.Debug("OSV cache store failed", "id", id, "error", err)
		}
	}

	return &vuln, nil
}

// BatchQuery sends multiple queries to OSV.dev in a single request.
func (c *Client) BatchQuery(ctx context.Context, queries []QueryRequest) (*BatchQueryResponse, error) {
	reqBody := BatchQueryRequest{
		Queries: queries,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("encoding batch query request: %w", err)
	}

	resp, err := c.http.Post(ctx, batchURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("posting batch query to OSV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV batch API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading OSV batch response body: %w", err)
	}

	var batchResp BatchQueryResponse
	if err := json.Unmarshal(body, &batchResp); err != nil {
		return nil, fmt.Errorf("decoding OSV batch response: %w", err)
	}

	return &batchResp, nil
}

// doQuery posts a single query request to the OSV query endpoint and returns
// the matching vulnerabilities.
func (c *Client) doQuery(ctx context.Context, req QueryRequest) ([]OSVVulnerability, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding query request: %w", err)
	}

	resp, err := c.http.Post(ctx, queryURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("posting query to OSV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV query API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading OSV query response body: %w", err)
	}

	var result struct {
		Vulns []OSVVulnerability `json:"vulns"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decoding OSV query response: %w", err)
	}

	return result.Vulns, nil
}

// convertToAdvisories maps OSV vulnerability records to the internal Advisory model.
func convertToAdvisories(vulns []OSVVulnerability) []model.Advisory {
	advisories := make([]model.Advisory, 0, len(vulns))
	for _, v := range vulns {
		severity := ExtractSeverity(v)
		url := buildOSVURL(v.ID)

		advisories = append(advisories, model.Advisory{
			ID:       v.ID,
			Source:   "osv",
			URL:      url,
			Severity: severity,
			Summary:  v.Summary,
		})
	}
	return advisories
}

// convertToAffectedPkgs maps OSV vulnerability records to the internal AffectedPkg model.
func convertToAffectedPkgs(vulns []OSVVulnerability) []model.AffectedPkg {
	var pkgs []model.AffectedPkg
	for _, v := range vulns {
		for _, a := range v.Affected {
			pkg := model.AffectedPkg{
				Ecosystem: a.Package.Ecosystem,
				Name:      a.Package.Name,
				Versions:  a.Versions,
			}

			// Convert OSV ranges to the internal Range model and extract
			// the first fixed version encountered.
			for _, r := range a.Ranges {
				var introduced, fixed, lastAffected string
				for _, evt := range r.Events {
					if evt.Introduced != "" {
						introduced = evt.Introduced
					}
					if evt.Fixed != "" {
						fixed = evt.Fixed
						if pkg.Fixed == "" {
							pkg.Fixed = fixed
						}
					}
					if evt.LastAffected != "" {
						lastAffected = evt.LastAffected
					}
				}

				pkg.Ranges = append(pkg.Ranges, model.Range{
					Type:         r.Type,
					Introduced:   introduced,
					Fixed:        fixed,
					LastAffected: lastAffected,
				})
			}

			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}

// ExtractSeverity returns a normalized severity string from an OSV vulnerability.
// It prefers CVSS_V3 scores and falls back to CVSS_V2 or database-specific data.
func ExtractSeverity(v OSVVulnerability) string {
	for _, s := range v.Severity {
		if strings.EqualFold(s.Type, "CVSS_V3") || strings.EqualFold(s.Type, "CVSS_V4") {
			if sev := normalizeCVSSSeverity(s.Score); sev != "" {
				return sev
			}
		}
	}
	for _, s := range v.Severity {
		if strings.EqualFold(s.Type, "CVSS_V2") {
			if sev := normalizeCVSSSeverity(s.Score); sev != "" {
				return sev
			}
		}
	}
	// Check database_specific for a severity hint.
	if sev, ok := v.DatabaseSpecific["severity"]; ok {
		if str, ok := sev.(string); ok {
			return normalizeCVSSSeverity(str)
		}
	}
	return ""
}

// normalizeCVSSSeverity attempts to extract a severity label from a CVSS vector
// string or score. If the string itself is a numeric score, it maps it to the
// standard severity labels.
func normalizeCVSSSeverity(score string) string {
	score = strings.TrimSpace(score)
	if score == "" {
		return ""
	}

	// If the score is a CVSS vector string, it does not contain a severity
	// label. Return empty so the caller falls through to database_specific.
	lower := strings.ToLower(score)
	if strings.HasPrefix(lower, "cvss:") {
		return ""
	}

	// Try to map well-known severity labels.
	switch lower {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "none", "informational":
		return "low"
	default:
		return score
	}
}

// buildOSVURL returns the canonical URL for an OSV vulnerability page.
func buildOSVURL(id string) string {
	return "https://osv.dev/vulnerability/" + id
}
