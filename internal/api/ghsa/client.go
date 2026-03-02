package ghsa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/model"
)

// ghErrorResponse represents the JSON error body returned by GitHub's API.
type ghErrorResponse struct {
	Message string `json:"message"`
}

// ghAPIError reads the response body and returns a descriptive error.
// For 403 rate-limit errors it adds a hint about authentication.
func ghAPIError(resp *http.Response, context string) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	var ghErr ghErrorResponse
	if json.Unmarshal(body, &ghErr) == nil && ghErr.Message != "" {
		msg := fmt.Sprintf("GitHub API %s: %s (HTTP %d)", context, ghErr.Message, resp.StatusCode)
		if resp.StatusCode == http.StatusForbidden {
			msg += "\nhint: set a GitHub token with 'vulnex config set api_keys.github <token>' to raise the rate limit"
		}
		return fmt.Errorf("%s", msg)
	}
	return fmt.Errorf("GitHub API %s: HTTP %d", context, resp.StatusCode)
}

const baseURL = "https://api.github.com/advisories"

// Client provides access to the GitHub Advisory Database REST API.
type Client struct {
	httpClient *api.Client
}

// NewClient creates a new GHSA API client backed by the given HTTP client.
func NewClient(httpClient *api.Client) *Client {
	return &Client{httpClient: httpClient}
}

// SearchParams configures a search query against the GitHub Advisory Database.
type SearchParams struct {
	Query     string // free-text keyword search
	Ecosystem string // filter by ecosystem (e.g. "npm", "pip", "go")
	Severity  string // filter by severity ("critical", "high", "medium", "low")
	Type      string // advisory type ("reviewed", "unreviewed", "malware")
	CveID     string // filter by CVE identifier
	PerPage   int    // results per page (max 100, default 30)
}

// Search queries the GitHub Advisory Database with the given parameters.
// PerPage acts as the total result limit — only one page is fetched.
func (c *Client) Search(ctx context.Context, params SearchParams) ([]GHSAdvisory, error) {
	reqURL, err := buildSearchURL(params)
	if err != nil {
		return nil, fmt.Errorf("building search URL: %w", err)
	}

	resp, err := c.httpClient.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("fetching advisories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ghAPIError(resp, "search")
	}

	var results []GHSAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("decoding advisory response: %w", err)
	}

	return results, nil
}

// GetAdvisory retrieves a single advisory by its GHSA ID (e.g. "GHSA-xxxx-xxxx-xxxx").
func (c *Client) GetAdvisory(ctx context.Context, ghsaID string) (*GHSAdvisory, error) {
	reqURL := baseURL + "/" + url.PathEscape(ghsaID)

	resp, err := c.httpClient.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("fetching advisory %s: %w", ghsaID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("advisory %s not found", ghsaID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, ghAPIError(resp, fmt.Sprintf("get advisory %s", ghsaID))
	}

	var advisory GHSAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&advisory); err != nil {
		return nil, fmt.Errorf("decoding advisory %s: %w", ghsaID, err)
	}

	return &advisory, nil
}

// FindByCVE searches for advisories associated with the given CVE ID and returns
// the results converted to the common model types.
func (c *Client) FindByCVE(ctx context.Context, cveID string) ([]model.Advisory, []model.AffectedPkg, error) {
	results, err := c.Search(ctx, SearchParams{CveID: cveID})
	if err != nil {
		return nil, nil, fmt.Errorf("searching GHSA by CVE %s: %w", cveID, err)
	}

	var advisories []model.Advisory
	var packages []model.AffectedPkg

	for i := range results {
		advisories = append(advisories, convertToAdvisory(&results[i]))
		packages = append(packages, convertToAffectedPkgs(&results[i])...)
	}

	return advisories, packages, nil
}

// FindByPackage searches for advisories affecting a specific package in a given ecosystem.
func (c *Client) FindByPackage(ctx context.Context, ecosystem, pkg string) ([]GHSAdvisory, error) {
	reqURL := baseURL + "?" + url.Values{
		"ecosystem": {ecosystem},
	}.Encode() + "&affects=" + url.QueryEscape(pkg)

	var all []GHSAdvisory
	currentURL := reqURL

	for currentURL != "" {
		resp, err := c.httpClient.Get(ctx, currentURL)
		if err != nil {
			return nil, fmt.Errorf("fetching advisories for package %s/%s: %w", ecosystem, pkg, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, ghAPIError(resp, fmt.Sprintf("find package %s/%s", ecosystem, pkg))
		}

		var page []GHSAdvisory
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			return nil, fmt.Errorf("decoding advisory response for package %s/%s: %w", ecosystem, pkg, err)
		}

		all = append(all, page...)
		currentURL = parseNextLink(resp.Header.Get("Link"))
	}

	return all, nil
}

// convertToAdvisory transforms a GitHub Advisory API response into the common model.Advisory type.
func convertToAdvisory(ghsa *GHSAdvisory) model.Advisory {
	return model.Advisory{
		ID:       ghsa.GHSAID,
		Source:   "ghsa",
		URL:      ghsa.URL,
		Severity: strings.ToLower(ghsa.Severity),
		Summary:  ghsa.Summary,
	}
}

// convertToAffectedPkgs extracts affected package information from a GitHub Advisory
// and converts it into the common model.AffectedPkg type.
func convertToAffectedPkgs(ghsa *GHSAdvisory) []model.AffectedPkg {
	var pkgs []model.AffectedPkg

	for _, vuln := range ghsa.Vulnerabilities {
		pkg := model.AffectedPkg{
			Ecosystem: normalizeEcosystem(vuln.Package.Ecosystem),
			Name:      vuln.Package.Name,
		}

		// Derive the fixed version from FirstPatchedVersion if available,
		// falling back to the PatchedVersions string.
		if vuln.FirstPatchedVersion != nil && *vuln.FirstPatchedVersion != "" {
			pkg.Fixed = *vuln.FirstPatchedVersion
		} else if vuln.PatchedVersions != "" {
			pkg.Fixed = vuln.PatchedVersions
		}

		// Parse the vulnerable version range into a model.Range.
		if vuln.VulnerableVersionRange != "" {
			r := parseVersionRange(vuln.VulnerableVersionRange, pkg.Fixed)
			if r != nil {
				pkg.Ranges = append(pkg.Ranges, *r)
			}
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs
}

// buildSearchURL constructs the full request URL for a Search call from the given params.
func buildSearchURL(params SearchParams) (string, error) {
	q := url.Values{}

	if params.Query != "" {
		// The GitHub API does not have a dedicated "q" parameter for the
		// advisories list endpoint; instead we use the keywords parameter.
		q.Set("keywords", params.Query)
	}
	if params.Ecosystem != "" {
		q.Set("ecosystem", params.Ecosystem)
	}
	if params.Severity != "" {
		q.Set("severity", params.Severity)
	}
	if params.Type != "" {
		q.Set("type", params.Type)
	}
	if params.CveID != "" {
		q.Set("cve_id", params.CveID)
	}
	if params.PerPage > 0 {
		q.Set("per_page", strconv.Itoa(params.PerPage))
	}

	if len(q) == 0 {
		return baseURL, nil
	}
	return baseURL + "?" + q.Encode(), nil
}

// linkNextRe matches the "next" relation in a GitHub Link header.
var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// parseNextLink extracts the URL for the next page from a GitHub Link header value.
// It returns an empty string when no next page is available.
func parseNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	matches := linkNextRe.FindStringSubmatch(linkHeader)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// normalizeEcosystem maps GitHub Advisory ecosystem names to the lowercase
// identifiers used in model.AffectedPkg.
func normalizeEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "npm"
	case "pip":
		return "pip"
	case "go":
		return "go"
	case "maven":
		return "maven"
	case "nuget":
		return "nuget"
	case "rubygems":
		return "rubygems"
	case "rust", "crates.io":
		return "crates.io"
	case "composer":
		return "composer"
	case "pub":
		return "pub"
	case "swift":
		return "swift"
	case "erlang":
		return "erlang"
	case "actions":
		return "actions"
	default:
		return strings.ToLower(eco)
	}
}

// parseVersionRange attempts to convert a GitHub Advisory vulnerable_version_range
// string (e.g. ">= 1.0, < 2.0") into a model.Range. Returns nil when the range
// cannot be meaningfully parsed.
func parseVersionRange(rangeStr, fixed string) *model.Range {
	r := &model.Range{
		Type: "ECOSYSTEM",
	}

	// The range string may contain multiple comma-separated constraints.
	parts := strings.Split(rangeStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		switch {
		case strings.HasPrefix(part, ">= "):
			r.Introduced = strings.TrimPrefix(part, ">= ")
		case strings.HasPrefix(part, "> "):
			// Treat exclusive lower bound as introduced for display purposes.
			r.Introduced = strings.TrimPrefix(part, "> ")
		case strings.HasPrefix(part, "<= "):
			r.LastAffected = strings.TrimPrefix(part, "<= ")
		case strings.HasPrefix(part, "< "):
			// An upper bound with no explicit fixed version: derive fixed from it.
			if fixed == "" {
				fixed = strings.TrimPrefix(part, "< ")
			}
		case strings.HasPrefix(part, "= "):
			// Exact version match; treat as both introduced and last-affected.
			ver := strings.TrimPrefix(part, "= ")
			r.Introduced = ver
			r.LastAffected = ver
		}
	}

	if fixed != "" {
		r.Fixed = fixed
	}

	// If we could not extract any useful bound, return nil.
	if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
		return nil
	}

	return r
}
