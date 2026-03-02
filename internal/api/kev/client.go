package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

const (
	// kevFeedURL is the CISA KEV JSON feed endpoint.
	kevFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// kevCacheTTL is the duration the KEV catalog is considered fresh.
	kevCacheTTL = 6 * time.Hour
)

// CatalogStats holds aggregate statistics about the KEV catalog.
type CatalogStats struct {
	TotalCount      int
	RecentCount     int // entries added in the last 30 days
	TopVendors      map[string]int
	RansomwareCount int
}

// Client provides access to the CISA Known Exploited Vulnerabilities catalog.
type Client struct {
	http  *api.Client
	cache cache.Cache
}

// NewClient creates a new KEV client backed by the given HTTP client and cache.
func NewClient(httpClient *api.Client, c cache.Cache) *Client {
	return &Client{
		http:  httpClient,
		cache: c,
	}
}

// FetchCatalog downloads the full KEV catalog. It returns a cached copy when
// available and still fresh; otherwise it fetches a new copy from CISA,
// honouring ETag-based conditional requests.
func (c *Client) FetchCatalog(ctx context.Context) (*Catalog, error) {
	// Try the cache first.
	entry, err := c.cache.GetKEV(ctx)
	if err == nil && entry != nil && time.Now().Before(entry.ExpiresAt) {
		var cat Catalog
		if err := json.Unmarshal(entry.Data, &cat); err == nil {
			return &cat, nil
		}
		// Corrupted cache data – fall through to a fresh download.
	}

	// Determine any previously stored ETag for conditional fetch.
	var etag string
	if entry != nil {
		etag = entry.ETag
	}

	resp, err := c.http.GetWithETag(ctx, kevFeedURL, etag)
	if err != nil {
		return nil, fmt.Errorf("fetching KEV catalog: %w", err)
	}
	defer resp.Body.Close()

	// 304 Not Modified – the cached copy is still valid.
	if resp.StatusCode == http.StatusNotModified && entry != nil {
		var cat Catalog
		if err := json.Unmarshal(entry.Data, &cat); err != nil {
			return nil, fmt.Errorf("decoding cached KEV catalog: %w", err)
		}
		// Refresh the cache TTL so we don't hit the server again too soon.
		_ = c.cache.SetKEV(ctx, entry.Data, cat.CatalogVersion, etag, kevCacheTTL)
		return &cat, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading KEV response body: %w", err)
	}

	var cat Catalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, fmt.Errorf("decoding KEV catalog: %w", err)
	}

	// Store in cache for future requests.
	newETag := resp.Header.Get("ETag")
	_ = c.cache.SetKEV(ctx, body, cat.CatalogVersion, newETag, kevCacheTTL)

	return &cat, nil
}

// Check looks up a single CVE in the KEV catalog. It returns a *model.KEVEntry
// if the CVE is present, or nil if it is not found.
func (c *Client) Check(ctx context.Context, cveID string) (*model.KEVEntry, error) {
	cat, err := c.FetchCatalog(ctx)
	if err != nil {
		return nil, err
	}

	upper := strings.ToUpper(cveID)
	for _, v := range cat.Vulnerabilities {
		if strings.ToUpper(v.CveID) == upper {
			entry := convertEntry(v)
			return &entry, nil
		}
	}

	return nil, nil
}

// List returns every entry in the KEV catalog as a slice of model.KEVEntry.
func (c *Client) List(ctx context.Context) ([]model.KEVEntry, error) {
	cat, err := c.FetchCatalog(ctx)
	if err != nil {
		return nil, err
	}

	entries := make([]model.KEVEntry, 0, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		entries = append(entries, convertEntry(v))
	}
	return entries, nil
}

// Recent returns KEV entries whose DateAdded falls within the last N days.
func (c *Client) Recent(ctx context.Context, days int) ([]model.KEVEntry, error) {
	cat, err := c.FetchCatalog(ctx)
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	var entries []model.KEVEntry
	for _, v := range cat.Vulnerabilities {
		added, err := time.Parse("2006-01-02", v.DateAdded)
		if err != nil {
			continue // skip entries with unparseable dates
		}
		if !added.Before(cutoff) {
			entries = append(entries, convertEntry(v))
		}
	}
	return entries, nil
}

// Stats computes aggregate statistics about the KEV catalog.
func (c *Client) Stats(ctx context.Context) (*CatalogStats, error) {
	cat, err := c.FetchCatalog(ctx)
	if err != nil {
		return nil, err
	}

	stats := &CatalogStats{
		TotalCount: len(cat.Vulnerabilities),
		TopVendors: make(map[string]int),
	}

	cutoff := time.Now().AddDate(0, 0, -30)

	for _, v := range cat.Vulnerabilities {
		// Count entries added in the last 30 days.
		if added, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
			if !added.Before(cutoff) {
				stats.RecentCount++
			}
		}

		// Tally vendors.
		stats.TopVendors[v.VendorProject]++

		// Count known ransomware usage.
		if strings.EqualFold(v.KnownRansomwareCampaignUse, "Known") {
			stats.RansomwareCount++
		}
	}

	return stats, nil
}

// convertEntry maps a KEV feed Vulnerability to the internal model.KEVEntry.
func convertEntry(v Vulnerability) model.KEVEntry {
	return model.KEVEntry{
		CVEID:                   v.CveID,
		VendorProject:           v.VendorProject,
		Product:                 v.Product,
		VulnerabilityName:       v.VulnerabilityName,
		DateAdded:               v.DateAdded,
		ShortDescription:        v.ShortDescription,
		RequiredAction:          v.RequiredAction,
		DueDate:                 v.DueDate,
		KnownRansomwareCampaign: v.KnownRansomwareCampaignUse,
		Notes:                   v.Notes,
	}
}
