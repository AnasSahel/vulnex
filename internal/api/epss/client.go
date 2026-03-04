package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

const (
	baseURL = "https://api.first.org/data/v1/epss"

	// maxURLLength is the maximum allowed URL length to stay within
	// HTTP spec and server limits. The EPSS API documentation recommends
	// keeping requests under 2000 characters.
	maxURLLength = 2000
)

// TopEntry represents a single CVE entry returned by the Top query,
// with the EPSS score and percentile already parsed to float64.
type TopEntry struct {
	CVEID      string
	Score      float64
	Percentile float64
	Date       string
}

const epssCacheTTL = 24 * time.Hour

// Client provides access to the FIRST.org EPSS API.
type Client struct {
	http  *api.Client
	cache cache.Cache
}

// NewClient creates a new EPSS API client.
func NewClient(httpClient *api.Client, c cache.Cache) *Client {
	return &Client{http: httpClient, cache: c}
}

// TimeSeriesEntry represents a single EPSS score data point in a time series.
type TimeSeriesEntry struct {
	Date       string  `json:"date"`
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// GetTimeSeries retrieves the historical EPSS score time-series for a CVE ID.
func (c *Client) GetTimeSeries(ctx context.Context, cveID string, days int) ([]TimeSeriesEntry, error) {
	url := fmt.Sprintf("%s?cve=%s&scope=time-series", baseURL, cveID)

	resp, err := c.http.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching EPSS time-series for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned status %d for time-series request", resp.StatusCode)
	}

	var apiResp Response
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding EPSS time-series response: %w", err)
	}

	entries := make([]TimeSeriesEntry, 0, len(apiResp.Data))
	for _, d := range apiResp.Data {
		score, err := parseFloat(d.EPSS, "EPSS score")
		if err != nil {
			continue
		}
		percentile, err := parseFloat(d.Percentile, "percentile")
		if err != nil {
			continue
		}
		entries = append(entries, TimeSeriesEntry{
			Date:       d.Date,
			Score:      score,
			Percentile: percentile,
		})
	}

	if days > 0 && len(entries) > days {
		entries = entries[len(entries)-days:]
	}

	return entries, nil
}

// GetScore retrieves the EPSS score for a single CVE ID.
func (c *Client) GetScore(ctx context.Context, cveID string) (*model.EPSSScore, error) {
	// Check cache first
	if c.cache != nil {
		entry, err := c.cache.GetEPSS(ctx, cveID)
		if err == nil && entry != nil && time.Now().Before(entry.ExpiresAt) {
			var score model.EPSSScore
			if err := json.Unmarshal(entry.Data, &score); err == nil {
				slog.Debug("EPSS cache hit", "cve", cveID)
				return &score, nil
			}
		}
	}

	url := fmt.Sprintf("%s?cve=%s", baseURL, cveID)

	resp, err := c.http.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching EPSS score for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned status %d for %s", resp.StatusCode, cveID)
	}

	var apiResp Response
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding EPSS response for %s: %w", cveID, err)
	}

	if len(apiResp.Data) == 0 {
		return nil, fmt.Errorf("no EPSS data found for %s", cveID)
	}

	score, err := toEPSSScore(&apiResp.Data[0])
	if err != nil {
		return nil, err
	}

	// Store in cache
	if c.cache != nil {
		if data, err := json.Marshal(score); err == nil {
			if err := c.cache.SetEPSS(ctx, cveID, data, epssCacheTTL); err != nil {
				slog.Debug("EPSS cache store failed", "cve", cveID, "error", err)
			}
		}
	}

	return score, nil
}

// GetScores retrieves EPSS scores for multiple CVE IDs in batch.
// It automatically splits requests to respect the 2000-character URL limit.
// Cached scores are returned directly; only cache misses are fetched from the API.
func (c *Client) GetScores(ctx context.Context, cveIDs []string) (map[string]*model.EPSSScore, error) {
	if len(cveIDs) == 0 {
		return make(map[string]*model.EPSSScore), nil
	}

	results := make(map[string]*model.EPSSScore, len(cveIDs))
	var misses []string

	// Check cache for each CVE ID
	if c.cache != nil {
		for _, id := range cveIDs {
			entry, err := c.cache.GetEPSS(ctx, id)
			if err == nil && entry != nil && time.Now().Before(entry.ExpiresAt) {
				var score model.EPSSScore
				if err := json.Unmarshal(entry.Data, &score); err == nil {
					results[id] = &score
					continue
				}
			}
			misses = append(misses, id)
		}
	} else {
		misses = cveIDs
	}

	if len(misses) == 0 {
		return results, nil
	}

	// Batch-fetch cache misses
	batches := splitIntoBatches(misses)
	for _, batch := range batches {
		url := fmt.Sprintf("%s?cve=%s", baseURL, strings.Join(batch, ","))

		resp, err := c.http.Get(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetching EPSS scores: %w", err)
		}

		var apiResp Response
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decoding EPSS batch response: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("EPSS API returned status %d for batch request", resp.StatusCode)
		}

		for i := range apiResp.Data {
			score, err := toEPSSScore(&apiResp.Data[i])
			if err != nil {
				return nil, fmt.Errorf("parsing EPSS data for %s: %w", apiResp.Data[i].CVE, err)
			}
			results[apiResp.Data[i].CVE] = score

			// Store each score in cache
			if c.cache != nil {
				if data, err := json.Marshal(score); err == nil {
					_ = c.cache.SetEPSS(ctx, apiResp.Data[i].CVE, data, epssCacheTTL)
				}
			}
		}
	}

	return results, nil
}

// Top retrieves the top N CVEs ranked by EPSS score in descending order.
func (c *Client) Top(ctx context.Context, n int) ([]*TopEntry, error) {
	url := fmt.Sprintf("%s?order=!epss&limit=%d", baseURL, n)

	resp, err := c.http.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching top %d EPSS scores: %w", n, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned status %d for top request", resp.StatusCode)
	}

	var apiResp Response
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding EPSS top response: %w", err)
	}

	entries := make([]*TopEntry, 0, len(apiResp.Data))
	for i := range apiResp.Data {
		entry, err := toTopEntry(&apiResp.Data[i])
		if err != nil {
			return nil, fmt.Errorf("parsing top entry for %s: %w", apiResp.Data[i].CVE, err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// splitIntoBatches divides CVE IDs into groups such that each resulting
// URL stays within the maxURLLength limit.
func splitIntoBatches(cveIDs []string) [][]string {
	// Base URL length: baseURL + "?cve=" prefix
	prefix := baseURL + "?cve="
	prefixLen := len(prefix)

	var batches [][]string
	var current []string
	currentLen := prefixLen

	for _, id := range cveIDs {
		// Account for the comma separator between CVE IDs
		addition := len(id)
		if len(current) > 0 {
			addition++ // for the comma
		}

		if currentLen+addition > maxURLLength && len(current) > 0 {
			batches = append(batches, current)
			current = []string{id}
			currentLen = prefixLen + len(id)
		} else {
			current = append(current, id)
			currentLen += addition
		}
	}

	if len(current) > 0 {
		batches = append(batches, current)
	}

	return batches
}

// parseFloat parses a string value to float64, wrapping errors with context.
func parseFloat(value, field string) (float64, error) {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s %q: %w", field, value, err)
	}
	return f, nil
}

// toEPSSScore converts an EPSSData record from the API into a model.EPSSScore.
func toEPSSScore(data *EPSSData) (*model.EPSSScore, error) {
	score, err := parseFloat(data.EPSS, "EPSS score")
	if err != nil {
		return nil, err
	}

	percentile, err := parseFloat(data.Percentile, "percentile")
	if err != nil {
		return nil, err
	}

	return &model.EPSSScore{
		Score:      score,
		Percentile: percentile,
		Date:       data.Date,
	}, nil
}

// toTopEntry converts an EPSSData record from the API into a TopEntry.
func toTopEntry(data *EPSSData) (*TopEntry, error) {
	score, err := parseFloat(data.EPSS, "EPSS score")
	if err != nil {
		return nil, err
	}

	percentile, err := parseFloat(data.Percentile, "percentile")
	if err != nil {
		return nil, err
	}

	return &TopEntry{
		CVEID:      data.CVE,
		Score:      score,
		Percentile: percentile,
		Date:       data.Date,
	}, nil
}
