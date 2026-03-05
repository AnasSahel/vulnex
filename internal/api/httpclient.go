package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/trustin-tech/vulnex/internal/ratelimit"
)

const (
	userAgent      = "vulnex/1.0 (https://github.com/trustin-tech/vulnex)"
	defaultTimeout = 30 * time.Second
)

// Client wraps an HTTP client with rate limiting and API key injection.
type Client struct {
	http      *http.Client
	limiter   *ratelimit.Limiter
	apiKeys   map[string]string // host -> api key header value
	timeout   time.Duration
}

// ClientOption configures an API Client.
type ClientOption func(*Client)

// WithTimeout sets the HTTP request timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithAPIKey configures an API key for a specific host.
func WithAPIKey(host, key string) ClientOption {
	return func(c *Client) {
		c.apiKeys[host] = key
	}
}

// NewClient creates a new API Client with retries and rate limiting.
func NewClient(limiter *ratelimit.Limiter, opts ...ClientOption) *Client {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.RetryWaitMin = 1 * time.Second
	retryClient.RetryWaitMax = 30 * time.Second
	retryClient.Logger = nil // Suppress default logger
	retryClient.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		// Never retry rate-limit responses — they won't resolve within our backoff window
		if resp != nil && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) {
			return false, nil
		}
		return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
	}

	c := &Client{
		http:    retryClient.StandardClient(),
		limiter: limiter,
		apiKeys: make(map[string]string),
		timeout: defaultTimeout,
	}

	for _, opt := range opts {
		opt(c)
	}

	c.http.Timeout = c.timeout

	return c
}

// Get performs a rate-limited HTTP GET request.
func (c *Client) Get(ctx context.Context, rawURL string) (*http.Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	if err := c.limiter.Wait(ctx, parsed.Host); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	// Inject API key if configured for this host
	if key, ok := c.apiKeys[parsed.Host]; ok {
		switch parsed.Host {
		case "services.nvd.nist.gov":
			req.Header.Set("apiKey", key)
		case "api.github.com":
			req.Header.Set("Authorization", "Bearer "+key)
		default:
			req.Header.Set("Authorization", "Bearer "+key)
		}
	}

	return c.http.Do(req)
}

// GetWithETag performs a rate-limited HTTP GET with conditional ETag support.
func (c *Client) GetWithETag(ctx context.Context, rawURL, etag string) (*http.Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	if err := c.limiter.Wait(ctx, parsed.Host); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	return c.http.Do(req)
}

// Post performs a rate-limited HTTP POST request.
func (c *Client) Post(ctx context.Context, rawURL string, contentType string, body io.Reader) (*http.Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	if err := c.limiter.Wait(ctx, parsed.Host); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	return c.http.Do(req)
}
