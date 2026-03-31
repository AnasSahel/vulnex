package github

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/go-github/v68/github"
)

// Release holds key metadata extracted from a GitHub Release.
type Release struct {
	TagName     string
	Name        string
	Body        string
	PublishedAt string
	HTMLURL     string
}

// CommitInfo holds commit details including GPG signature verification.
type CommitInfo struct {
	SHA                string
	Message            string
	AuthorName         string
	AuthorDate         string
	VerificationStatus string // "verified" | "unverified" | "unknown"
}

// BranchProtection holds branch protection rule summary.
type BranchProtection struct {
	RequiredStatusChecks    bool
	RequiredReviewCount     int
	DismissStaleReviews     bool
	RequireCodeOwnerReviews bool
	EnforceAdmins           bool
}

// Client wraps go-github for CRA report repo-level operations.
type Client struct {
	gh    *github.Client
	token string // preserved so WithBaseURL can reconstruct auth
}

// NewClient creates a GitHub REST client.
// If token is empty, unauthenticated requests are used (rate limit: 60 req/h).
func NewClient(token string) *Client {
	var httpClient *http.Client
	if token != "" {
		httpClient = &http.Client{
			Transport: &bearerTransport{token: token},
		}
	}
	return &Client{gh: github.NewClient(httpClient), token: token}
}

// WithBaseURL returns a new client pointing at a custom base URL.
// Used in tests to redirect requests to an httptest.Server.
// A fresh github.Client is constructed so that all service sub-clients
// (Repositories, Git, …) share the new BaseURL pointer.
func (c *Client) WithBaseURL(rawURL string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}
	if u.Path == "" || u.Path[len(u.Path)-1] != '/' {
		u.Path += "/"
	}
	var httpClient *http.Client
	if c.token != "" {
		httpClient = &http.Client{Transport: &bearerTransport{token: c.token}}
	}
	newGH := github.NewClient(httpClient)
	newGH.BaseURL = u
	newGH.UploadURL = u
	return &Client{gh: newGH, token: c.token}, nil
}

// GetRelease fetches a GitHub Release by tag. If no Release exists (404),
// it falls back to GET /git/refs/tags/{tag} to confirm the tag exists.
func (c *Client) GetRelease(ctx context.Context, owner, repo, tag string) (*Release, error) {
	rel, resp, err := c.gh.Repositories.GetReleaseByTag(ctx, owner, repo, tag)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusNotFound:
				return c.releaseFromTagRef(ctx, owner, repo, tag)
			case http.StatusForbidden:
				return nil, fmt.Errorf("GitHub API: access denied fetching release (HTTP 403)\nhint: set a GitHub token via 'vulnex config set api_keys.github <token>'")
			}
		}
		return nil, fmt.Errorf("fetching release %s: %w", tag, err)
	}

	r := &Release{
		TagName: rel.GetTagName(),
		Name:    rel.GetName(),
		Body:    rel.GetBody(),
		HTMLURL: rel.GetHTMLURL(),
	}
	if rel.PublishedAt != nil {
		r.PublishedAt = rel.PublishedAt.Format("2006-01-02T15:04:05Z")
	}
	return r, nil
}

func (c *Client) releaseFromTagRef(ctx context.Context, owner, repo, tag string) (*Release, error) {
	ref, resp, err := c.gh.Git.GetRef(ctx, owner, repo, "tags/"+tag)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("tag %q not found in %s/%s", tag, owner, repo)
		}
		return nil, fmt.Errorf("fetching tag ref %s: %w", tag, err)
	}

	r := &Release{TagName: tag, Name: tag}
	if obj := ref.GetObject(); obj != nil {
		r.Body = fmt.Sprintf("(tag-only release; no GitHub Release found — commit %s)", obj.GetSHA())
	}
	return r, nil
}

// GetCommit fetches commit metadata including GPG signature verification status.
// The sha parameter accepts a commit SHA, tag name, or branch name.
func (c *Client) GetCommit(ctx context.Context, owner, repo, sha string) (*CommitInfo, error) {
	commit, resp, err := c.gh.Repositories.GetCommit(ctx, owner, repo, sha, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("commit %q not found in %s/%s", sha, owner, repo)
		}
		return nil, fmt.Errorf("fetching commit %s: %w", sha, err)
	}

	info := &CommitInfo{
		SHA:                commit.GetSHA(),
		VerificationStatus: "unknown",
	}

	if gc := commit.GetCommit(); gc != nil {
		info.Message = gc.GetMessage()
		if a := gc.GetAuthor(); a != nil {
			info.AuthorName = a.GetName()
			if t := a.GetDate(); !t.IsZero() {
				info.AuthorDate = t.Format("2006-01-02")
			}
		}
		if v := gc.GetVerification(); v != nil {
			if v.GetVerified() {
				info.VerificationStatus = "verified"
			} else {
				info.VerificationStatus = "unverified"
			}
		}
	}

	return info, nil
}

// GetBranchProtection fetches branch protection rules.
// Returns nil, nil when branch protection is not configured (HTTP 404).
// Returns an error with a scope hint on HTTP 403.
func (c *Client) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*BranchProtection, error) {
	prot, resp, err := c.gh.Repositories.GetBranchProtection(ctx, owner, repo, branch)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusNotFound:
				return nil, nil
			case http.StatusForbidden:
				return nil, fmt.Errorf("GitHub API: access denied fetching branch protection (HTTP 403)\nhint: branch protection requires a token with 'repo' scope (set via 'vulnex config set api_keys.github <token>')")
			}
		}
		return nil, fmt.Errorf("fetching branch protection for %s: %w", branch, err)
	}

	bp := &BranchProtection{}
	if rsc := prot.GetRequiredStatusChecks(); rsc != nil {
		bp.RequiredStatusChecks = true
	}
	if rprr := prot.GetRequiredPullRequestReviews(); rprr != nil {
		bp.RequiredReviewCount = rprr.RequiredApprovingReviewCount
		bp.DismissStaleReviews = rprr.DismissStaleReviews
		bp.RequireCodeOwnerReviews = rprr.RequireCodeOwnerReviews
	}
	if ea := prot.GetEnforceAdmins(); ea != nil {
		bp.EnforceAdmins = ea.Enabled
	}
	return bp, nil
}

// bearerTransport injects a Bearer token into every outgoing request.
type bearerTransport struct {
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(req)
}
