package githubapp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v68/github"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/api/osv"
	"github.com/trustin-tech/vulnex/internal/sbom"
)

// sbomFileNames are the well-known SBOM file paths to search for in a repo.
var sbomFileNames = []string{
	"bom.json",
	"sbom.json",
	"sbom.cdx.json",
	"sbom.spdx.json",
	"cyclonedx.json",
	".sbom/bom.json",
}

// Handler processes GitHub webhook events.
type Handler struct {
	appID      int64
	privateKey []byte
}

// NewHandler creates a new webhook event handler.
func NewHandler(cfg *Config) *Handler {
	return &Handler{
		appID:      cfg.AppID,
		privateKey: cfg.PrivateKey,
	}
}

// pullRequestEvent is the subset of the GitHub pull_request webhook payload we need.
type pullRequestEvent struct {
	Action       string `json:"action"`
	Number       int    `json:"number"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	PullRequest struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository struct {
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
		Name string `json:"name"`
	} `json:"repository"`
}

// HandlePullRequest processes a pull_request webhook payload.
func (h *Handler) HandlePullRequest(payload []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var event pullRequestEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		slog.Error("parsing pull_request payload", "error", err)
		return
	}

	// Only act on opened and synchronize
	if event.Action != "opened" && event.Action != "synchronize" {
		slog.Debug("ignoring pull_request action", "action", event.Action)
		return
	}

	owner := event.Repository.Owner.Login
	repo := event.Repository.Name
	prNum := event.Number
	headSHA := event.PullRequest.Head.SHA
	installID := event.Installation.ID

	log := slog.With("owner", owner, "repo", repo, "pr", prNum, "sha", headSHA)
	log.Info("processing pull request")

	// Create per-installation GitHub client
	itr, err := ghinstallation.New(http.DefaultTransport, h.appID, installID, h.privateKey)
	if err != nil {
		log.Error("creating installation transport", "error", err)
		return
	}
	gh := github.NewClient(&http.Client{Transport: itr})

	// Create in-progress Check Run
	checkRun, _, err := gh.Checks.CreateCheckRun(ctx, owner, repo, github.CreateCheckRunOptions{
		Name:    "vulnex",
		HeadSHA: headSHA,
		Status:  github.Ptr("in_progress"),
	})
	if err != nil {
		log.Error("creating check run", "error", err)
		return
	}

	// Fetch SBOM
	sbomData, err := h.fetchSBOM(ctx, gh, owner, repo)
	if err != nil {
		log.Warn("fetching SBOM", "error", err)
		h.completeCheckRun(ctx, gh, owner, repo, checkRun.GetID(), &sbom.CheckResult{}, fmt.Errorf("no SBOM found: %v", err))
		return
	}

	// Parse SBOM
	components, err := sbom.ParseBytes(sbomData)
	if err != nil {
		log.Error("parsing SBOM", "error", err)
		h.completeCheckRun(ctx, gh, owner, repo, checkRun.GetID(), &sbom.CheckResult{}, fmt.Errorf("failed to parse SBOM: %v", err))
		return
	}

	// Run vulnerability check
	osvClient := osv.NewClient(api.NewClient(nil))
	result, err := sbom.CheckComponents(ctx, osvClient, components, sbom.CheckOptions{})
	if err != nil {
		log.Error("checking components", "error", err)
		h.completeCheckRun(ctx, gh, owner, repo, checkRun.GetID(), &sbom.CheckResult{}, fmt.Errorf("vulnerability check failed: %v", err))
		return
	}

	// Update Check Run with results
	h.completeCheckRun(ctx, gh, owner, repo, checkRun.GetID(), result, nil)

	// Post PR comment
	comment := FormatPRComment(result)
	_, _, err = gh.Issues.CreateComment(ctx, owner, repo, prNum, &github.IssueComment{
		Body: github.Ptr(comment),
	})
	if err != nil {
		log.Error("posting PR comment", "error", err)
	}

	log.Info("pull request processed", "findings", len(result.Findings))
}

// fetchSBOM tries to get an SBOM from the dependency graph API, then falls back
// to searching for well-known SBOM files in the repository.
func (h *Handler) fetchSBOM(ctx context.Context, gh *github.Client, owner, repo string) ([]byte, error) {
	// Try GitHub Dependency Graph SBOM API
	data, err := h.fetchDependencyGraphSBOM(ctx, gh, owner, repo)
	if err == nil && data != nil {
		slog.Info("fetched SBOM from dependency graph API")
		return data, nil
	}
	slog.Debug("dependency graph SBOM not available", "error", err)

	// Fall back to searching for SBOM files in the repo
	for _, name := range sbomFileNames {
		data, err := h.fetchRepoFile(ctx, gh, owner, repo, name)
		if err == nil && data != nil {
			slog.Info("found SBOM file in repo", "path", name)
			return data, nil
		}
	}

	return nil, fmt.Errorf("no SBOM found via dependency graph or repo files")
}

// fetchDependencyGraphSBOM calls the GitHub Dependency Graph SBOM endpoint.
func (h *Handler) fetchDependencyGraphSBOM(ctx context.Context, gh *github.Client, owner, repo string) ([]byte, error) {
	url := fmt.Sprintf("repos/%s/%s/dependency-graph/sbom", owner, repo)
	req, err := gh.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := gh.Do(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dependency graph API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// fetchRepoFile downloads a single file from the repository's default branch.
func (h *Handler) fetchRepoFile(ctx context.Context, gh *github.Client, owner, repo, path string) ([]byte, error) {
	fc, _, resp, err := gh.Repositories.GetContents(ctx, owner, repo, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if fc == nil {
		return nil, nil
	}

	content, err := fc.GetContent()
	if err != nil {
		return nil, err
	}

	return []byte(content), nil
}

// completeCheckRun updates the Check Run with final results.
func (h *Handler) completeCheckRun(ctx context.Context, gh *github.Client, owner, repo string, checkRunID int64, result *sbom.CheckResult, checkErr error) {
	conclusion, summary, text := FormatCheckRun(result, checkErr)

	opts := github.UpdateCheckRunOptions{
		Name:       "vulnex",
		Status:     github.Ptr("completed"),
		Conclusion: github.Ptr(conclusion),
		Output: &github.CheckRunOutput{
			Title:   github.Ptr("vulnex vulnerability scan"),
			Summary: github.Ptr(summary),
			Text:    github.Ptr(text),
		},
	}

	_, _, err := gh.Checks.UpdateCheckRun(ctx, owner, repo, checkRunID, opts)
	if err != nil {
		slog.Error("updating check run", "error", err)
	}
}
