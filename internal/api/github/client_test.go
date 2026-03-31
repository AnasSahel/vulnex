package github_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	githubapi "github.com/trustin-tech/vulnex/internal/api/github"
)

// newTestClient sets up a client pointing at the given httptest.Server.
func newTestClient(t *testing.T, mux *http.ServeMux, token string) *githubapi.Client {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := githubapi.NewClient(token)
	c2, err := c.WithBaseURL(srv.URL + "/")
	if err != nil {
		t.Fatalf("WithBaseURL: %v", err)
	}
	return c2
}

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- GetRelease ---

func TestGetRelease_200(t *testing.T) {
	pub := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"tag_name":     "v1.0.0",
			"name":         "Release v1.0.0",
			"body":         "First release",
			"html_url":     "https://github.com/owner/repo/releases/tag/v1.0.0",
			"published_at": pub.Format(time.RFC3339),
		})
	})
	c := newTestClient(t, mux, "tok")

	rel, err := c.GetRelease(context.Background(), "owner", "repo", "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rel.TagName != "v1.0.0" {
		t.Errorf("TagName = %q, want %q", rel.TagName, "v1.0.0")
	}
	if rel.Name != "Release v1.0.0" {
		t.Errorf("Name = %q, want %q", rel.Name, "Release v1.0.0")
	}
	if rel.Body != "First release" {
		t.Errorf("Body = %q, want %q", rel.Body, "First release")
	}
	if rel.PublishedAt == "" {
		t.Error("PublishedAt should be set")
	}
}

func TestGetRelease_404_TagNotFound(t *testing.T) {
	mux := http.NewServeMux()
	// Release 404 and tag ref 404 → error mentioning tag name
	mux.HandleFunc("/repos/owner/repo/releases/tags/v9.9.9", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
	})
	mux.HandleFunc("/repos/owner/repo/git/ref/tags/v9.9.9", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
	})
	c := newTestClient(t, mux, "tok")

	_, err := c.GetRelease(context.Background(), "owner", "repo", "v9.9.9")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "v9.9.9") {
		t.Errorf("error should mention tag name; got: %v", err)
	}
}

func TestGetRelease_404_FallbackToTagRef(t *testing.T) {
	mux := http.NewServeMux()
	// No GitHub Release, but the tag ref exists
	mux.HandleFunc("/repos/owner/repo/releases/tags/v1.1.0", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
	})
	mux.HandleFunc("/repos/owner/repo/git/ref/tags/v1.1.0", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ref": "refs/tags/v1.1.0",
			"object": map[string]string{
				"sha":  "abc1234",
				"type": "commit",
			},
		})
	})
	c := newTestClient(t, mux, "tok")

	rel, err := c.GetRelease(context.Background(), "owner", "repo", "v1.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rel.TagName != "v1.1.0" {
		t.Errorf("TagName = %q, want %q", rel.TagName, "v1.1.0")
	}
	if !strings.Contains(rel.Body, "abc1234") {
		t.Errorf("Body should contain commit SHA; got: %q", rel.Body)
	}
}

func TestGetRelease_403(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "Forbidden"})
	})
	c := newTestClient(t, mux, "")

	_, err := c.GetRelease(context.Background(), "owner", "repo", "v1.0.0")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention 403; got: %v", err)
	}
	if !strings.Contains(err.Error(), "hint") {
		t.Errorf("error should include a hint about token; got: %v", err)
	}
}

// --- GetCommit ---

func TestGetCommit_SignedCommit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/commits/abc1234", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"sha": "abc1234",
			"commit": map[string]any{
				"message": "feat: add feature",
				"author": map[string]string{
					"name": "Alice",
					"date": "2026-03-01T10:00:00Z",
				},
				"verification": map[string]any{
					"verified": true,
					"reason":   "valid",
				},
			},
		})
	})
	c := newTestClient(t, mux, "tok")

	info, err := c.GetCommit(context.Background(), "owner", "repo", "abc1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.VerificationStatus != "verified" {
		t.Errorf("VerificationStatus = %q, want %q", info.VerificationStatus, "verified")
	}
	if info.AuthorName != "Alice" {
		t.Errorf("AuthorName = %q, want %q", info.AuthorName, "Alice")
	}
}

func TestGetCommit_UnsignedCommit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/commits/def5678", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"sha": "def5678",
			"commit": map[string]any{
				"message": "fix: something",
				"author": map[string]string{
					"name": "Bob",
					"date": "2026-03-01T12:00:00Z",
				},
				"verification": map[string]any{
					"verified": false,
					"reason":   "unsigned",
				},
			},
		})
	})
	c := newTestClient(t, mux, "tok")

	info, err := c.GetCommit(context.Background(), "owner", "repo", "def5678")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.VerificationStatus != "unverified" {
		t.Errorf("VerificationStatus = %q, want %q", info.VerificationStatus, "unverified")
	}
}

// --- GetBranchProtection ---

func TestGetBranchProtection_ProtectionRules(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"required_status_checks": map[string]any{
				"strict":   true,
				"contexts": []string{"ci/test"},
			},
			"required_pull_request_reviews": map[string]any{
				"required_approving_review_count": 2,
				"dismiss_stale_reviews":           true,
				"require_code_owner_reviews":      false,
			},
			"enforce_admins": map[string]any{
				"url":     "https://api.github.com/repos/owner/repo/branches/main/protection/enforce_admins",
				"enabled": true,
			},
		})
	})
	c := newTestClient(t, mux, "tok")

	bp, err := c.GetBranchProtection(context.Background(), "owner", "repo", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bp == nil {
		t.Fatal("expected non-nil BranchProtection")
	}
	if !bp.RequiredStatusChecks {
		t.Error("RequiredStatusChecks should be true")
	}
	if bp.RequiredReviewCount != 2 {
		t.Errorf("RequiredReviewCount = %d, want 2", bp.RequiredReviewCount)
	}
	if !bp.DismissStaleReviews {
		t.Error("DismissStaleReviews should be true")
	}
	if !bp.EnforceAdmins {
		t.Error("EnforceAdmins should be true")
	}
}

func TestGetBranchProtection_NotConfigured(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Branch not protected"})
	})
	c := newTestClient(t, mux, "tok")

	bp, err := c.GetBranchProtection(context.Background(), "owner", "repo", "main")
	if err != nil {
		t.Fatalf("expected nil error for 404, got: %v", err)
	}
	if bp != nil {
		t.Error("expected nil BranchProtection for unprotected branch")
	}
}

func TestGetBranchProtection_403_ScopeHint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main/protection", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "Resource not accessible by integration"})
	})
	c := newTestClient(t, mux, "limited-token")

	_, err := c.GetBranchProtection(context.Background(), "owner", "repo", "main")
	if err == nil {
		t.Fatal("expected error for 403, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention 403; got: %v", err)
	}
	if !strings.Contains(err.Error(), "repo") && !strings.Contains(err.Error(), "scope") {
		t.Errorf("error should include scope hint; got: %v", err)
	}
}

// --- Token injection ---

func TestNewClient_TokenSetInHeader(t *testing.T) {
	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		writeJSON(w, http.StatusOK, map[string]any{
			"tag_name": "v1.0.0",
			"name":     "v1.0.0",
		})
	})
	c := newTestClient(t, mux, "mytoken")

	_, _ = c.GetRelease(context.Background(), "owner", "repo", "v1.0.0")
	if gotAuth != "Bearer mytoken" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer mytoken")
	}
}

func TestNewClient_NoTokenNoAuthHeader(t *testing.T) {
	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		writeJSON(w, http.StatusOK, map[string]any{
			"tag_name": "v1.0.0",
			"name":     "v1.0.0",
		})
	})
	c := newTestClient(t, mux, "") // no token

	_, _ = c.GetRelease(context.Background(), "owner", "repo", "v1.0.0")
	if gotAuth != "" {
		t.Errorf("Authorization header should be empty when no token; got %q", gotAuth)
	}
}
