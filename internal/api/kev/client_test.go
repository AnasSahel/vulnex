package kev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/ratelimit"
)

func testCatalog() *Catalog {
	return &Catalog{
		Title:          "Test KEV",
		CatalogVersion: "2026.03.03",
		Count:          1,
		Vulnerabilities: []Vulnerability{
			{
				CveID:                      "CVE-2021-44228",
				VendorProject:              "Apache",
				Product:                    "Log4j",
				VulnerabilityName:          "Apache Log4j2 RCE",
				DateAdded:                  "2021-12-10",
				ShortDescription:           "Apache Log4j2 JNDI RCE",
				RequiredAction:             "Apply updates",
				DueDate:                    "2021-12-24",
				KnownRansomwareCampaignUse: "Known",
				Notes:                      "",
			},
		},
	}
}

func newTestServer(t *testing.T, cat *Catalog) *httptest.Server {
	t.Helper()
	data, err := json.Marshal(cat)
	if err != nil {
		t.Fatalf("marshalling test catalog: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"test-etag"`)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
}

func TestFetchCatalog_NilCache(t *testing.T) {
	cat := testCatalog()
	srv := newTestServer(t, cat)
	defer srv.Close()

	// Patch the feed URL for testing.
	origURL := kevFeedURL
	defer func() { restoreKEVFeedURL(origURL) }()
	setKEVFeedURL(srv.URL)

	httpClient := api.NewClient(ratelimit.New())
	client := NewClient(httpClient, nil)

	result, err := client.FetchCatalog(context.Background())
	if err != nil {
		t.Fatalf("FetchCatalog with nil cache: %v", err)
	}
	if result.CatalogVersion != cat.CatalogVersion {
		t.Errorf("got version %q, want %q", result.CatalogVersion, cat.CatalogVersion)
	}
	if len(result.Vulnerabilities) != 1 {
		t.Errorf("got %d vulnerabilities, want 1", len(result.Vulnerabilities))
	}
}

func TestCheck_NilCache(t *testing.T) {
	cat := testCatalog()
	srv := newTestServer(t, cat)
	defer srv.Close()

	origURL := kevFeedURL
	defer func() { restoreKEVFeedURL(origURL) }()
	setKEVFeedURL(srv.URL)

	httpClient := api.NewClient(ratelimit.New())
	client := NewClient(httpClient, nil)

	entry, err := client.Check(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("Check with nil cache: %v", err)
	}
	if entry == nil {
		t.Fatal("expected KEV entry, got nil")
	}
	if entry.CVEID != "CVE-2021-44228" {
		t.Errorf("got CVE ID %q, want CVE-2021-44228", entry.CVEID)
	}
}

func TestCheck_NilCache_NotFound(t *testing.T) {
	cat := testCatalog()
	srv := newTestServer(t, cat)
	defer srv.Close()

	origURL := kevFeedURL
	defer func() { restoreKEVFeedURL(origURL) }()
	setKEVFeedURL(srv.URL)

	httpClient := api.NewClient(ratelimit.New())
	client := NewClient(httpClient, nil)

	entry, err := client.Check(context.Background(), "CVE-9999-99999")
	if err != nil {
		t.Fatalf("Check with nil cache: %v", err)
	}
	if entry != nil {
		t.Errorf("expected nil entry for unknown CVE, got %+v", entry)
	}
}

func TestStats_NilCache(t *testing.T) {
	cat := testCatalog()
	srv := newTestServer(t, cat)
	defer srv.Close()

	origURL := kevFeedURL
	defer func() { restoreKEVFeedURL(origURL) }()
	setKEVFeedURL(srv.URL)

	httpClient := api.NewClient(ratelimit.New())
	client := NewClient(httpClient, nil)

	stats, err := client.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats with nil cache: %v", err)
	}
	if stats.TotalCount != 1 {
		t.Errorf("got TotalCount %d, want 1", stats.TotalCount)
	}
	if stats.RansomwareCount != 1 {
		t.Errorf("got RansomwareCount %d, want 1", stats.RansomwareCount)
	}
}
