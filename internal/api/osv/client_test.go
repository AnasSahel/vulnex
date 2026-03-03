package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/ratelimit"
)

func TestQueryByCVE_DirectHit(t *testing.T) {
	vuln := OSVVulnerability{
		ID:      "CVE-2021-44228",
		Summary: "Log4j RCE",
		Severity: []OSVSeverity{
			{Type: "CVSS_V3", Score: "critical"},
		},
		Affected: []OSVAffected{
			{
				Package: OSVPackage{
					Ecosystem: "Maven",
					Name:      "org.apache.logging.log4j:log4j-core",
				},
				Ranges: []OSVRange{
					{
						Type: "ECOSYSTEM",
						Events: []OSVEvent{
							{Introduced: "2.0"},
							{Fixed: "2.15.0"},
						},
					},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vulns/CVE-2021-44228" {
			json.NewEncoder(w).Encode(vuln)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	origURL := vulnURL
	defer func() { vulnURL = origURL }()
	vulnURL = srv.URL + "/v1/vulns/"

	httpClient := api.NewClient(ratelimit.New())
	client := NewClient(httpClient)

	advisories, pkgs, err := client.QueryByCVE(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("QueryByCVE direct hit: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advisories))
	}
	if advisories[0].ID != "CVE-2021-44228" {
		t.Errorf("advisory ID = %q, want CVE-2021-44228", advisories[0].ID)
	}
	if advisories[0].Source != "osv" {
		t.Errorf("advisory Source = %q, want osv", advisories[0].Source)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if pkgs[0].Name != "org.apache.logging.log4j:log4j-core" {
		t.Errorf("package Name = %q, want org.apache.logging.log4j:log4j-core", pkgs[0].Name)
	}
	if pkgs[0].Fixed != "2.15.0" {
		t.Errorf("package Fixed = %q, want 2.15.0", pkgs[0].Fixed)
	}
}

func TestQueryByCVE_AliasHit(t *testing.T) {
	// Simulate: CVE-2023-99999 resolves via alias to GHSA-xxxx-yyyy-zzzz,
	// which in turn has a PYSEC sibling alias.
	ghsaVuln := OSVVulnerability{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Summary: "Test advisory via alias",
		Aliases: []string{"CVE-2023-99999", "PYSEC-2023-42"},
		Affected: []OSVAffected{
			{
				Package: OSVPackage{Ecosystem: "npm", Name: "test-pkg"},
				Ranges: []OSVRange{
					{Type: "ECOSYSTEM", Events: []OSVEvent{{Introduced: "0"}, {Fixed: "1.0.1"}}},
				},
			},
		},
	}
	pysecVuln := OSVVulnerability{
		ID:      "PYSEC-2023-42",
		Summary: "Test advisory PYSEC sibling",
		Aliases: []string{"CVE-2023-99999", "GHSA-xxxx-yyyy-zzzz"},
		Affected: []OSVAffected{
			{
				Package: OSVPackage{Ecosystem: "PyPI", Name: "test-pypkg"},
				Ranges: []OSVRange{
					{Type: "ECOSYSTEM", Events: []OSVEvent{{Introduced: "0"}, {Fixed: "2.0.0"}}},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vulns/CVE-2023-99999":
			// Alias resolution: return the GHSA record.
			json.NewEncoder(w).Encode(ghsaVuln)
		case "/v1/vulns/PYSEC-2023-42":
			json.NewEncoder(w).Encode(pysecVuln)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	origURL := vulnURL
	defer func() { vulnURL = origURL }()
	vulnURL = srv.URL + "/v1/vulns/"

	httpClient := api.NewClient(ratelimit.New())
	client := NewClient(httpClient)

	advisories, pkgs, err := client.QueryByCVE(context.Background(), "CVE-2023-99999")
	if err != nil {
		t.Fatalf("QueryByCVE alias hit: %v", err)
	}
	// Should have 2 advisories: the GHSA primary + the PYSEC sibling.
	if len(advisories) != 2 {
		t.Fatalf("got %d advisories, want 2", len(advisories))
	}
	if advisories[0].ID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("first advisory ID = %q, want GHSA-xxxx-yyyy-zzzz", advisories[0].ID)
	}
	if advisories[1].ID != "PYSEC-2023-42" {
		t.Errorf("second advisory ID = %q, want PYSEC-2023-42", advisories[1].ID)
	}
	// Should have 2 affected packages: npm/test-pkg and PyPI/test-pypkg.
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
}

func TestQueryByCVE_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	origURL := vulnURL
	defer func() { vulnURL = origURL }()
	vulnURL = srv.URL + "/v1/vulns/"

	httpClient := api.NewClient(ratelimit.New())
	client := NewClient(httpClient)

	advisories, pkgs, err := client.QueryByCVE(context.Background(), "CVE-9999-99999")
	if err != nil {
		t.Fatalf("QueryByCVE no match should return nil error, got: %v", err)
	}
	if len(advisories) != 0 {
		t.Errorf("got %d advisories, want 0", len(advisories))
	}
	if len(pkgs) != 0 {
		t.Errorf("got %d packages, want 0", len(pkgs))
	}
}

func TestQueryByCVE_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	origURL := vulnURL
	defer func() { vulnURL = origURL }()
	vulnURL = srv.URL + "/v1/vulns/"

	httpClient := api.NewClient(ratelimit.New())
	client := NewClient(httpClient)

	_, _, err := client.QueryByCVE(context.Background(), "CVE-2021-44228")
	if err == nil {
		t.Fatal("QueryByCVE should return error on server error")
	}
}
