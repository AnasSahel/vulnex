package enricher

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/trustin-tech/vulnex/internal/api/epss"
	"github.com/trustin-tech/vulnex/internal/api/ghsa"
	"github.com/trustin-tech/vulnex/internal/api/kev"
	"github.com/trustin-tech/vulnex/internal/api/nvd"
	"github.com/trustin-tech/vulnex/internal/api/osv"
	"github.com/trustin-tech/vulnex/internal/model"
)

// Enricher aggregates data from multiple vulnerability intelligence sources.
type Enricher struct {
	nvd  *nvd.Client
	kev  *kev.Client
	epss *epss.Client
	ghsa *ghsa.Client
	osv  *osv.Client
}

// New creates a new Enricher with the given API clients.
func New(nvdClient *nvd.Client, kevClient *kev.Client, epssClient *epss.Client, ghsaClient *ghsa.Client, osvClient *osv.Client) *Enricher {
	return &Enricher{
		nvd:  nvdClient,
		kev:  kevClient,
		epss: epssClient,
		ghsa: ghsaClient,
		osv:  osvClient,
	}
}

// Enrich fetches data from all sources concurrently and merges into an EnrichedCVE.
// Partial failures are tolerated — available data is returned with warnings logged.
func (e *Enricher) Enrich(ctx context.Context, cveID string) (*model.EnrichedCVE, error) {
	g, gctx := errgroup.WithContext(ctx)

	var (
		nvdResult  *model.EnrichedCVE
		epssResult *model.EPSSScore
		kevResult  *model.KEVEntry
		ghsaAdvs   []model.Advisory
		ghsaPkgs   []model.AffectedPkg
		osvAdvs    []model.Advisory
		osvPkgs    []model.AffectedPkg
	)

	// NVD — primary CVE data
	if e.nvd != nil {
		g.Go(func() error {
			var err error
			nvdResult, err = e.nvd.GetCVE(gctx, cveID)
			if err != nil {
				slog.Warn("NVD fetch failed", "cve", cveID, "error", err)
			}
			return nil // non-fatal
		})
	}

	// EPSS — exploitation probability
	if e.epss != nil {
		g.Go(func() error {
			var err error
			epssResult, err = e.epss.GetScore(gctx, cveID)
			if err != nil {
				slog.Warn("EPSS fetch failed", "cve", cveID, "error", err)
			}
			return nil
		})
	}

	// KEV — known exploitation status
	if e.kev != nil {
		g.Go(func() error {
			var err error
			kevResult, err = e.kev.Check(gctx, cveID)
			if err != nil {
				slog.Warn("KEV check failed", "cve", cveID, "error", err)
			}
			return nil
		})
	}

	// GHSA — GitHub advisories and affected packages
	if e.ghsa != nil {
		g.Go(func() error {
			var err error
			ghsaAdvs, ghsaPkgs, err = e.ghsa.FindByCVE(gctx, cveID)
			if err != nil {
				slog.Warn("GHSA fetch failed", "cve", cveID, "error", err)
			}
			return nil
		})
	}

	// OSV — open-source vulnerability data
	if e.osv != nil {
		g.Go(func() error {
			var err error
			osvAdvs, osvPkgs, err = e.osv.QueryByCVE(gctx, cveID)
			if err != nil {
				slog.Warn("OSV fetch failed", "cve", cveID, "error", err)
			}
			return nil
		})
	}

	_ = g.Wait()

	return e.merge(cveID, nvdResult, epssResult, kevResult, ghsaAdvs, ghsaPkgs, osvAdvs, osvPkgs), nil
}

// EnrichBatch enriches multiple CVEs concurrently with bounded parallelism.
func (e *Enricher) EnrichBatch(ctx context.Context, cveIDs []string) ([]*model.EnrichedCVE, error) {
	results := make([]*model.EnrichedCVE, len(cveIDs))
	sem := make(chan struct{}, 10) // concurrency limit

	g, gctx := errgroup.WithContext(ctx)

	for i, id := range cveIDs {
		g.Go(func() error {
			sem <- struct{}{}
			defer func() { <-sem }()

			enriched, err := e.Enrich(gctx, id)
			if err != nil {
				slog.Warn("enrichment failed", "cve", id, "error", err)
				return nil
			}
			results[i] = enriched
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return results, err
	}
	return results, nil
}

// merge combines data from all sources into a single EnrichedCVE.
func (e *Enricher) merge(
	cveID string,
	nvdResult *model.EnrichedCVE,
	epssResult *model.EPSSScore,
	kevResult *model.KEVEntry,
	ghsaAdvs []model.Advisory,
	ghsaPkgs []model.AffectedPkg,
	osvAdvs []model.Advisory,
	osvPkgs []model.AffectedPkg,
) *model.EnrichedCVE {
	var result *model.EnrichedCVE

	if nvdResult != nil {
		result = nvdResult
	} else {
		result = &model.EnrichedCVE{
			ID:          cveID,
			DataSources: []string{},
		}
	}

	// Merge EPSS
	if epssResult != nil {
		result.EPSS = epssResult
		result.DataSources = appendUnique(result.DataSources, "epss")
	}

	// Merge KEV
	if kevResult != nil {
		result.KEV = kevResult
		result.DataSources = appendUnique(result.DataSources, "kev")
	}

	// Merge GHSA advisories
	if len(ghsaAdvs) > 0 {
		result.Advisories = append(result.Advisories, ghsaAdvs...)
		result.DataSources = appendUnique(result.DataSources, "ghsa")
	}
	if len(ghsaPkgs) > 0 {
		result.AffectedPkgs = append(result.AffectedPkgs, ghsaPkgs...)
	}

	// Merge OSV advisories
	if len(osvAdvs) > 0 {
		result.Advisories = append(result.Advisories, osvAdvs...)
		result.DataSources = appendUnique(result.DataSources, "osv")
	}
	if len(osvPkgs) > 0 {
		result.AffectedPkgs = append(result.AffectedPkgs, osvPkgs...)
	}

	// Detect CVSS score conflicts between sources
	if conflicts := ReconcileScores(result); len(conflicts) > 0 {
		result.ScoreConflicts = conflicts
	}

	result.FetchedAt = time.Now()
	return result
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
