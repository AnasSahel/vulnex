package enricher

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

// SaveSnapshot computes a risk score and stores a snapshot for a single CVE.
// Errors are logged but never returned — snapshot failures must not break commands.
func SaveSnapshot(ctx context.Context, c cache.Cache, cve *model.EnrichedCVE) {
	if c == nil || cve == nil {
		return
	}

	risk := model.ComputeRisk(cve)
	snap := model.SnapshotFromEnriched(cve, risk)

	data, err := json.Marshal(cve)
	if err != nil {
		slog.Debug("snapshot marshal failed", "cve", cve.ID, "error", err)
	} else {
		snap.Data = data
	}

	if err := c.SaveSnapshot(ctx, snap); err != nil {
		slog.Debug("snapshot save failed", "cve", cve.ID, "error", err)
	}
}

// SaveSnapshots computes risk scores and stores snapshots for multiple CVEs in a batch.
// Errors are logged but never returned — snapshot failures must not break commands.
func SaveSnapshots(ctx context.Context, c cache.Cache, cves []*model.EnrichedCVE) {
	if c == nil || len(cves) == 0 {
		return
	}

	var snapshots []model.Snapshot
	for _, cve := range cves {
		if cve == nil {
			continue
		}

		risk := model.ComputeRisk(cve)
		snap := model.SnapshotFromEnriched(cve, risk)

		data, err := json.Marshal(cve)
		if err != nil {
			slog.Debug("snapshot marshal failed", "cve", cve.ID, "error", err)
		} else {
			snap.Data = data
		}

		snapshots = append(snapshots, snap)
	}

	if err := c.SaveSnapshots(ctx, snapshots); err != nil {
		slog.Debug("batch snapshot save failed", "count", len(snapshots), "error", err)
	}
}
