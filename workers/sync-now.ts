/**
 * Direct sync script — bypasses Motia, runs with bun directly.
 * Usage: cd workers && bun run sync-now.ts
 */
import { createDb, cve, cveScore, kevEntry, syncLog } from "@vulnex/db";

const DATABASE_URL = process.env.DATABASE_URL!;
const db = createDb(DATABASE_URL);

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const EPSS_API = "https://api.first.org/data/v1/epss";
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── NVD Sync ───────────────────────────────────────────────────────────────
async function syncNvd() {
  console.log("[NVD] Starting sync (last 30 days)...");

  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const params = new URLSearchParams({
    resultsPerPage: "200",
    startIndex: "0",
    lastModStartDate: thirtyDaysAgo.toISOString().replace("Z", "+00:00"),
    lastModEndDate: new Date().toISOString().replace("Z", "+00:00"),
  });

  const headers: Record<string, string> = { "User-Agent": "VulneX/1.0" };
  if (process.env.NVD_API_KEY) headers["apiKey"] = process.env.NVD_API_KEY;

  let totalSynced = 0;
  let startIndex = 0;
  let totalResults = Infinity;

  while (startIndex < totalResults) {
    params.set("startIndex", startIndex.toString());
    const res = await fetch(`${NVD_API}?${params}`, { headers });

    if (!res.ok) {
      console.error(`[NVD] API error: ${res.status} ${res.statusText}`);
      break;
    }

    const data = await res.json();
    totalResults = data.totalResults ?? 0;
    if (!data.vulnerabilities?.length) break;

    for (const item of data.vulnerabilities) {
      const vuln = item.cve;
      if (!vuln?.id) continue;

      const desc = vuln.descriptions?.find((d: any) => d.lang === "en")?.value;

      await db
        .insert(cve)
        .values({
          id: vuln.id,
          description: desc ?? null,
          publishedAt: vuln.published ? new Date(vuln.published) : null,
          lastModified: vuln.lastModified ? new Date(vuln.lastModified) : null,
          sourceId: vuln.sourceIdentifier ?? null,
          status: vuln.vulnStatus ?? null,
        })
        .onConflictDoUpdate({
          target: cve.id,
          set: {
            description: desc ?? null,
            lastModified: vuln.lastModified ? new Date(vuln.lastModified) : null,
            sourceId: vuln.sourceIdentifier ?? null,
            status: vuln.vulnStatus ?? null,
            updatedAt: new Date(),
          },
        });

      // CVSS score
      const cvssMetric = vuln.metrics?.cvssMetricV31?.[0] ?? vuln.metrics?.cvssMetricV30?.[0];
      if (cvssMetric?.cvssData) {
        await db.insert(cveScore).values({
          cveId: vuln.id,
          cvssV3Score: cvssMetric.cvssData.baseScore ?? null,
          cvssV3Vector: cvssMetric.cvssData.vectorString ?? null,
          source: "nvd",
          scoredAt: new Date(),
        });
      }

      totalSynced++;
    }

    startIndex += data.vulnerabilities.length;
    console.log(`[NVD] Progress: ${startIndex}/${totalResults}`);

    if (startIndex < totalResults) {
      await sleep(process.env.NVD_API_KEY ? 1000 : 6500);
    }
  }

  await db
    .insert(syncLog)
    .values({ source: "nvd", lastSyncedAt: new Date(), status: "success", itemsSynced: totalSynced })
    .onConflictDoUpdate({
      target: syncLog.source,
      set: { lastSyncedAt: new Date(), status: "success", itemsSynced: totalSynced, errorMessage: null, updatedAt: new Date() },
    });

  console.log(`[NVD] Done: ${totalSynced} CVEs synced`);
  return totalSynced;
}

// ─── KEV Sync ───────────────────────────────────────────────────────────────
async function syncKev() {
  console.log("[KEV] Starting sync...");

  const res = await fetch(KEV_URL);
  if (!res.ok) throw new Error(`KEV error: ${res.status}`);

  const data = await res.json();
  const vulns = data.vulnerabilities ?? [];
  let totalSynced = 0;

  for (const vuln of vulns) {
    if (!vuln.cveID) continue;

    // Ensure CVE record exists
    await db.insert(cve).values({ id: vuln.cveID, description: vuln.shortDescription ?? null, status: "KEV" }).onConflictDoNothing();

    // Check if KEV entry exists
    const { eq } = await import("drizzle-orm");
    const existing = await db.select({ id: kevEntry.id }).from(kevEntry).where(eq(kevEntry.cveId, vuln.cveID)).limit(1);

    if (existing.length === 0) {
      await db.insert(kevEntry).values({
        cveId: vuln.cveID,
        vendor: vuln.vendorProject ?? null,
        product: vuln.product ?? null,
        vulnerabilityName: vuln.vulnerabilityName ?? null,
        dateAdded: vuln.dateAdded ?? null,
        dueDate: vuln.dueDate ?? null,
        knownRansomware: vuln.knownRansomwareCampaignUse === "Known",
        notes: vuln.notes ?? null,
      });
      totalSynced++;
    }
  }

  await db
    .insert(syncLog)
    .values({ source: "kev", lastSyncedAt: new Date(), status: "success", itemsSynced: totalSynced })
    .onConflictDoUpdate({
      target: syncLog.source,
      set: { lastSyncedAt: new Date(), status: "success", itemsSynced: totalSynced, errorMessage: null, updatedAt: new Date() },
    });

  console.log(`[KEV] Done: ${totalSynced} new entries`);
  return totalSynced;
}

// ─── EPSS Sync ──────────────────────────────────────────────────────────────
async function syncEpss() {
  console.log("[EPSS] Starting sync...");

  const allCves = await db.select({ id: cve.id }).from(cve);
  if (allCves.length === 0) {
    console.log("[EPSS] No CVEs in database, skipping");
    return 0;
  }

  let totalSynced = 0;
  const BATCH = 100;

  for (let i = 0; i < allCves.length; i += BATCH) {
    const batch = allCves.slice(i, i + BATCH);
    const ids = batch.map((c) => c.id).join(",");

    const res = await fetch(`${EPSS_API}?cve=${ids}`);
    if (!res.ok) {
      console.error(`[EPSS] API error: ${res.status}`);
      continue;
    }

    const data = await res.json();
    for (const entry of data.data ?? []) {
      if (!entry.cve) continue;
      await db.insert(cveScore).values({
        cveId: entry.cve,
        epssScore: parseFloat(entry.epss),
        epssPercentile: parseFloat(entry.percentile),
        source: "epss",
        scoredAt: entry.date ? new Date(entry.date) : new Date(),
      });
      totalSynced++;
    }

    console.log(`[EPSS] Progress: ${Math.min(i + BATCH, allCves.length)}/${allCves.length}`);
  }

  await db
    .insert(syncLog)
    .values({ source: "epss", lastSyncedAt: new Date(), status: "success", itemsSynced: totalSynced })
    .onConflictDoUpdate({
      target: syncLog.source,
      set: { lastSyncedAt: new Date(), status: "success", itemsSynced: totalSynced, errorMessage: null, updatedAt: new Date() },
    });

  console.log(`[EPSS] Done: ${totalSynced} scores synced`);
  return totalSynced;
}

// ─── Run all ────────────────────────────────────────────────────────────────
async function main() {
  console.log("=== VulneX Data Sync ===\n");

  try {
    // NVD first (gets CVE records)
    const nvdCount = await syncNvd();

    // KEV (adds more CVE records + KEV entries)
    const kevCount = await syncKev();

    // EPSS (scores for existing CVEs)
    const epssCount = await syncEpss();

    console.log(`\n=== Sync Complete ===`);
    console.log(`NVD:  ${nvdCount} CVEs`);
    console.log(`KEV:  ${kevCount} entries`);
    console.log(`EPSS: ${epssCount} scores`);
  } catch (err) {
    console.error("Sync failed:", err);
    process.exit(1);
  }
}

main();
