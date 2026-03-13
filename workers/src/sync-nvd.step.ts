import type { StepConfig, Handlers } from "motia";
import { createDb, syncLog, cve, cveScore } from "@vulnex/db";
import { eq } from "drizzle-orm";

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE_SIZE = 200;
const RATE_LIMIT_DELAY = 6500; // 5 requests per 30s without API key

export const config = {
  name: "sync-nvd",
  description: "Fetches CVE records and CVSS scores from the NVD 2.0 API",
  triggers: [{ type: "queue", topic: "sync.nvd" }],
  flows: ["vulnerability-sync"],
} as const satisfies StepConfig;

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchNvdPage(params: URLSearchParams): Promise<any> {
  const url = `${NVD_API}?${params.toString()}`;
  const headers: Record<string, string> = { "User-Agent": "VulneX/1.0" };

  const apiKey = process.env.NVD_API_KEY;
  if (apiKey) {
    headers["apiKey"] = apiKey;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`NVD API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export const handler: Handlers<typeof config> = async (_input, { logger }) => {
  const db = createDb(process.env.DATABASE_URL!);

  logger.info("Starting NVD sync");

  // Get last sync cursor
  const [lastSync] = await db
    .select()
    .from(syncLog)
    .where(eq(syncLog.source, "nvd"));

  const params = new URLSearchParams({
    resultsPerPage: PAGE_SIZE.toString(),
    startIndex: "0",
  });

  // Use lastModStartDate for incremental sync, or last 30 days for initial
  if (lastSync?.lastSyncedAt) {
    const since = lastSync.lastSyncedAt.toISOString().replace("Z", "+00:00");
    params.set("lastModStartDate", since);
    params.set("lastModEndDate", new Date().toISOString().replace("Z", "+00:00"));
  } else {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    params.set("lastModStartDate", thirtyDaysAgo.toISOString().replace("Z", "+00:00"));
    params.set("lastModEndDate", new Date().toISOString().replace("Z", "+00:00"));
  }

  let totalSynced = 0;
  let startIndex = 0;
  let totalResults = Infinity;

  try {
    while (startIndex < totalResults) {
      params.set("startIndex", startIndex.toString());

      const data = await fetchNvdPage(params);
      totalResults = data.totalResults ?? 0;

      if (!data.vulnerabilities?.length) break;

      for (const item of data.vulnerabilities) {
        const vuln = item.cve;
        if (!vuln?.id) continue;

        // Upsert CVE record
        const englishDesc = vuln.descriptions?.find(
          (d: any) => d.lang === "en"
        )?.value;

        await db
          .insert(cve)
          .values({
            id: vuln.id,
            description: englishDesc ?? null,
            publishedAt: vuln.published ? new Date(vuln.published) : null,
            lastModified: vuln.lastModified ? new Date(vuln.lastModified) : null,
            sourceId: vuln.sourceIdentifier ?? null,
            status: vuln.vulnStatus ?? null,
          })
          .onConflictDoUpdate({
            target: cve.id,
            set: {
              description: englishDesc ?? null,
              lastModified: vuln.lastModified ? new Date(vuln.lastModified) : null,
              sourceId: vuln.sourceIdentifier ?? null,
              status: vuln.vulnStatus ?? null,
              updatedAt: new Date(),
            },
          });

        // Extract CVSS v3 score
        const cvssMetric =
          vuln.metrics?.cvssMetricV31?.[0] ?? vuln.metrics?.cvssMetricV30?.[0];

        if (cvssMetric?.cvssData) {
          await db
            .insert(cveScore)
            .values({
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
      logger.info(`NVD sync progress: ${startIndex}/${totalResults}`);

      // Rate limit
      if (startIndex < totalResults) {
        await sleep(process.env.NVD_API_KEY ? 1000 : RATE_LIMIT_DELAY);
      }
    }

    // Update sync log
    await db
      .insert(syncLog)
      .values({
        source: "nvd",
        lastSyncedAt: new Date(),
        status: "success",
        itemsSynced: totalSynced,
      })
      .onConflictDoUpdate({
        target: syncLog.source,
        set: {
          lastSyncedAt: new Date(),
          status: "success",
          itemsSynced: totalSynced,
          errorMessage: null,
          updatedAt: new Date(),
        },
      });

    logger.info(`NVD sync complete: ${totalSynced} CVEs synced`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`NVD sync failed: ${message}`);

    await db
      .insert(syncLog)
      .values({
        source: "nvd",
        lastSyncedAt: new Date(),
        status: "error",
        errorMessage: message,
        itemsSynced: totalSynced,
      })
      .onConflictDoUpdate({
        target: syncLog.source,
        set: {
          lastSyncedAt: new Date(),
          status: "error",
          errorMessage: message,
          itemsSynced: totalSynced,
          updatedAt: new Date(),
        },
      });
  }
};
