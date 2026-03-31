import type { StepConfig, Handlers } from "motia";
import { createDb, syncLog, cve, cveScore } from "@vulnex/db";
import { eq } from "drizzle-orm";

const EPSS_API = "https://api.first.org/data/v1/epss";
const BATCH_SIZE = 100;

export const config = {
  name: "sync-epss",
  description: "Fetches EPSS scores from the FIRST.org API",
  triggers: [{ type: "queue", topic: "sync.epss" }],
  flows: ["vulnerability-sync"],
} as const satisfies StepConfig;

export const handler: Handlers<typeof config> = async (_input, { logger }) => {
  const db = createDb(process.env.DATABASE_URL!);

  logger.info("Starting EPSS sync");

  // Get all CVE IDs from the database
  const cves = await db.select({ id: cve.id }).from(cve);

  if (cves.length === 0) {
    logger.info("No CVEs in database, skipping EPSS sync");
    return;
  }

  let totalSynced = 0;

  try {
    // Process in batches of 100
    for (let i = 0; i < cves.length; i += BATCH_SIZE) {
      const batch = cves.slice(i, i + BATCH_SIZE);
      const cveIds = batch.map((c) => c.id).join(",");

      const res = await fetch(`${EPSS_API}?cve=${cveIds}`);
      if (!res.ok) {
        throw new Error(`EPSS API error: ${res.status} ${res.statusText}`);
      }

      const data = await res.json();

      if (!data.data?.length) continue;

      for (const entry of data.data) {
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

      logger.info(
        `EPSS sync progress: ${Math.min(i + BATCH_SIZE, cves.length)}/${cves.length}`
      );
    }

    await db
      .insert(syncLog)
      .values({
        source: "epss",
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

    logger.info(`EPSS sync complete: ${totalSynced} scores synced`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`EPSS sync failed: ${message}`);

    await db
      .insert(syncLog)
      .values({
        source: "epss",
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
