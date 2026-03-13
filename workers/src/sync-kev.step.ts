import type { StepConfig, Handlers } from "motia";
import { createDb, syncLog, cve, kevEntry } from "@vulnex/db";
import { eq } from "drizzle-orm";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export const config = {
  name: "sync-kev",
  description: "Fetches the CISA Known Exploited Vulnerabilities catalog",
  triggers: [{ type: "queue", topic: "sync.kev" }],
  flows: ["vulnerability-sync"],
} as const satisfies StepConfig;

export const handler: Handlers<typeof config> = async (_input, { logger }) => {
  const db = createDb(process.env.DATABASE_URL!);

  logger.info("Starting KEV sync");

  let totalSynced = 0;

  try {
    const res = await fetch(KEV_URL);
    if (!res.ok) {
      throw new Error(`KEV API error: ${res.status} ${res.statusText}`);
    }

    const data = await res.json();
    const vulnerabilities = data.vulnerabilities ?? [];

    logger.info(`KEV catalog has ${vulnerabilities.length} entries`);

    for (const vuln of vulnerabilities) {
      if (!vuln.cveID) continue;

      // Ensure CVE record exists
      await db
        .insert(cve)
        .values({
          id: vuln.cveID,
          description: vuln.shortDescription ?? null,
          status: "KEV",
        })
        .onConflictDoNothing();

      // Upsert KEV entry
      const existing = await db
        .select({ id: kevEntry.id })
        .from(kevEntry)
        .where(eq(kevEntry.cveId, vuln.cveID))
        .limit(1);

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
      .values({
        source: "kev",
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

    logger.info(`KEV sync complete: ${totalSynced} new entries`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`KEV sync failed: ${message}`);

    await db
      .insert(syncLog)
      .values({
        source: "kev",
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
