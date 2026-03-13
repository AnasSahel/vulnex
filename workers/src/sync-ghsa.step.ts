import type { StepConfig, Handlers } from "motia";
import { createDb, syncLog, advisory } from "@vulnex/db";

const GITHUB_GRAPHQL = "https://api.github.com/graphql";

const ADVISORIES_QUERY = `
  query($after: String) {
    securityAdvisories(
      first: 100,
      after: $after,
      orderBy: { field: UPDATED_AT, direction: DESC }
    ) {
      nodes {
        ghsaId
        summary
        description
        severity
        publishedAt
        updatedAt
        permalink
        identifiers {
          type
          value
        }
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
`;

export const config = {
  name: "sync-ghsa",
  description: "Fetches GitHub Security Advisories via GraphQL API",
  triggers: [{ type: "queue", topic: "sync.ghsa" }],
  flows: ["vulnerability-sync"],
} as const satisfies StepConfig;

export const handler: Handlers<typeof config> = async (_input, { logger }) => {
  const db = createDb(process.env.DATABASE_URL!);
  const token = process.env.GITHUB_TOKEN;

  if (!token) {
    logger.warn("GITHUB_TOKEN not set, skipping GHSA sync");
    return;
  }

  logger.info("Starting GHSA sync");

  let totalSynced = 0;
  let cursor: string | null = null;
  let hasNextPage = true;
  const maxPages = 10; // Limit to 1000 advisories per sync
  let page = 0;

  try {
    while (hasNextPage && page < maxPages) {
      const res: Response = await fetch(GITHUB_GRAPHQL, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          "User-Agent": "VulneX/1.0",
        },
        body: JSON.stringify({
          query: ADVISORIES_QUERY,
          variables: { after: cursor },
        }),
      });

      if (!res.ok) {
        throw new Error(`GitHub API error: ${res.status} ${res.statusText}`);
      }

      const json: any = await res.json();

      if (json.errors?.length) {
        throw new Error(`GraphQL errors: ${JSON.stringify(json.errors)}`);
      }

      const advisories: any = json.data?.securityAdvisories;
      if (!advisories?.nodes?.length) break;

      for (const node of advisories.nodes) {
        const cveId =
          node.identifiers?.find((i: any) => i.type === "CVE")?.value ?? null;

        await db
          .insert(advisory)
          .values({
            ghsaId: node.ghsaId,
            cveId,
            severity: node.severity?.toLowerCase() ?? null,
            summary: node.summary ?? null,
            description: node.description ?? null,
            publishedAt: node.publishedAt ? new Date(node.publishedAt) : null,
            updatedAt: node.updatedAt ? new Date(node.updatedAt) : null,
            url: node.permalink ?? null,
          })
          .onConflictDoUpdate({
            target: advisory.ghsaId,
            set: {
              cveId,
              severity: node.severity?.toLowerCase() ?? null,
              summary: node.summary ?? null,
              description: node.description ?? null,
              updatedAt: node.updatedAt ? new Date(node.updatedAt) : null,
            },
          });

        totalSynced++;
      }

      hasNextPage = advisories.pageInfo.hasNextPage;
      cursor = advisories.pageInfo.endCursor;
      page++;

      logger.info(`GHSA sync progress: page ${page}, ${totalSynced} advisories`);
    }

    await db
      .insert(syncLog)
      .values({
        source: "ghsa",
        lastSyncedAt: new Date(),
        lastCursor: cursor,
        status: "success",
        itemsSynced: totalSynced,
      })
      .onConflictDoUpdate({
        target: syncLog.source,
        set: {
          lastSyncedAt: new Date(),
          lastCursor: cursor,
          status: "success",
          itemsSynced: totalSynced,
          errorMessage: null,
          updatedAt: new Date(),
        },
      });

    logger.info(`GHSA sync complete: ${totalSynced} advisories synced`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`GHSA sync failed: ${message}`);

    await db
      .insert(syncLog)
      .values({
        source: "ghsa",
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
