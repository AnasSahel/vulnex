import { db } from "@/lib/db";
import { product, productCve, cve, cveScore, kevEntry } from "@/lib/db/schema";
import { eq, desc, sql, and, isNotNull } from "drizzle-orm";
import { computePriority, type DashboardCVE } from "./cves";

export type ProductSummary = {
  id: string;
  name: string;
  source: string;
  lastScannedAt: string | null;
  cveCount: number;
  p0: number;
  p1: number;
  p2: number;
  p3: number;
  p4: number;
};

export type ProductDetail = ProductSummary & {
  createdAt: string;
};

export async function getUserProducts(userId: string): Promise<ProductSummary[]> {
  const rows = await db.execute(sql`
    SELECT
      p.id,
      p.name,
      p.source,
      p.last_scanned_at,
      COALESCE(stats.cve_count, 0) AS cve_count,
      COALESCE(stats.p0, 0) AS p0,
      COALESCE(stats.p1, 0) AS p1,
      COALESCE(stats.p2, 0) AS p2,
      COALESCE(stats.p3, 0) AS p3,
      COALESCE(stats.p4, 0) AS p4
    FROM product p
    LEFT JOIN LATERAL (
      SELECT
        COUNT(*)::int AS cve_count,
        COUNT(*) FILTER (WHERE priority = 'P0')::int AS p0,
        COUNT(*) FILTER (WHERE priority = 'P1')::int AS p1,
        COUNT(*) FILTER (WHERE priority = 'P2')::int AS p2,
        COUNT(*) FILTER (WHERE priority = 'P3')::int AS p3,
        COUNT(*) FILTER (WHERE priority = 'P4')::int AS p4
      FROM (
        SELECT
          pc.cve_id,
          CASE
            WHEN (EXISTS (SELECT 1 FROM kev_entry k WHERE k.cve_id = pc.cve_id))
                 AND COALESCE(cvss.cvss_v3_score, 0) >= 9.0 THEN 'P0'
            WHEN (EXISTS (SELECT 1 FROM kev_entry k WHERE k.cve_id = pc.cve_id))
                 OR (COALESCE(cvss.cvss_v3_score, 0) >= 9.0 AND COALESCE(epss.epss_score, 0) >= 0.7) THEN 'P0'
            WHEN COALESCE(cvss.cvss_v3_score, 0) >= 7.0 AND COALESCE(epss.epss_score, 0) >= 0.5 THEN 'P1'
            WHEN COALESCE(cvss.cvss_v3_score, 0) >= 7.0 OR COALESCE(epss.epss_score, 0) >= 0.4 THEN 'P2'
            WHEN COALESCE(cvss.cvss_v3_score, 0) >= 4.0 THEN 'P3'
            ELSE 'P4'
          END AS priority
        FROM product_cve pc
        LEFT JOIN LATERAL (
          SELECT cs.cvss_v3_score FROM cve_score cs
          WHERE cs.cve_id = pc.cve_id AND cs.source = 'nvd' AND cs.cvss_v3_score IS NOT NULL
          ORDER BY cs.scored_at DESC LIMIT 1
        ) cvss ON true
        LEFT JOIN LATERAL (
          SELECT cs.epss_score FROM cve_score cs
          WHERE cs.cve_id = pc.cve_id AND cs.source = 'epss' AND cs.epss_score IS NOT NULL
          ORDER BY cs.scored_at DESC LIMIT 1
        ) epss ON true
        WHERE pc.product_id = p.id
      ) enriched
    ) stats ON true
    WHERE p.user_id = ${userId}
    ORDER BY COALESCE(stats.p0, 0) DESC, COALESCE(stats.p1, 0) DESC, p.updated_at DESC
  `);

  return rows.rows.map((r: any) => ({
    id: r.id,
    name: r.name,
    source: r.source,
    lastScannedAt: r.last_scanned_at ? new Date(r.last_scanned_at).toISOString() : null,
    cveCount: r.cve_count,
    p0: r.p0,
    p1: r.p1,
    p2: r.p2,
    p3: r.p3,
    p4: r.p4,
  }));
}

export async function getProductDetail(productId: string): Promise<ProductDetail | null> {
  const [row] = await db
    .select()
    .from(product)
    .where(eq(product.id, productId))
    .limit(1);

  if (!row) return null;

  const products = await getUserProducts(row.userId);
  const summary = products.find((p) => p.id === productId);
  if (!summary) return null;

  return {
    ...summary,
    createdAt: row.createdAt.toISOString(),
  };
}

export async function getGlobalPriorityCounts(userId: string) {
  const products = await getUserProducts(userId);
  return {
    p0: products.reduce((sum, p) => sum + p.p0, 0),
    p1: products.reduce((sum, p) => sum + p.p1, 0),
    p2: products.reduce((sum, p) => sum + p.p2, 0),
    p3: products.reduce((sum, p) => sum + p.p3, 0),
    p4: products.reduce((sum, p) => sum + p.p4, 0),
  };
}

export async function getProductCVEs(productId: string): Promise<DashboardCVE[]> {
  const rows = await db.execute(sql`
    SELECT
      c.id,
      c.description,
      c.last_modified,
      cvss.cvss_v3_score,
      epss.epss_score,
      (EXISTS (SELECT 1 FROM kev_entry k WHERE k.cve_id = c.id)) AS in_kev
    FROM product_cve pc
    INNER JOIN cve c ON c.id = pc.cve_id
    LEFT JOIN LATERAL (
      SELECT cs.cvss_v3_score FROM cve_score cs
      WHERE cs.cve_id = c.id AND cs.source = 'nvd' AND cs.cvss_v3_score IS NOT NULL
      ORDER BY cs.scored_at DESC LIMIT 1
    ) cvss ON true
    LEFT JOIN LATERAL (
      SELECT cs.epss_score FROM cve_score cs
      WHERE cs.cve_id = c.id AND cs.source = 'epss' AND cs.epss_score IS NOT NULL
      ORDER BY cs.scored_at DESC LIMIT 1
    ) epss ON true
    WHERE pc.product_id = ${productId}
    ORDER BY c.last_modified DESC NULLS LAST
  `);

  return rows.rows.map((row: any) => {
    const cvssVal = row.cvss_v3_score ?? 0;
    const epssVal = row.epss_score ?? 0;
    const isKev = row.in_kev === true;
    return {
      id: row.id,
      description: row.description ?? "No description available",
      cvss: cvssVal,
      epss: epssVal,
      kev: isKev,
      priority: computePriority(cvssVal, epssVal, isKev),
      updatedAt: row.last_modified ? new Date(row.last_modified).toISOString().split("T")[0] : "",
    };
  });
}
