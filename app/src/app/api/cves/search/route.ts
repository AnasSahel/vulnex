import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { sql } from "drizzle-orm";

export async function GET(request: Request) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const q = searchParams.get("q")?.trim();

  if (!q || q.length < 3) {
    return NextResponse.json({ results: [] });
  }

  const rows = await db.execute(sql`
    SELECT
      c.id,
      c.description,
      cs.cvss_v3_score
    FROM cve c
    LEFT JOIN LATERAL (
      SELECT cs.cvss_v3_score FROM cve_score cs
      WHERE cs.cve_id = c.id AND cs.source = 'nvd' AND cs.cvss_v3_score IS NOT NULL
      ORDER BY cs.scored_at DESC LIMIT 1
    ) cs ON true
    WHERE c.id ILIKE ${'%' + q + '%'}
       OR c.description ILIKE ${'%' + q + '%'}
    ORDER BY cs.cvss_v3_score DESC NULLS LAST
    LIMIT 50
  `);

  const results = rows.rows.map((r: any) => ({
    id: r.id,
    description: r.description ?? "",
    cvss: r.cvss_v3_score ?? 0,
  }));

  return NextResponse.json({ results });
}
