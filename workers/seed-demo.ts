/**
 * Seed script — creates a demo product and links CVEs to it.
 * Usage: cd workers && DATABASE_URL=... bun run seed-demo.ts
 * Or: source ../app/.env.local && cd workers && bun run seed-demo.ts
 */
import { createDb, product, productCve } from "@vulnex/db";
import { sql } from "drizzle-orm";

const db = createDb(process.env.DATABASE_URL!);

async function seed() {
  // Get first user
  const users = await db.execute(sql`SELECT id FROM "user" LIMIT 1`);
  if (users.rows.length === 0) {
    console.error("No users found. Sign up first.");
    process.exit(1);
  }
  const userId = users.rows[0].id as string;
  console.log(`Using user: ${userId}`);

  // Create or get demo product
  const productId = "demo-product-001";
  await db.insert(product).values({
    id: productId,
    userId,
    name: "Demo Application",
    source: "manual",
  }).onConflictDoNothing();
  console.log("✓ Product created: Demo Application");

  // Get top 200 CVEs by CVSS score
  const topCves = await db.execute(sql`
    SELECT DISTINCT cs.cve_id
    FROM cve_score cs
    WHERE cs.source = 'nvd' AND cs.cvss_v3_score IS NOT NULL
    ORDER BY cs.cve_id
    LIMIT 200
  `);

  if (topCves.rows.length === 0) {
    console.error("No CVEs with scores found. Run sync first.");
    process.exit(1);
  }

  // Link CVEs to product
  const values = topCves.rows.map((row: any) => ({
    productId,
    cveId: row.cve_id as string,
  }));

  await db.insert(productCve).values(values).onConflictDoNothing();
  console.log(`✓ Linked ${values.length} CVEs to Demo Application`);
  console.log("Done! Visit /dashboard to see the product.");
}

seed().catch(console.error);
