import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { product, productCve, productSbom } from "@/lib/db/schema";
import { eq, and } from "drizzle-orm";
import { nanoid } from "nanoid";

/**
 * POST /api/push — Receives CLI push payload
 *
 * Body: {
 *   name: string,           // Product name
 *   cveIds: string[],       // CVE IDs to link
 *   sbom?: { filename: string, content: string }, // Optional SBOM
 * }
 *
 * Auth: Bearer token (session cookie or API key via VULNEX_API_KEY header)
 */
export async function POST(request: Request) {
  // Try session auth first
  let userId: string | null = null;

  const session = await auth.api.getSession({ headers: await headers() });
  if (session?.user) {
    userId = session.user.id;
  }

  // Fall back to API key auth
  if (!userId) {
    const apiKey = request.headers.get("x-api-key");
    if (apiKey) {
      // For now, look up user by API key stored in a simple way
      // TODO: proper API key table in milestone 2+
      // For now, accept session-based auth only
    }
  }

  if (!userId) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  const { name, cveIds, sbom } = body;

  if (!name || typeof name !== "string") {
    return NextResponse.json({ error: "Product name is required" }, { status: 400 });
  }

  // Find or create product by name
  const existing = await db
    .select()
    .from(product)
    .where(and(eq(product.userId, userId), eq(product.name, name)))
    .limit(1);

  let productId: string;
  if (existing.length > 0) {
    productId = existing[0].id;
    // Update lastScannedAt
    await db
      .update(product)
      .set({ lastScannedAt: new Date(), updatedAt: new Date() })
      .where(eq(product.id, productId));
  } else {
    productId = nanoid();
    await db.insert(product).values({
      id: productId,
      userId,
      name,
      source: "cli",
      lastScannedAt: new Date(),
    });
  }

  // Link CVEs
  let linkedCount = 0;
  if (Array.isArray(cveIds) && cveIds.length > 0) {
    const values = cveIds.map((cveId: string) => ({
      productId,
      cveId,
    }));
    await db.insert(productCve).values(values).onConflictDoNothing();
    linkedCount = cveIds.length;
  }

  // Store SBOM if provided
  if (sbom && sbom.filename && sbom.content) {
    const format = detectFormat(sbom.content);
    await db.insert(productSbom).values({
      productId,
      filename: sbom.filename,
      format,
      content: sbom.content,
      fileSize: new Blob([sbom.content]).size,
    });
  }

  return NextResponse.json({
    productId,
    name,
    linkedCves: linkedCount,
    message: `Pushed ${linkedCount} CVEs to product '${name}'`,
  }, { status: 200 });
}

function detectFormat(content: string): string {
  const trimmed = content.trim();
  if (trimmed.startsWith("{") && content.includes('"bomFormat"')) return "cyclonedx";
  if (trimmed.startsWith("<") && content.includes("cyclonedx")) return "cyclonedx";
  if (trimmed.startsWith("{") && content.includes('"spdxVersion"')) return "spdx";
  if (content.includes("SPDXVersion:")) return "spdx";
  return "unknown";
}
