import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { productSbom } from "@/lib/db/schema";
import { eq } from "drizzle-orm";

const MAX_SIZE = 10 * 1024 * 1024; // 10MB

function detectFormat(content: string): string {
  const trimmed = content.trim();
  // CycloneDX JSON
  if (trimmed.startsWith("{") && content.includes('"bomFormat"')) {
    return "cyclonedx";
  }
  // CycloneDX XML
  if (trimmed.startsWith("<") && content.includes("cyclonedx")) {
    return "cyclonedx";
  }
  // SPDX JSON
  if (trimmed.startsWith("{") && content.includes('"spdxVersion"')) {
    return "spdx";
  }
  // SPDX tag-value
  if (content.includes("SPDXVersion:")) {
    return "spdx";
  }
  return "unknown";
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id: productId } = await params;

  const formData = await request.formData();
  const file = formData.get("file") as File | null;

  if (!file) {
    return NextResponse.json({ error: "No file provided" }, { status: 400 });
  }

  if (file.size > MAX_SIZE) {
    return NextResponse.json({ error: "File too large (max 10MB)" }, { status: 400 });
  }

  const content = await file.text();
  const format = detectFormat(content);

  const [row] = await db.insert(productSbom).values({
    productId,
    filename: file.name,
    format,
    content,
    fileSize: file.size,
  }).returning({ id: productSbom.id });

  return NextResponse.json({ id: row.id, format }, { status: 201 });
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id: productId } = await params;

  const sboms = await db
    .select({
      id: productSbom.id,
      filename: productSbom.filename,
      format: productSbom.format,
      fileSize: productSbom.fileSize,
      uploadedAt: productSbom.uploadedAt,
    })
    .from(productSbom)
    .where(eq(productSbom.productId, productId))
    .orderBy(productSbom.uploadedAt);

  return NextResponse.json({ sboms });
}
