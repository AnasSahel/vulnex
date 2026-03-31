import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { productCve } from "@/lib/db/schema";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id: productId } = await params;
  const body = await request.json();
  const { cveIds } = body;

  if (!Array.isArray(cveIds) || cveIds.length === 0) {
    return NextResponse.json({ error: "cveIds array is required" }, { status: 400 });
  }

  const values = cveIds.map((cveId: string) => ({
    productId,
    cveId,
  }));

  await db.insert(productCve).values(values).onConflictDoNothing();

  return NextResponse.json({ added: cveIds.length }, { status: 201 });
}
