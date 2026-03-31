import { NextResponse } from "next/server";
import { getSyncStatus } from "@/lib/queries";

const MOTIA_API_URL = process.env.MOTIA_API_URL ?? "http://localhost:4100";

export async function GET() {
  try {
    const status = await getSyncStatus();
    return NextResponse.json({ status });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to fetch sync status" },
      { status: 500 }
    );
  }
}

export async function POST() {
  try {
    const res = await fetch(`${MOTIA_API_URL}/api/sync`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });

    if (!res.ok) {
      return NextResponse.json(
        { error: `Sync trigger failed: ${res.statusText}` },
        { status: res.status }
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json(
      { error: "Failed to reach sync service. Is the Motia worker running?" },
      { status: 503 }
    );
  }
}
