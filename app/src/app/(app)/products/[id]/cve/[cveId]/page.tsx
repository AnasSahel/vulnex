import { notFound } from "next/navigation";
import { getCVEDetail } from "@/lib/queries";
import { CVEDetailClient } from "./cve-detail-client";

export default async function CVEPage({ params }: { params: Promise<{ id: string; cveId: string }> }) {
  const { id: productId, cveId } = await params;
  const decodedCveId = decodeURIComponent(cveId);

  const detail = await getCVEDetail(decodedCveId);

  if (!detail) notFound();

  return <CVEDetailClient detail={detail} productId={productId} />;
}
