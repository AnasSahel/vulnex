import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { redirect, notFound } from "next/navigation";
import { getProductDetail, getProductCVEs } from "@/lib/queries";
import { ProductDetailClient } from "./product-detail-client";

export default async function ProductPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user) redirect("/login");

  const { id } = await params;
  const [product, cves] = await Promise.all([
    getProductDetail(id),
    getProductCVEs(id),
  ]);

  if (!product) notFound();

  return <ProductDetailClient product={product} cves={cves} />;
}
