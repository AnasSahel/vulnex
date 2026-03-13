"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import { ArrowLeft, RefreshCw, Terminal, Upload, FolderPlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PriorityStrip } from "@/components/dashboard/priority-strip";
import { CveTable } from "@/components/dashboard/cve-table";
import { AddCvesDialog } from "@/components/dashboard/add-cves-dialog";
import { SbomUpload } from "@/components/dashboard/sbom-upload";
import type { ProductDetail, DashboardCVE } from "@/lib/queries";

const sourceIcons: Record<string, React.ElementType> = {
  cli: Terminal,
  sbom: Upload,
  manual: FolderPlus,
};

const sourceLabels: Record<string, string> = {
  cli: "CLI Import",
  sbom: "SBOM Upload",
  manual: "Manual",
};

export function ProductDetailClient({
  product,
  cves,
}: {
  product: ProductDetail;
  cves: DashboardCVE[];
}) {
  const [searchQuery, setSearchQuery] = useState("");

  const counts = useMemo(() => {
    const c = { p0: 0, p1: 0, p2: 0, p3: 0, p4: 0 };
    for (const cve of cves) {
      const key = cve.priority.toLowerCase() as keyof typeof c;
      if (key in c) c[key]++;
    }
    return c;
  }, [cves]);

  const SourceIcon = sourceIcons[product.source] ?? FolderPlus;

  return (
    <div className="space-y-8 max-w-6xl">
      <div className="animate-fade-up">
        <Link
          href="/products"
          className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors mb-4"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to products
        </Link>

        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">
              {product.name}
            </h1>
            <div className="flex items-center gap-3 mt-1.5 text-sm text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <SourceIcon className="h-3.5 w-3.5" />
                {sourceLabels[product.source] ?? product.source}
              </span>
              {product.lastScannedAt && (
                <span>
                  Last scanned{" "}
                  {new Date(product.lastScannedAt).toLocaleDateString()}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <AddCvesDialog productId={product.id} />
            <Button variant="outline" size="sm" disabled>
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
              Re-scan
            </Button>
          </div>
        </div>
      </div>

      <div className="animate-fade-up" style={{ animationDelay: "50ms" }}>
        <PriorityStrip counts={counts} />
      </div>

      <div className="animate-fade-up space-y-4" style={{ animationDelay: "100ms" }}>
        <Input
          placeholder="Search CVEs..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="max-w-sm"
        />
        <CveTable cves={cves} searchQuery={searchQuery} title="Vulnerabilities" productId={product.id} />
      </div>

      <div className="animate-fade-up" style={{ animationDelay: "150ms" }}>
        <SbomUpload productId={product.id} />
      </div>
    </div>
  );
}
