"use client";

import Link from "next/link";
import { Terminal, Upload, FolderPlus, ChevronRight } from "lucide-react";
import { EmptyState } from "@/components/dashboard/empty-state";
import { SectionHeader } from "@/components/dashboard/section-header";
import { CreateProductDialog } from "@/components/dashboard/create-product-dialog";
import type { ProductSummary } from "@/lib/queries";

const sourceIcons: Record<string, React.ElementType> = {
  cli: Terminal,
  sbom: Upload,
  manual: FolderPlus,
};

function statusColor(product: ProductSummary): string {
  if (product.p0 > 0) return "var(--severity-critical)";
  if (product.p1 > 0) return "var(--severity-high)";
  return "var(--status-success)";
}

function timeAgo(iso: string | null): string {
  if (!iso) return "Never";
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function MiniPriorityBar({ product }: { product: ProductSummary }) {
  const total = product.p0 + product.p1 + product.p2 + product.p3 + product.p4;
  if (total === 0) {
    return (
      <div className="w-24 h-2 rounded-full bg-secondary" />
    );
  }

  const segments = [
    { count: product.p0, color: "var(--severity-critical)" },
    { count: product.p1, color: "var(--severity-high)" },
    { count: product.p2, color: "var(--severity-medium)" },
    { count: product.p3, color: "var(--severity-low)" },
    { count: product.p4, color: "var(--text-dimmer)" },
  ];

  return (
    <div className="flex w-24 h-2 rounded-full overflow-hidden bg-secondary">
      {segments.map(
        (seg, i) =>
          seg.count > 0 && (
            <div
              key={i}
              className="h-full"
              style={{
                width: `${(seg.count / total) * 100}%`,
                backgroundColor: seg.color,
              }}
            />
          ),
      )}
    </div>
  );
}

export function ProductList({ products }: { products: ProductSummary[] }) {
  if (products.length === 0) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <SectionHeader title="Products" count={0} countLabel="products" />
          <CreateProductDialog />
        </div>
        <EmptyState
          title="No products yet"
          description="Create a product by running a CLI scan, uploading an SBOM, or adding one manually."
        />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <SectionHeader
          title="Products"
          count={products.length}
          countLabel="products"
        />
        <CreateProductDialog />
      </div>
      <div className="rounded-lg border border-border overflow-hidden">
        {products.map((product, idx) => {
          const SourceIcon = sourceIcons[product.source] ?? FolderPlus;
          return (
            <Link
              key={product.id}
              href={`/products/${product.id}`}
              className={`flex items-center gap-3 px-4 py-3.5 transition-colors hover:bg-secondary ${
                idx !== products.length - 1
                  ? "border-b border-border"
                  : ""
              }`}
            >
              {/* Status dot */}
              <span
                className="h-2 w-2 rounded-full flex-shrink-0"
                style={{ backgroundColor: statusColor(product) }}
              />

              {/* Source icon */}
              <SourceIcon className="h-4 w-4 text-muted-foreground flex-shrink-0" />

              {/* Product name */}
              <span className="font-medium text-sm text-foreground truncate min-w-0 flex-1">
                {product.name}
              </span>

              {/* Mini priority bar */}
              <MiniPriorityBar product={product} />

              {/* CVE count */}
              <span className="text-xs text-muted-foreground tabular-nums whitespace-nowrap">
                {product.cveCount} CVE{product.cveCount !== 1 ? "s" : ""}
              </span>

              {/* Last scanned */}
              <span className="text-[11px] text-muted-foreground/60 tabular-nums whitespace-nowrap w-16 text-right">
                {timeAgo(product.lastScannedAt)}
              </span>

              <ChevronRight className="h-4 w-4 text-muted-foreground/60 flex-shrink-0" />
            </Link>
          );
        })}
      </div>
    </div>
  );
}
