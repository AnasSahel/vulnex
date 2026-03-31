"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Upload, FileText, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SectionHeader } from "@/components/dashboard/section-header";

type SbomEntry = {
  id: number;
  filename: string;
  format: string;
  fileSize: number;
  uploadedAt: string;
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatLabel(format: string): string {
  if (format === "cyclonedx") return "CycloneDX";
  if (format === "spdx") return "SPDX";
  return "Unknown";
}

export function SbomUpload({ productId }: { productId: string }) {
  const router = useRouter();
  const fileRef = useRef<HTMLInputElement>(null);
  const [sboms, setSboms] = useState<SbomEntry[]>([]);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`/api/products/${productId}/sboms`)
      .then((r) => r.json())
      .then((data) => setSboms(data.sboms ?? []))
      .catch(() => {});
  }, [productId]);

  async function handleUpload(file: File) {
    setUploading(true);
    setError("");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`/api/products/${productId}/sboms`, {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const data = await res.json();
        setError(data.error || "Upload failed");
        return;
      }

      // Refresh list
      const listRes = await fetch(`/api/products/${productId}/sboms`);
      const listData = await listRes.json();
      setSboms(listData.sboms ?? []);
      router.refresh();
    } catch {
      setError("Upload failed");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <SectionHeader title="SBOMs" count={sboms.length} countLabel="files" />
        <Button
          size="sm"
          variant="outline"
          className="gap-1.5"
          disabled={uploading}
          onClick={() => fileRef.current?.click()}
        >
          <Upload className="h-4 w-4" />
          {uploading ? "Uploading..." : "Upload SBOM"}
        </Button>
        <input
          ref={fileRef}
          type="file"
          accept=".json,.xml,.spdx,.cdx"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleUpload(file);
            e.target.value = "";
          }}
        />
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {sboms.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-6 text-center">
          <Upload className="h-8 w-8 text-muted-foreground/60 mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">No SBOMs uploaded yet</p>
          <p className="text-xs text-muted-foreground/60 mt-1">
            Upload a CycloneDX or SPDX file to get started
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          {sboms.map((sbom, idx) => (
            <div
              key={sbom.id}
              className={`flex items-center gap-3 px-4 py-3 ${
                idx !== sboms.length - 1 ? "border-b border-border/30" : ""
              }`}
            >
              <FileText className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              <div className="min-w-0 flex-1">
                <span className="text-sm font-medium truncate block">
                  {sbom.filename}
                </span>
                <span className="text-xs text-muted-foreground">
                  {formatLabel(sbom.format)} &middot; {formatBytes(sbom.fileSize)}
                </span>
              </div>
              <span className="inline-flex items-center gap-1 text-[10px] text-muted-foreground/60 bg-secondary px-2 py-0.5 rounded-full">
                <Clock className="h-3 w-3" />
                Pending analysis
              </span>
              <span className="text-[11px] text-muted-foreground/60 tabular-nums">
                {new Date(sbom.uploadedAt).toLocaleDateString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
