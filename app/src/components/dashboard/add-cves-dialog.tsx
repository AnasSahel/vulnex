"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Plus, Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

type SearchResult = {
  id: string;
  description: string;
  cvss: number;
};

function useDebouncedSearch() {
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [timer, setTimer] = useState<ReturnType<typeof setTimeout> | null>(null);

  const search = useCallback((query: string) => {
    if (timer) clearTimeout(timer);
    if (query.length < 3) {
      setResults([]);
      return;
    }
    setLoading(true);
    const t = setTimeout(async () => {
      try {
        const res = await fetch(`/api/cves/search?q=${encodeURIComponent(query)}`);
        const data = await res.json();
        setResults(data.results ?? []);
      } catch {
        setResults([]);
      } finally {
        setLoading(false);
      }
    }, 300);
    setTimer(t);
  }, [timer]);

  return { results, loading, search };
}

export function AddCvesDialog({ productId }: { productId: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<"search" | "bulk">("search");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkText, setBulkText] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const { results, loading, search } = useDebouncedSearch();

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleAdd() {
    let cveIds: string[];

    if (tab === "search") {
      cveIds = Array.from(selected);
    } else {
      cveIds = bulkText
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter((s) => /^CVE-\d{4}-\d+$/i.test(s))
        .map((s) => s.toUpperCase());
    }

    if (cveIds.length === 0) {
      setError("No valid CVE IDs selected");
      return;
    }

    setSubmitting(true);
    setError("");

    try {
      const res = await fetch(`/api/products/${productId}/cves`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cveIds }),
      });

      if (!res.ok) {
        const data = await res.json();
        setError(data.error || "Failed to add CVEs");
        return;
      }

      setOpen(false);
      setSelected(new Set());
      setBulkText("");
      router.refresh();
    } catch {
      setError("Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger
        render={<Button size="sm" variant="outline" className="gap-1.5" />}
      >
        <Plus className="h-4 w-4" />
        Add CVEs
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add CVEs to Product</DialogTitle>
          <DialogDescription>
            Search for CVEs or paste a list of CVE IDs.
          </DialogDescription>
        </DialogHeader>

        {/* Tab switcher */}
        <div className="flex gap-1 p-1 bg-secondary rounded-lg">
          <button
            className={`flex-1 text-xs font-medium py-1.5 rounded-md transition-colors ${
              tab === "search" ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground"
            }`}
            onClick={() => setTab("search")}
          >
            Search
          </button>
          <button
            className={`flex-1 text-xs font-medium py-1.5 rounded-md transition-colors ${
              tab === "bulk" ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground"
            }`}
            onClick={() => setTab("bulk")}
          >
            Bulk Add
          </button>
        </div>

        {tab === "search" ? (
          <div className="space-y-3 min-w-0">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by CVE ID or keyword..."
                className="pl-9"
                onChange={(e) => search(e.target.value)}
              />
            </div>
            <div className="max-h-[240px] overflow-y-auto space-y-1">
              {loading && (
                <p className="text-xs text-muted-foreground text-center py-4">Searching...</p>
              )}
              {!loading && results.length === 0 && (
                <p className="text-xs text-muted-foreground text-center py-4">
                  Type at least 3 characters to search
                </p>
              )}
              {results.map((cve) => (
                <label
                  key={cve.id}
                  className={`flex items-start gap-2.5 p-2 rounded-md cursor-pointer transition-colors ${
                    selected.has(cve.id)
                      ? "bg-primary/10 border border-primary/20"
                      : "hover:bg-secondary border border-transparent"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selected.has(cve.id)}
                    onChange={() => toggleSelect(cve.id)}
                    className="mt-0.5 accent-primary"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-medium">{cve.id}</span>
                      <span className="text-[10px] font-mono text-muted-foreground">
                        CVSS {cve.cvss.toFixed(1)}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground truncate mt-0.5">
                      {cve.description}
                    </p>
                  </div>
                </label>
              ))}
            </div>
            {selected.size > 0 && (
              <p className="text-xs text-muted-foreground">
                {selected.size} CVE{selected.size !== 1 ? "s" : ""} selected
              </p>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            <div className="grid gap-2">
              <Label htmlFor="bulk-cves">CVE IDs (one per line or comma-separated)</Label>
              <textarea
                id="bulk-cves"
                className="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                placeholder={"CVE-2024-1234\nCVE-2024-5678\nCVE-2024-9012"}
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
              />
            </div>
          </div>
        )}

        {error && <p className="text-sm text-destructive">{error}</p>}

        <DialogFooter>
          <Button onClick={handleAdd} disabled={submitting}>
            {submitting ? "Adding..." : "Add CVEs"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
