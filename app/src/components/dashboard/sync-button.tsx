"use client";

import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

export function SyncButton() {
  const [syncing, setSyncing] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function triggerSync() {
    setSyncing(true);
    setMessage(null);

    try {
      const res = await fetch("/api/sync", { method: "POST" });
      const data = await res.json();

      if (res.ok) {
        setMessage("Sync triggered");
      } else {
        setMessage(data.error ?? "Sync failed");
      }
    } catch {
      setMessage("Failed to reach sync service");
    } finally {
      setSyncing(false);
      setTimeout(() => setMessage(null), 3000);
    }
  }

  return (
    <div className="relative">
      <Button
        variant="outline"
        size="sm"
        onClick={triggerSync}
        disabled={syncing}
        className="border-border text-muted-foreground hover:text-foreground hover:bg-secondary h-8 px-3"
      >
        <RefreshCw
          className={`h-3.5 w-3.5 mr-1.5 ${syncing ? "animate-spin" : ""}`}
        />
        {syncing ? "Syncing..." : "Sync"}
      </Button>
      {message && (
        <div className="absolute top-full right-0 mt-1 whitespace-nowrap text-[11px] text-muted-foreground bg-card border border-border rounded px-2 py-1 z-50">
          {message}
        </div>
      )}
    </div>
  );
}
