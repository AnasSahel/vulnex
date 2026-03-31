"use client";

const levels = [
  { key: "p0", label: "P0", color: "var(--severity-critical)" },
  { key: "p1", label: "P1", color: "var(--severity-high)" },
  { key: "p2", label: "P2", color: "var(--severity-medium)" },
  { key: "p3", label: "P3", color: "var(--severity-low)" },
  { key: "p4", label: "P4", color: "var(--text-dimmer)" },
] as const;

export function PriorityStrip({
  counts,
}: {
  counts: { p0: number; p1: number; p2: number; p3: number; p4: number };
}) {
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {levels.map(({ key, label, color }) => (
        <div
          key={key}
          className="flex items-center gap-1.5 rounded-full border border-border px-3 py-1.5"
        >
          <span
            className="inline-block h-1.5 w-1.5 rounded-full"
            style={{ backgroundColor: color }}
          />
          <span className="text-xs font-medium text-muted-foreground">
            {label}
          </span>
          <span
            className="text-sm font-semibold tabular-nums"
            style={{ color }}
          >
            {counts[key]}
          </span>
        </div>
      ))}
    </div>
  );
}
