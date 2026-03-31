import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const severityColorVars: Record<string, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
  info: "var(--status-info)",
  purple: "var(--status-purple)",
  success: "var(--status-success)",
  P0: "var(--severity-critical)",
  P1: "var(--severity-high)",
  P2: "var(--severity-medium)",
  P3: "var(--status-info)",
  P4: "var(--severity-low)",
};

export function SeverityBadge({
  severity,
  className,
  children,
}: {
  severity: string;
  className?: string;
  children: React.ReactNode;
}) {
  const colorVar = severityColorVars[severity] ?? "var(--text-dim)";

  return (
    <Badge
      variant="outline"
      className={cn(
        "border-transparent text-[10px] font-bold px-1.5 py-0.5",
        className,
      )}
      style={{
        color: colorVar,
        backgroundColor: `color-mix(in srgb, ${colorVar} 15%, transparent)`,
      }}
    >
      {children}
    </Badge>
  );
}
