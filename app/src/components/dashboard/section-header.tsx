export function SectionHeader({
  title,
  count,
  countLabel,
}: {
  title: string;
  count?: number;
  countLabel?: string;
}) {
  return (
    <div className="flex items-center gap-3">
      <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        {title}
      </h2>
      <div className="flex-1 h-px bg-border" />
      {count != null && (
        <span className="text-xs text-muted-foreground tabular-nums">
          {count} {countLabel ?? ""}
        </span>
      )}
    </div>
  );
}
