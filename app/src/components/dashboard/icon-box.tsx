export function IconBox({
  color,
  children,
  className,
}: {
  color: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded p-1 flex-shrink-0 ${className ?? ""}`}
      style={{
        backgroundColor: `color-mix(in srgb, ${color} 10%, transparent)`,
      }}
    >
      {children}
    </div>
  );
}
