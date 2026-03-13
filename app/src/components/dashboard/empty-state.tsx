import { SearchX } from "lucide-react";

export function EmptyState({
  icon: Icon = SearchX,
  title,
  description,
  children,
}: {
  icon?: React.ElementType;
  title: string;
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <div className="rounded-full bg-secondary p-3 mb-3">
        <Icon className="h-5 w-5 text-muted-foreground/60" />
      </div>
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="text-[13px] text-muted-foreground mt-1 max-w-xs">{description}</p>
      {children && <div className="mt-4">{children}</div>}
    </div>
  );
}
