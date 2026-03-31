import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { AppSidebar } from "@/components/app-sidebar";
import { ThemeToggle } from "@/components/theme-toggle";
import { SyncButton } from "@/components/dashboard/sync-button";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="sticky top-0 z-50 flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background/80 backdrop-blur-xl px-4">
          <SidebarTrigger className="-ml-1 text-muted-foreground hover:text-foreground" />
          <Separator orientation="vertical" className="mr-2 !h-4" />

          <div className="flex items-center gap-1 rounded-full bg-secondary px-2.5 py-1 border border-border">
            <span className="h-1.5 w-1.5 rounded-full bg-status-success animate-pulse-dot" />
            <span className="hidden sm:inline text-[11px] font-medium text-status-success">
              All sources online
            </span>
          </div>

          <div className="ml-auto flex items-center gap-1">
            <SyncButton />
            <ThemeToggle />
          </div>
        </header>

        <main className="flex-1 px-6 py-8 sm:px-8 lg:px-12">{children}</main>
      </SidebarInset>
    </SidebarProvider>
  );
}
