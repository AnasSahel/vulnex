"use client";

import { User, Bell, Key, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { SectionHeader } from "@/components/dashboard/section-header";
import { IconBox } from "@/components/dashboard/icon-box";
import { authClient } from "@/lib/auth-client";

export default function SettingsPage() {
  const { data: session } = authClient.useSession();

  return (
    <div className="space-y-8 max-w-2xl">
      <div className="animate-fade-up">
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Manage your account and preferences
        </p>
      </div>

      {/* Profile */}
      <div className="animate-fade-up" style={{ animationDelay: "50ms" }}>
        <SectionHeader title="Profile" />
        <Card className="mt-4 border-border ring-0">
          <CardContent className="p-5 space-y-4">
            <div className="flex items-center gap-3 mb-2">
              <IconBox color="var(--status-info)" className="rounded-md p-2">
                <User className="h-4 w-4" style={{ color: "var(--status-info)" }} />
              </IconBox>
              <div>
                <p className="text-sm font-semibold">{session?.user?.name ?? "—"}</p>
                <p className="text-[13px] text-muted-foreground">{session?.user?.email ?? "—"}</p>
              </div>
            </div>
            <Separator className="bg-border" />
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label className="text-muted-foreground">Name</Label>
                <Input
                  defaultValue={session?.user?.name ?? ""}
                  className="bg-background border-border focus-visible:ring-primary/30 focus-visible:border-primary/50"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-muted-foreground">Email</Label>
                <Input
                  defaultValue={session?.user?.email ?? ""}
                  disabled
                  className="bg-background border-border"
                />
              </div>
            </div>
            <Button className="bg-primary text-primary-foreground hover:bg-primary/90">
              Save changes
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Notifications */}
      <div className="animate-fade-up" style={{ animationDelay: "100ms" }}>
        <SectionHeader title="Notifications" />
        <Card className="mt-4 border-border ring-0">
          <CardContent className="p-5 space-y-4">
            <div className="flex items-center gap-3 mb-2">
              <IconBox color="var(--severity-high)" className="rounded-md p-2">
                <Bell className="h-4 w-4" style={{ color: "var(--severity-high)" }} />
              </IconBox>
              <p className="text-sm font-semibold">Alert preferences</p>
            </div>
            <Separator className="bg-border" />
            {[
              { label: "New exploit published", description: "When a public exploit is released for a watched CVE", defaultChecked: true },
              { label: "EPSS score spike", description: "When a CVE's EPSS score increases significantly", defaultChecked: true },
              { label: "KEV additions", description: "When a watched CVE is added to the CISA KEV catalog", defaultChecked: true },
              { label: "CVSS score changes", description: "When NVD revises a CVSS score", defaultChecked: false },
              { label: "New advisory", description: "When a new security advisory is published", defaultChecked: false },
            ].map((pref) => (
              <div key={pref.label} className="flex items-center justify-between py-1">
                <div>
                  <p className="text-sm font-medium">{pref.label}</p>
                  <p className="text-[12px] text-muted-foreground">{pref.description}</p>
                </div>
                <Switch defaultChecked={pref.defaultChecked} />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* API Keys */}
      <div className="animate-fade-up" style={{ animationDelay: "150ms" }}>
        <SectionHeader title="API Keys" />
        <Card className="mt-4 border-border ring-0">
          <CardContent className="p-5 space-y-4">
            <div className="flex items-center gap-3 mb-2">
              <IconBox color="var(--status-purple)" className="rounded-md p-2">
                <Key className="h-4 w-4" style={{ color: "var(--status-purple)" }} />
              </IconBox>
              <div>
                <p className="text-sm font-semibold">Access tokens</p>
                <p className="text-[12px] text-muted-foreground">
                  Use API keys to authenticate CLI and integrations
                </p>
              </div>
            </div>
            <Separator className="bg-border" />
            <p className="text-[13px] text-muted-foreground py-4 text-center">
              No API keys created yet
            </p>
            <Button variant="outline" className="border-border text-muted-foreground hover:text-foreground hover:bg-secondary">
              <Key className="h-4 w-4 mr-1.5" />
              Generate API key
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Danger zone */}
      <div className="animate-fade-up" style={{ animationDelay: "200ms" }}>
        <SectionHeader title="Danger Zone" />
        <Card className="mt-4 border-destructive/30 bg-card ring-0">
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <IconBox color="var(--severity-critical)" className="rounded-md p-2">
                  <AlertTriangle className="h-4 w-4" style={{ color: "var(--severity-critical)" }} />
                </IconBox>
                <div>
                  <p className="text-sm font-semibold">Delete account</p>
                  <p className="text-[12px] text-muted-foreground">
                    Permanently delete your account and all associated data
                  </p>
                </div>
              </div>
              <Button variant="destructive" className="shrink-0">
                Delete account
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
