"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Shield, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { authClient } from "@/lib/auth-client";

export default function SignupPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    const { error: authError } = await authClient.signUp.email({
      name,
      email,
      password,
    });

    if (authError) {
      setError(authError.message ?? "Could not create account");
      setLoading(false);
      return;
    }

    router.push("/products");
    router.refresh();
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 relative">
      {/* Background glow */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] rounded-full bg-primary/[0.03] blur-[100px] pointer-events-none" />

      <Card className="w-full max-w-sm border-border bg-card shadow-2xl">
        <CardHeader className="text-center pb-4">
          <div className="mx-auto mb-3 flex items-center justify-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            <span className="text-lg font-bold tracking-tight">
              vulnex<span className="text-muted-foreground">.cloud</span>
            </span>
          </div>
          <CardTitle className="text-xl">Create an account</CardTitle>
          <CardDescription className="text-muted-foreground">
            Get started with VulneX Cloud
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name" className="text-muted-foreground">
                Name
              </Label>
              <Input
                id="name"
                type="text"
                placeholder="Jane Doe"
                className="bg-background border-border focus-visible:ring-primary/30 focus-visible:border-primary/50"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                disabled={loading}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email" className="text-muted-foreground">
                Email
              </Label>
              <Input
                id="email"
                type="email"
                placeholder="you@company.com"
                className="bg-background border-border focus-visible:ring-primary/30 focus-visible:border-primary/50"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={loading}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password" className="text-muted-foreground">
                Password
              </Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                className="bg-background border-border focus-visible:ring-primary/30 focus-visible:border-primary/50"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading}
              />
            </div>
            {error && (
              <p className="text-sm text-destructive">{error}</p>
            )}
            <Button
              className="w-full bg-primary text-primary-foreground font-semibold hover:bg-primary/90"
              type="submit"
              disabled={loading}
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                "Create account"
              )}
            </Button>
          </form>
          <p className="mt-4 text-center text-sm text-muted-foreground">
            Already have an account?{" "}
            <Link
              href="/login"
              className="font-medium text-primary hover:underline underline-offset-4"
            >
              Sign in
            </Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
