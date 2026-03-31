"use client";

import { useTheme } from "next-themes";
import { useEffect, useState } from "react";
import { Sun, Moon, Monitor } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const modes = ["system", "light", "dark"] as const;
const icons: Record<string, React.ElementType> = {
  system: Monitor,
  light: Sun,
  dark: Moon,
};
const labels: Record<string, string> = {
  system: "System theme",
  light: "Light theme",
  dark: "Dark theme",
};

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  if (!mounted) {
    return (
      <Button
        variant="ghost"
        size="icon"
        className="h-8 w-8 text-muted-foreground"
        disabled
      >
        <Monitor className="h-4 w-4" />
      </Button>
    );
  }

  const current = theme ?? "system";
  const nextIdx = (modes.indexOf(current as (typeof modes)[number]) + 1) % modes.length;
  const next = modes[nextIdx];
  const Icon = icons[current] ?? Monitor;

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-muted-foreground hover:text-foreground hover:bg-secondary"
            onClick={() => setTheme(next)}
          />
        }
      >
        <Icon className="h-4 w-4 transition-transform duration-200" />
      </TooltipTrigger>
      <TooltipContent side="bottom" className="text-xs">
        {labels[current]}
      </TooltipContent>
    </Tooltip>
  );
}
