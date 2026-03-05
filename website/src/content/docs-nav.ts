/** Docs navigation structure — single source of truth for sidebar, hub, and pager. */

export interface DocsSubcommand {
  id: string;       // anchor id, e.g. "kev-list"
  label: string;    // display name, e.g. "kev list"
}

export interface DocsPage {
  slug: string;
  title: string;
  description: string;
  subcommands?: DocsSubcommand[];
}

export interface DocsSection {
  key: string;
  label: string;
  icon: string; // SVG string
  pages: DocsPage[];
}

export const docsSections: DocsSection[] = [
  {
    key: "getting-started",
    label: "Getting Started",
    icon: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>`,
    pages: [
      { slug: "getting-started", title: "Quick Start", description: "Install vulnex and run your first query in under two minutes." },
    ],
  },
  {
    key: "commands",
    label: "Commands",
    icon: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="m8 8 4 4-4 4"/><line x1="14" x2="18" y1="16" y2="16"/></svg>`,
    pages: [
      {
        slug: "cve", title: "cve", description: "Search, list, fetch, and track CVEs from the NVD.",
        subcommands: [
          { id: "cve-get", label: "cve get" },
          { id: "cve-search", label: "cve search" },
          { id: "cve-list", label: "cve list" },
          { id: "cve-history", label: "cve history" },
          { id: "cve-watch", label: "cve watch" },
        ],
      },
      {
        slug: "kev", title: "kev", description: "Browse, check, and filter CISA Known Exploited Vulnerabilities.",
        subcommands: [
          { id: "kev-list", label: "kev list" },
          { id: "kev-recent", label: "kev recent" },
          { id: "kev-check", label: "kev check" },
          { id: "kev-stats", label: "kev stats" },
        ],
      },
      {
        slug: "epss", title: "epss", description: "Query exploit prediction scores, top exploited CVEs, and score trends.",
        subcommands: [
          { id: "epss-score", label: "epss score" },
          { id: "epss-top", label: "epss top" },
          { id: "epss-trend", label: "epss trend" },
        ],
      },
      {
        slug: "advisory", title: "advisory", description: "Search, retrieve, and inspect security advisories from GitHub Advisory Database.",
        subcommands: [
          { id: "advisory-search", label: "advisory search" },
          { id: "advisory-get", label: "advisory get" },
          { id: "advisory-affected", label: "advisory affected" },
        ],
      },
      {
        slug: "exploit", title: "exploit", description: "Find public exploits, PoCs, and attack tools for CVEs across GitHub, Metasploit, Nuclei, and ExploitDB.",
        subcommands: [
          { id: "exploit-check", label: "exploit check" },
        ],
      },
    ],
  },
  {
    key: "reference",
    label: "Reference",
    icon: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20v-6M6 20V10M18 20V4"/></svg>`,
    pages: [
      { slug: "scoring", title: "Scoring & Prioritization", description: "Composite risk scoring with CVSS, EPSS, and KEV signals." },
    ],
  },
];

/** Flat ordered list of all docs pages for prev/next navigation. */
export const allPages: DocsPage[] = docsSections.flatMap(s => s.pages);

/** Get prev/next pages for a given slug. */
export function getPagerLinks(slug: string): { prev?: DocsPage; next?: DocsPage } {
  const idx = allPages.findIndex(p => p.slug === slug);
  return {
    prev: idx > 0 ? allPages[idx - 1] : undefined,
    next: idx < allPages.length - 1 ? allPages[idx + 1] : undefined,
  };
}
