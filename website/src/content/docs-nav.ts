/** Docs navigation structure — single source of truth for sidebar, hub, and pager. */

export interface DocsPage {
  slug: string;
  title: string;
  description: string;
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
      { slug: "cve", title: "CVE Commands", description: "Search, list, fetch, and track CVEs from the NVD." },
      { slug: "epss", title: "EPSS Commands", description: "Query exploit prediction scores, top exploited CVEs, and score trends." },
    ],
  },
  {
    key: "scoring",
    label: "Scoring & Policy",
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
