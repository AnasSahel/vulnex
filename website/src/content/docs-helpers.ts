import { getCollection, type CollectionEntry } from 'astro:content';

export type DocsEntry = CollectionEntry<'docs'>;

export interface DocsSubcommand {
  id: string;
  label: string;
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
  icon: string;
  pages: DocsPage[];
}

const sectionMeta: Record<string, { label: string; icon: string }> = {
  'getting-started': {
    label: 'Getting Started',
    icon: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>`,
  },
  commands: {
    label: 'Commands',
    icon: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="m8 8 4 4-4 4"/><line x1="14" x2="18" y1="16" y2="16"/></svg>`,
  },
};

function entryToPage(entry: DocsEntry): DocsPage {
  return {
    slug: entry.id,
    title: entry.data.title,
    description: entry.data.description,
    subcommands: entry.data.subcommands,
  };
}

/** Get all docs sections with pages sorted by order. */
export async function getDocsSections(): Promise<DocsSection[]> {
  const entries = await getCollection('docs');
  const grouped = new Map<string, DocsEntry[]>();

  for (const entry of entries) {
    const section = entry.data.section;
    if (!grouped.has(section)) grouped.set(section, []);
    grouped.get(section)!.push(entry);
  }

  const sectionOrder = ['getting-started', 'commands'];
  return sectionOrder
    .filter(key => grouped.has(key))
    .map(key => {
      const meta = sectionMeta[key];
      const pages = grouped.get(key)!
        .sort((a, b) => a.data.order - b.data.order)
        .map(entryToPage);
      return { key, label: meta.label, icon: meta.icon, pages };
    });
}

/** Flat ordered list of all docs pages. */
export async function getAllPages(): Promise<DocsPage[]> {
  const sections = await getDocsSections();
  return sections.flatMap(s => s.pages);
}

/** Get prev/next pages for a given slug. */
export async function getPagerLinks(slug: string): Promise<{ prev?: DocsPage; next?: DocsPage }> {
  const pages = await getAllPages();
  const idx = pages.findIndex(p => p.slug === slug);
  return {
    prev: idx > 0 ? pages[idx - 1] : undefined,
    next: idx < pages.length - 1 ? pages[idx + 1] : undefined,
  };
}
