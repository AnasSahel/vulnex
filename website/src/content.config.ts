import { defineCollection, z } from 'astro:content';
import { file } from 'astro/loaders';

const docs = defineCollection({
  loader: file('src/data/docs.yaml'),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    section: z.enum(['getting-started', 'commands']),
    order: z.number(),
    subcommands: z.array(z.object({
      id: z.string(),
      label: z.string(),
    })).optional(),
  }),
});

export const collections = { docs };
