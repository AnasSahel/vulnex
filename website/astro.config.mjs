import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import mdx from '@astrojs/mdx';

const isProd = process.env.NODE_ENV === 'production';

export default defineConfig({
  integrations: [mdx()],
  vite: {
    plugins: [tailwindcss()],
  },
  site: isProd ? 'https://anassahel.github.io' : 'http://localhost:4321',
  base: isProd ? '/vulnex' : '/',
});
