import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

const isProd = process.env.NODE_ENV === 'production';

export default defineConfig({
  vite: {
    plugins: [tailwindcss()],
  },
  site: isProd ? 'https://anassahel.github.io' : 'http://localhost:4321',
  base: isProd ? '/vulnex' : '/',
});
