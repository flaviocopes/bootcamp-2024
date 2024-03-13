import tailwind from '@astrojs/tailwind'
import { defineConfig } from 'astro/config'

import node from '@astrojs/node'
import 'dotenv/config'

// https://astro.build/config
export default defineConfig({
  integrations: [tailwind()],
  output: 'server',
  adapter: node({
    mode: 'standalone',
  }),
  redirects: {
    '/app': '/app/dashboard',
  },
})
