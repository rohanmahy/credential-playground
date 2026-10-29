/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { cspString } from './csp.config.ts';

// Adds the CSP <meta> to the production index.html (not in dev, where Vite's
// HMR client needs inline scripts and a websocket).
function cspMeta(): Plugin {
  return {
    name: 'tokenator-csp-meta',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler: () => [
        {
          tag: 'meta',
          attrs: { 'http-equiv': 'Content-Security-Policy', content: cspString() },
          injectTo: 'head-prepend',
        },
      ],
    },
  };
}

export default defineConfig({
  plugins: [svelte(), svelteTesting(), cspMeta()],
  // Relative asset paths, for GitHub Pages and the Tauri bundle.
  base: './',
  build: {
    target: 'es2022',
    // Inline nothing as data: URLs; everything is loaded from 'self'.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    setupFiles: ['src/test/setup.ts'],
    restoreMocks: true,
  },
});
