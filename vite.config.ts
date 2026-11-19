import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
// The version the Welcome footer shows: the one this build was made from.
const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string };
export default defineConfig({ plugins: [svelte()], clearScreen: false, define: { 'import.meta.env.VITE_APP_VERSION': JSON.stringify(version) }, server: { host: '127.0.0.1', port: 1420, strictPort: true }, build: {
  target: ['es2022', 'safari15'],
  rollupOptions: { input: {
    main: fileURLToPath(new URL('./index.html', import.meta.url)),
    offlinePhotos: fileURLToPath(new URL('./offline-photos.html', import.meta.url)),
  } },
} });
