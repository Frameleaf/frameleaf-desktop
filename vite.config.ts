import { fileURLToPath } from "node:url";
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
export default defineConfig({ plugins: [svelte()], clearScreen: false, server: { host: '127.0.0.1', port: 1420, strictPort: true }, build: {
  target: ['es2022', 'safari15'],
  rollupOptions: { input: {
    main: fileURLToPath(new URL('./index.html', import.meta.url)),
    offlinePhotos: fileURLToPath(new URL('./offline-photos.html', import.meta.url)),
  } },
} });
