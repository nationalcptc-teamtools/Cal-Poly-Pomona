import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '127.0.0.1',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  // The typst.ts packages ship wasm-pack shims + large wasm that esbuild's dep
  // pre-bundler mishandles; they are loaded lazily via dynamic import + `?url`.
  optimizeDeps: { exclude: ['@myriaddreamin/typst.ts', '@myriaddreamin/typst-ts-web-compiler', '@myriaddreamin/typst-ts-renderer'] },
  // The compiler worker uses dynamic imports; Vite's default iife worker
  // format cannot code-split.
  worker: { format: 'es' },
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [{ name: 'icons', test: /node_modules[\\/]lucide-react[\\/]/ }],
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
});
