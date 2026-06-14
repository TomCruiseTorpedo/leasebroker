import { defineConfig } from 'vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';

export default defineConfig({
  server: {
    port: 3210,
    // Allow importing the leasebroker core's compiled dist/ from one level up.
    fs: { allow: ['..'] },
  },
  plugins: [
    // tanstackStart must come before the React plugin.
    tanstackStart(),
    viteReact(),
  ],
});
