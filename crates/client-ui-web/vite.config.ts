import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed port; if that's not available, it will use the next one.
export default defineConfig(async () => ({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: "es2022",
    minify: "esbuild",
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          // three is only used by the lazily-loaded TopologyPage; splitting it
          // into its own chunk keeps ~600KB of 3D engine out of the initial
          // bundle while letting TopologyPage's async import pull it on demand.
          three: ["three"],
        },
      },
    },
  },
}));
