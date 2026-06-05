import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build the SPA straight into the Go binary's embed directory.
export default defineConfig({
  plugins: [react()],
  // Relative base so the SPA loads correctly when mounted under a secret
  // admin path (e.g. /admin-ab12/) instead of the web root.
  base: "./",
  build: {
    outDir: "cmd/zanoza-panel/web/dist",
    emptyOutDir: true,
  },
});
