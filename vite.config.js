import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, the frontend runs on Vite's port and proxies /api to the backend.
// In production, server.js serves the built files and handles /api directly.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:3001",
    },
  },
});
