import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const backend = process.env.ADVISOR_BACKEND || "http://localhost:9034";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The UI imports src/alert_level.ts from the server tree (one alert-level rule for both), so the dev server may read one level up.
  server: { port: 5174, proxy: { "/api": backend, "/health": backend, "/busy": backend }, fs: { allow: [path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")] } },
});
