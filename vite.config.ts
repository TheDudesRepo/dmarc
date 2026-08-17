import react from "@vitejs/plugin-react";
import { configDefaults, defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const cloudflareRuntimeShim = fileURLToPath(new URL("./test/cloudflare-runtime-shim.ts", import.meta.url));

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  ...(mode === "test" ? {
    test: {
      exclude: [...configDefaults.exclude, "scanner-container/**"],
    },
    resolve: {
      alias: {
        "cloudflare:sockets": cloudflareRuntimeShim,
        "cloudflare:workers": cloudflareRuntimeShim,
        "cloudflare:workflows": cloudflareRuntimeShim,
      },
    },
  } : {}),
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8787",
    },
  },
}));
