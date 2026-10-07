import { defineConfig } from "vite";

// base "./": Freenet serves the app from a sandboxed iframe under a contract path.
export default defineConfig({ base: "./", build: { target: "es2022", assetsInlineLimit: 0 } });
