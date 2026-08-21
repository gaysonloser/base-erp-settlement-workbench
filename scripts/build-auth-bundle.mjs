import { build } from "esbuild";
import { readFileSync, writeFileSync } from "node:fs";

await build({
  entryPoints: ["src/auth/browser-entry.mjs"],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: ["es2022"],
  outfile: "public/assets/base-auth-sdk.bundle.js",
  sourcemap: false,
  legalComments: "none",
  minify: true,
  drop: ["console"],
  // The SDK's global store is persistent by default. Keep the bundled auth
  // route strictly ephemeral: no wallet/session material may reach browser
  // storage even after the explicit sign-in click.
  define: {
    localStorage: "__baseAuthMemoryStorage",
    sessionStorage: "__baseAuthMemoryStorage",
    "window.indexedDB": "undefined",
    indexedDB: "undefined",
    "console.error": "__baseAuthNoop",
    "console.warn": "__baseAuthNoop",
    "console.log": "__baseAuthNoop",
    "console.group": "__baseAuthNoop",
    "console.groupEnd": "__baseAuthNoop",
  },
  banner: {
    js: "const __baseAuthMemoryStorage=Object.freeze({getItem(){return null},setItem(){},removeItem(){},clear(){},key(){return null},length:0});const __baseAuthNoop=()=>{};const __baseAuthNoIndexedDb=undefined;",
  },
});

// Keep vendor diagnostics from reaching the page console. This is a
// deterministic post-build hardening pass over the generated asset only.
const bundlePath = "public/assets/base-auth-sdk.bundle.js";
const bundle = readFileSync(bundlePath, "utf8")
  .replaceAll("console.", "__baseAuthNoop.")
  .replaceAll("o.console", "o.__baseAuthNoConsole")
  .replaceAll("indexedDB", "__baseAuthNoIndexedDb");
writeFileSync(bundlePath, bundle);
