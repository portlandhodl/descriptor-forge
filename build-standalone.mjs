// Builds descriptor-forge.html — a single self-contained HTML file with the
// wasm-bindgen glue and the compiled .wasm (base64) inlined. No server needed;
// the file works when opened directly in a browser (file://) too.
//
// Usage:  wasm-pack build --target web   (if Rust changed)
//         node build-standalone.mjs

import { readFileSync, writeFileSync } from "node:fs";

const PKG_JS = new URL("./pkg/descriptor_forge.js", import.meta.url);
const PKG_WASM = new URL("./pkg/descriptor_forge_bg.wasm", import.meta.url);
const INDEX = new URL("./index.html", import.meta.url);
const OUT = new URL("./descriptor-forge.html", import.meta.url);

// 1. wasm-bindgen glue, with module exports stripped so it inlines into the page
let glue = readFileSync(PKG_JS, "utf8")
  .replace(/^export \{[^}]*\};?\s*$/m, "")
  .replace(/^export function /gm, "function ");
if (/^export /m.test(glue)) throw new Error("unstripped export remains in glue");
if (/^import .*from/m.test(glue)) throw new Error("unexpected import in glue");

// 2. compiled wasm → base64 payload
const wasmBuf = readFileSync(PKG_WASM);
const injected = `/* ==== inlined wasm-bindgen glue ==== */
${glue}
/* ==== inlined wasm binary (${Math.round(wasmBuf.length / 1024)} KiB, base64) ==== */
const WASM_B64 = "${wasmBuf.toString("base64")}";
function wasmBytes() {
  const bin = atob(WASM_B64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
/* ==== app ==== */
`;

// 3. swap the network loader for inline instantiation
let html = readFileSync(INDEX, "utf8");
const LOADER =
  '    const wasm = await import("./pkg/descriptor_forge.js");\n    await wasm.default();';
const INLINE_LOADER =
  "    await __wbg_init({ module_or_path: wasmBytes() });\n" +
  "    const wasm = { build_import, extract_command, compute_checksum, wasm_version };";
if (!html.includes(LOADER)) throw new Error("loader snippet not found — index.html changed?");
html = html.replace(LOADER, INLINE_LOADER);

// 4. adjust the failure hint (there is no pkg/ to rebuild in single-file mode)
const errRe = /🚫 WebAssembly module failed to load:[\s\S]*?won't work\.<\/div>`;/;
if (!errRe.test(html)) throw new Error("error-message snippet not found in index.html");
html = html.replace(
  errRe,
  "🚫 Inlined WebAssembly failed to instantiate: <code>${e}</code></div>`;"
);

// 5. inject glue + payload at the top of the module script
const SCRIPT_OPEN = '<script type="module">';
if (!html.includes(SCRIPT_OPEN)) throw new Error("module script not found");
html = html.replace(SCRIPT_OPEN, SCRIPT_OPEN + "\n" + injected);

writeFileSync(OUT, html);
console.log(
  `wrote descriptor-forge.html (${Math.round(html.length / 1024)} KiB total, ` +
  `${Math.round(wasmBuf.length / 1024)} KiB wasm inlined)`
);
