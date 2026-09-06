# ⚡ Descriptor Forge

A quick & fun WebAssembly page for forging and inspecting Bitcoin Core
`importdescriptors` commands. All descriptor validation and checksums are done
by **rust-miniscript** (same checksum algorithm as Bitcoin Core) compiled to WASM.

## Run — single file (easiest)

`descriptor-forge.html` is the whole app in one file — the compiled WASM is
inlined as base64, so it works when opened directly (`file://`, double-click)
or served over HTTP. Rebuild it with:

```sh
wasm-pack build --target web   # rebuilds pkg/ after Rust changes
node build-standalone.mjs      # regenerates descriptor-forge.html
```

## Run — dev mode

```sh
python3 -m http.server 8000    # then open http://localhost:8000 (index.html loads pkg/)
```

Dev mode must be served over HTTP (not `file://`) so the browser can fetch the WASM.

## Features

- **Browser compatibility check on startup** — WebAssembly, streaming compile,
  ES modules, BigInt, fetch, secure RNG, clipboard; the app only unlocks if the
  core checks pass.
- **Forge tab** — script flavor (`wsh(multi)`, `wsh(sortedmulti)`, `wpkh`,
  `sh(wpkh)`, `pkh`, or raw descriptor), m-of-n threshold, per-key
  fingerprint/origin/xpub/path, receive+change branch generation, `active`,
  `timestamp` (unix or `"now"`), `range`, `next_index`, `label`. Output is a
  copy-paste-ready `importdescriptors '[...]'` command plus each descriptor
  with its computed checksum.
- **Extract tab** — paste any `importdescriptors` command (or bare JSON array)
  to pull out every descriptor, verify its checksum, and show script type,
  keys, and import options.

## Test

```sh
cargo test                 # native unit tests (incl. checksum fixtures)
node /tmp/opencode/forge_smoke.mjs   # smoke-test the built WASM bundle
```
