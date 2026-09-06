# ⚡ Descriptor Forge

A quick & fun WebAssembly page for decoding and rebuilding Bitcoin Core
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

- **Extract** — paste any `importdescriptors` command (or bare JSON
  array). Shell-escaped pastes are decoded automatically (`'\''`, `'"'"'`,
  `\'`, `\"` from hardened path markers and shell quoting). Every descriptor is
  validated, checksum-verified, and decoded into script type, keys, import
  options, and `after()` timelocks (with human dates).
- **Rebuild** — mint a fresh command from extracted descriptors with new
  shared options; checksums are recomputed so mangled pastes self-heal.
- **Bash-safe output** — commands are emitted both raw (Core console) and with
  single quotes pre-escaped (`'\''`) for direct terminal pasting.

## Test

```sh
cargo test                        # native unit tests (incl. real Core checksum fixtures)
node build-standalone.mjs         # regenerate the single-file build
```
