/* tslint:disable */
/* eslint-disable */

/**
 * Build a complete `importdescriptors '<json>'` command from UI params.
 * Input/output are JSON strings.
 */
export function build_import(params_json: string): string;

/**
 * Validate a descriptor and return it with its (correct) checksum appended.
 */
export function compute_checksum(desc: string): string;

/**
 * Parse a pasted `importdescriptors ...` command (or bare JSON array) and
 * extract + validate every descriptor inside it.
 */
export function extract_command(text: string): string;

export function init(): void;

/**
 * Mint a fresh `importdescriptors` command from previously extracted
 * descriptors plus new shared options. Every descriptor is re-validated and
 * its checksum recomputed, so mangled pastes self-heal.
 */
export function rebuild_command(params_json: string): string;

export function wasm_version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly build_import: (a: number, b: number) => [number, number, number, number];
    readonly compute_checksum: (a: number, b: number) => [number, number, number, number];
    readonly extract_command: (a: number, b: number) => [number, number, number, number];
    readonly init: () => void;
    readonly rebuild_command: (a: number, b: number) => [number, number, number, number];
    readonly wasm_version: () => [number, number];
    readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
    readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
