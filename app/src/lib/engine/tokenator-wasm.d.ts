// The binding surface of crates/tokenator-wasm (wasm-pack --target web),
// declared here so type-checking works without the Rust build. The
// generated pkg/tokenator_wasm.d.ts must declare the same names;
// src/test/wasm/binary.test.ts checks that. See
// crates/tokenator-wasm/TEST-PLAN.md §1.
declare module 'tokenator-wasm' {
  /** Every method returns `{"ok":…}` or `{"err":EngineError}` as JSON text. */
  export class TokenatorEngine {
    /** Throws the `{"err":…}` envelope text when `snapshot` is unreadable. */
    constructor(snapshot?: Uint8Array | null);
    free(): void;
    info(): string;
    detect(input: Uint8Array): string;
    open(input: Uint8Array, candidate: string, view: string): string;
    render(req: string): string;
    parse_edit(req: string): string;
    issue(req: string): string;
    redact(req: string): string;
    disclose(req: string): string;
    present(req: string): string;
    validate(req: string): string;
    lint(req: string): string;
    resign(req: string): string;
    tamper(req: string): string;
    reencode(req: string): string;
    edit_disclosures(req: string): string;
    decode_embedded(req: string): string;
    key_import(req: string): string;
    key_export(req: string): string;
    key_public(key: string): string;
    key_generate(req: string): string;
    key_thumbprint(req: string): string;
    key_assign_kid(req: string): string;
    key_to_jwk(req: string): string;
    key_to_cwk(req: string): string;
    datetime(req: string): string;
    registry_lookup(query: string): string;
    registry_merge(req: string): string;
    /** Test hook: panics inside a method call. Never used by the app. */
    panic_for_tests(message: string): void;
  }

  export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

  /** Instantiates the module (fetching the .wasm next to the glue by default). */
  export default function init(
    options?: { module_or_path?: InitInput | Promise<InitInput> } | undefined,
  ): Promise<unknown>;

  export function initSync(options: { module: BufferSource | WebAssembly.Module }): unknown;
}
