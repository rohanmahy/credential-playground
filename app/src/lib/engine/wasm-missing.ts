// Stands in for crates/tokenator-wasm/pkg when it has not been built, in
// unit tests only (vite.config.ts). Loading it fails like a broken
// download would, so WasmEngine reports an EngineFailure.
export default async function init(): Promise<never> {
  throw new Error('tokenator-wasm is not built: run `pnpm build:wasm`');
}

export function initSync(): never {
  throw new Error('tokenator-wasm is not built: run `pnpm build:wasm`');
}

/** `new TokenatorEngine()` throws too. */
export function TokenatorEngine(): never {
  throw new Error('tokenator-wasm is not built: run `pnpm build:wasm`');
}
