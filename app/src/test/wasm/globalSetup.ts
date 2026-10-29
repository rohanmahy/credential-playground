// The wasm tests need the release module; fail early and clearly without it.
import { existsSync } from 'node:fs';
import { WASM_FILE } from './helpers';

export default function setup(): void {
  if (!existsSync(WASM_FILE)) {
    throw new Error(`${WASM_FILE} is missing: run \`pnpm build:wasm\` first`);
  }
}
