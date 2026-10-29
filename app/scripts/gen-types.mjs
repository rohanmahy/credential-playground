// Generates src/lib/engine/types/index.ts from the tokenator-core DTOs
// (ts-rs, feature `ts`) via `cargo run -p ts-bindings`, formatted with
// Prettier. With --check, fails if the committed file is out of date.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as prettier from 'prettier';

const appDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const repoDir = join(appDir, '..');
const target = join(appDir, 'src/lib/engine/types/index.ts');
const check = process.argv.includes('--check');

const raw = execFileSync('cargo', ['run', '--quiet', '--locked', '-p', 'ts-bindings'], {
  cwd: repoDir,
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'inherit'],
});
const options = (await prettier.resolveConfig(target)) ?? {};
const formatted = await prettier.format(raw, { ...options, filepath: target });

if (check) {
  let current = '';
  try {
    current = readFileSync(target, 'utf8');
  } catch {
    // missing counts as out of date
  }
  if (current !== formatted) {
    console.error('src/lib/engine/types/index.ts is out of date: run `pnpm gen:types`.');
    process.exit(1);
  }
  console.log('generated types are up to date');
} else {
  writeFileSync(target, formatted);
  console.log(`wrote ${target}`);
}
