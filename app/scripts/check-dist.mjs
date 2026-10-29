// Checks the built site in dist/ before a Pages deploy: index.html starts
// with the production CSP <meta> (csp.config.ts), and nothing refers to an
// absolute path, so the site works under any base path
// (https://rohanmahy.github.io/credential-playground/) as well as in Tauri.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const problems = [];

const html = readFileSync(join(dist, 'index.html'), 'utf8');
const metas = [...html.matchAll(/<meta http-equiv="Content-Security-Policy" content="([^"]*)"/g)];
if (metas.length !== 1) {
  problems.push(`index.html has ${metas.length} CSP <meta> elements, expected 1`);
} else {
  // Vite writes the quotes as &#39;.
  const policy = (metas[0]?.[1] ?? '').replaceAll('&#39;', "'");
  if (!/<head>\s*<meta http-equiv="Content-Security-Policy"/.test(html)) {
    problems.push('the CSP <meta> is not the first element of <head>');
  }
  for (const directive of [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval';",
    "object-src 'none'",
    "base-uri 'none'",
  ]) {
    if (!policy.includes(directive)) problems.push(`the CSP lacks "${directive}"`);
  }
  if (policy.includes("'unsafe-eval'")) problems.push("the CSP allows 'unsafe-eval'");
}
for (const [, attr, url = ''] of html.matchAll(/\b(src|href)="([^"]*)"/g)) {
  if (url.startsWith('/') || /^[a-z]+:/i.test(url)) {
    problems.push(`index.html: ${attr}="${url}" is not a relative URL`);
  }
}

// Vite writes asset URLs into the JS; with base './' they are relative.
const assets = join(dist, 'assets');
for (const name of readdirSync(assets).filter((n) => n.endsWith('.js'))) {
  const js = readFileSync(join(assets, name), 'utf8');
  if (/["'`]\/assets\//.test(js)) problems.push(`assets/${name} refers to /assets/`);
}

if (problems.length > 0) {
  for (const p of problems) console.error(`check-dist: ${p}`);
  process.exit(1);
}
console.log('check-dist: CSP present, all asset URLs relative');
