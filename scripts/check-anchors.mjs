import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'public' || entry.name === '.git' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.name.endsWith('.html')) files.push(full);
  }
}
walk(root);

function routeFor(file) {
  const rel = path.relative(root, file).replace(/\\/g, '/');
  if (rel === 'index.html') return '/';
  if (rel.endsWith('/index.html')) return `/${rel.slice(0, -10)}/`;
  return `/${rel.slice(0, -5)}`;
}
const routeFiles = new Map(files.map(file => [routeFor(file), file]));
routeFiles.set('/products', path.join(root, 'products', 'index.html'));

function decode(value) {
  return value.replace(/&amp;/g, '&').replace(/&#35;/g, '#');
}
const invalid = [];
let checked = 0;
for (const source of files) {
  const html = fs.readFileSync(source, 'utf8');
  const sourceRoute = routeFor(source);
  for (const match of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
    const href = decode(match[1]);
    if (!href.includes('#') || /^(?:mailto:|tel:|javascript:)/i.test(href)) continue;
    const url = new URL(href, `https://centrocontainers.com${sourceRoute}`);
    if (url.origin !== 'https://centrocontainers.com' || !url.hash) continue;
    checked += 1;
    const destination = routeFiles.get(url.pathname) || routeFiles.get(url.pathname.replace(/\/$/, ''));
    const fragment = decodeURIComponent(url.hash.slice(1));
    if (!destination || !fs.existsSync(destination)) {
      invalid.push({ source: path.relative(root, source).replace(/\\/g, '/'), href, reason: 'missing route' });
      continue;
    }
    const targetHtml = fs.readFileSync(destination, 'utf8');
    const escaped = fragment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (!new RegExp(`\\bid\\s*=\\s*["']${escaped}["']`, 'i').test(targetHtml)) {
      invalid.push({ source: path.relative(root, source).replace(/\\/g, '/'), href, reason: `missing #${fragment}` });
    }
  }
}

if (invalid.length) {
  console.error(`ANCHOR_QA_FAILED: ${invalid.length} invalid of ${checked} checked`);
  for (const item of invalid) console.error(`${item.source}: ${item.href} (${item.reason})`);
  process.exit(1);
}
console.log(`ANCHOR_QA_OK: 0 invalid of ${checked} fragment links checked`);
