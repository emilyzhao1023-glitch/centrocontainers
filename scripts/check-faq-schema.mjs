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

function text(value) {
  return value.replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
}
function faqNodes(value, found = []) {
  if (!value || typeof value !== 'object') return found;
  if (value['@type'] === 'FAQPage') found.push(value);
  for (const child of Object.values(value)) {
    if (Array.isArray(child)) child.forEach(item => faqNodes(item, found));
    else faqNodes(child, found);
  }
  return found;
}

const failures = [];
let schemaPages = 0;
let questionCount = 0;
for (const file of files) {
  const html = fs.readFileSync(file, 'utf8');
  const visible = [];
  for (const match of html.matchAll(/<details\b[^>]*>([\s\S]*?)<\/details>/gi)) {
    const block = match[1];
    const q = block.match(/<summary\b[^>]*>([\s\S]*?)<\/summary>/i);
    const a = block.match(/<p\b[^>]*>([\s\S]*?)<\/p>/i);
    if (q && a) visible.push([text(q[1]), text(a[1])]);
  }
  for (const match of html.matchAll(/<div\b[^>]*class=["'][^"']*faq-item[^"']*["'][^>]*>([\s\S]*?)<\/div>/gi)) {
    const block = match[1];
    const q = block.match(/<h3\b[^>]*>([\s\S]*?)<\/h3>/i);
    const a = block.match(/<p\b[^>]*>([\s\S]*?)<\/p>/i);
    if (q && a) visible.push([text(q[1]), text(a[1])]);
  }
  for (const match of html.matchAll(/<article\b[^>]*>([\s\S]*?)<\/article>/gi)) {
    const block = match[1];
    const q = block.match(/<h3\b[^>]*>([\s\S]*?)<\/h3>/i);
    const a = block.match(/<p\b[^>]*>([\s\S]*?)<\/p>/i);
    if (q && a) visible.push([text(q[1]), text(a[1])]);
  }
  for (const match of html.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    let json;
    try { json = JSON.parse(match[1]); }
    catch (error) { failures.push(`${path.relative(root, file)}: invalid JSON-LD (${error.message})`); continue; }
    for (const faq of faqNodes(json)) {
      schemaPages += 1;
      for (const entity of faq.mainEntity || []) {
        questionCount += 1;
        const pair = [text(entity.name || ''), text(entity.acceptedAnswer?.text || '')];
        if (!visible.some(item => item[0] === pair[0] && item[1] === pair[1])) failures.push(`${path.relative(root, file)}: schema does not exactly match visible FAQ: ${pair[0]}`);
      }
    }
  }
}
if (failures.length) {
  console.error(`FAQ_SCHEMA_QA_FAILED: ${failures.length} mismatch(es)`);
  failures.forEach(item => console.error(item));
  process.exit(1);
}
console.log(`FAQ_SCHEMA_QA_OK: ${schemaPages} FAQPage blocks, ${questionCount} exactly matched questions`);
