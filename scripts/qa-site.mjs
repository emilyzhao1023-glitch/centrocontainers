import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve('public');
const failures = [];
const htmlFiles = [];
const requiredRoutes = {
  '/': 'index.html',
  '/custom-container-components': 'custom-container-components.html',
  '/products/': 'products/index.html',
  '/manufacturing-capabilities': 'manufacturing-capabilities.html',
  '/about': 'about.html',
  '/contact': 'contact.html',
  '/products/roof-panel': 'products/roof-panel.html',
  '/products/side-panel': 'products/side-panel.html',
  '/products/cross-member': 'products/cross-member.html',
  '/products/corner-post': 'products/corner-post.html',
  '/products/door-panel': 'products/door-panel.html',
  '/products/door-locking-gear': 'products/door-locking-gear.html',
  '/products/corner-casting': 'products/corner-casting.html',
  '/products/door-gasket': 'products/door-gasket.html',
  '/products/bridge-fitting': 'products/bridge-fitting.html',
  '/landing/container-roof-panel': 'landing/container-roof-panel.html',
  '/landing/container-door-locking-gear': 'landing/container-door-locking-gear.html',
  '/landing/container-corner-casting': 'landing/container-corner-casting.html',
  '/landing/rolling-shutter-door': 'landing/rolling-shutter-door.html'
};

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.name.endsWith('.html')) htmlFiles.push(full);
  }
}
walk(root);

function fail(message) { failures.push(message); }
function existsForPath(urlPath) {
  let clean = decodeURIComponent(urlPath.split(/[?#]/)[0]);
  if (!clean || clean === '/') clean = '/index.html';
  const candidate = path.join(root, clean.replace(/^\//, ''));
  const variants = [candidate];
  if (clean.endsWith('/')) variants.push(path.join(candidate, 'index.html'));
  if (!path.extname(clean)) variants.push(`${candidate}.html`, path.join(candidate, 'index.html'));
  return variants.some(value => fs.existsSync(value));
}

for (const [route, relativeFile] of Object.entries(requiredRoutes)) {
  if (!fs.existsSync(path.join(root, relativeFile))) fail(`Missing route ${route} (${relativeFile})`);
}

for (const file of htmlFiles) {
  const relative = path.relative(root, file).replace(/\\/g, '/');
  const html = fs.readFileSync(file, 'utf8');
  const title = html.match(/<title>([\s\S]*?)<\/title>/i)?.[1]?.trim();
  const description = html.match(/<meta\s+name=["']description["'][^>]*content=["']([^"']+)/i)?.[1];
  const canonicals = [...html.matchAll(/<link\s+rel=["']canonical["'][^>]*href=["']([^"']+)/gi)];
  const h1s = [...html.matchAll(/<h1\b/gi)];
  if (!title) fail(`${relative}: missing title`);
  if (!description) fail(`${relative}: missing meta description`);
  if (canonicals.length !== 1) fail(`${relative}: expected one canonical, found ${canonicals.length}`);
  if (h1s.length !== 1) fail(`${relative}: expected one H1, found ${h1s.length}`);
  if (/<meta\s+name=["']robots["'][^>]*noindex/i.test(html)) fail(`${relative}: accidental noindex`);

  const ids = [...html.matchAll(/\bid=["']([^"']+)["']/gi)].map(match => match[1]);
  for (const duplicate of new Set(ids.filter((id, index) => ids.indexOf(id) !== index))) fail(`${relative}: duplicate id ${duplicate}`);

  const documentUrl = `https://local/${relative}`;
  for (const match of html.matchAll(/\b(?:href|src|poster)=["']([^"']+)["']/gi)) {
    const value = match[1];
    if (/^(?:https?:|mailto:|tel:|data:|javascript:|#)/i.test(value) || value.startsWith('//') || value.startsWith('/api/')) continue;
    const resolved = new URL(value, documentUrl).pathname;
    if (!existsForPath(resolved)) fail(`${relative}: broken local reference ${value}`);
  }
  for (const image of html.matchAll(/<img\b([^>]*)>/gi)) {
    if (!/\balt=["'][^"']*["']/i.test(image[1])) fail(`${relative}: image missing alt attribute`);
  }
  for (const script of html.matchAll(/<script\s+type=["']application\/ld\+json["']>([\s\S]*?)<\/script>/gi)) {
    try { JSON.parse(script[1]); } catch { fail(`${relative}: invalid JSON-LD`); }
  }
  for (const video of html.matchAll(/<video\b([^>]*)>/gi)) {
    if (/\bautoplay\b/i.test(video[1])) fail(`${relative}: video autoplays`);
    if (!/\bpreload=["'](?:metadata|none)["']/i.test(video[1])) fail(`${relative}: video preload is not metadata/none`);
    if (!/\bposter=["'][^"']+["']/i.test(video[1])) fail(`${relative}: video missing poster`);
  }
}

const sitemap = fs.readFileSync(path.join(root, 'sitemap.xml'), 'utf8');
const sitemapUrls = [...sitemap.matchAll(/<loc>https:\/\/centrocontainers\.com([^<]*)<\/loc>/g)].map(match => match[1] || '/');
for (const route of Object.keys(requiredRoutes)) {
  if (!sitemapUrls.includes(route)) fail(`Sitemap missing ${route}`);
}
for (const route of sitemapUrls) {
  if (!existsForPath(route)) fail(`Sitemap route has no file: ${route}`);
}

const robots = fs.readFileSync(path.join(root, 'robots.txt'), 'utf8');
if (/Disallow:\s*\//i.test(robots)) fail('robots.txt blocks the site');
if (!/Sitemap:\s*https:\/\/centrocontainers\.com\/sitemap\.xml/i.test(robots)) fail('robots.txt missing sitemap declaration');

const contact = fs.readFileSync(path.join(root, 'contact.html'), 'utf8');
const requiredFormNames = [...contact.matchAll(/<(?:input|textarea|select)\b(?=[^>]*\brequired\b)[^>]*\bname=["']([^"']+)/gi)].map(match => match[1]);
const expectedRequired = ['name','email','company','country','project_description','drawing_available','batch_quantity','destination'];
for (const name of expectedRequired) if (!requiredFormNames.includes(name)) fail(`RFQ required field missing: ${name}`);
if (requiredFormNames.includes('annual_volume')) fail('Annual volume must be optional');
if (!/name=["']annual_volume["'][^>]*placeholder=["'][^"']*Not confirmed yet/i.test(contact)) fail('Annual volume does not allow “Not confirmed yet”');

const quoteModal = fs.readFileSync(path.join(root, 'quote-modal.js'), 'utf8');
if (quoteModal.indexOf("emit('rfq_success'") < quoteModal.indexOf('response.ok')) fail('rfq_success can fire before backend confirmation');
if (!quoteModal.includes("field('Estimated Annual Volume (optional)','annual_volume','text',false")) fail('Modal annual volume is not optional');

const productKeywordChecks = {
  'roof-panel.html': /(?:container.*roof panel|roof panel.*container)/i,
  'side-panel.html': /(?:container.*side panel|side panel.*container)/i,
  'cross-member.html': /container cross member/i,
  'corner-post.html': /container corner post/i,
  'door-panel.html': /container door panel/i,
  'door-locking-gear.html': /container door locking gear/i
};
for (const [fileName, pattern] of Object.entries(productKeywordChecks)) {
  const html = fs.readFileSync(path.join(root, 'products', fileName), 'utf8');
  const title = html.match(/<title>(.*?)<\/title>/i)?.[1] || '';
  const h1 = html.match(/<h1>(.*?)<\/h1>/i)?.[1] || '';
  if (!pattern.test(title) || !pattern.test(h1)) fail(`${fileName}: product intent missing from title or H1`);
}

if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}
console.log(`SITE_QA_OK: ${htmlFiles.length} HTML files, ${sitemapUrls.length} sitemap URLs`);
