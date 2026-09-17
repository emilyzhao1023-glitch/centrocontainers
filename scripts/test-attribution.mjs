import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../attribution.js', import.meta.url), 'utf8');
const customPage = fs.readFileSync(new URL('../custom-container-components.html', import.meta.url), 'utf8');
const storage = new Map();
const expected = {
  utm_source:'google', utm_medium:'cpc', utm_campaign:'review', utm_term:'matched-keyword',
  utm_content:'ad-a', gclid:'g1', gbraid:'b1', wbraid:'w1',
  landing_page:'/custom-container-components', referrer:'https://www.google.com/'
};

function expect(condition, message) { if (!condition) throw new Error(message); }
function runPage({ search, pathname, referrer }) {
  const inputs = new Map();
  const form = {
    dataset:{ formType:'manufacturing' },
    querySelector(selector) { const name = selector.match(/name="([^"]+)"/)?.[1]; return name ? inputs.get(name) || null : null; },
    appendChild(input) { inputs.set(input.name, input); },
    addEventListener() {}, removeEventListener() {}
  };
  const document = {
    referrer,
    addEventListener(type, callback) { if (type === 'DOMContentLoaded') callback(); },
    querySelectorAll(selector) { return selector === 'form[data-form-type]' ? [form] : []; },
    createElement() { return { type:'', name:'', value:'' }; }
  };
  const sessionStorage = {
    getItem(key) { return storage.has(key) ? storage.get(key) : null; },
    setItem(key, value) { storage.set(key, value); }
  };
  const window = { location:{ search, pathname }, sessionStorage, dataLayer:[], dispatchEvent() {} };
  vm.runInNewContext(source, { window, document, sessionStorage, URLSearchParams, CustomEvent:class {}, console });
  return Object.fromEntries([...inputs].map(([name, input]) => [name, input.value]));
}

const query = '?' + new URLSearchParams(Object.fromEntries(Object.entries(expected).filter(([key]) => !['landing_page','referrer'].includes(key))));
const first = runPage({ search:query, pathname:'/custom-container-components', referrer:expected.referrer });
const second = runPage({ search:'', pathname:'/contact', referrer:'https://centrocontainers.com/custom-container-components' });
for (const [key, value] of Object.entries(expected)) {
  expect(first[key] === value, `first-touch attribution missing ${key}`);
  expect(second[key] === value, `RFQ continuity missing ${key}`);
}

const loaderMatches = customPage.match(/googletagmanager\.com\/gtag\/js\?id=AW-18230780035/g) || [];
expect(loaderMatches.length === 1, 'Custom Manufacturing must load the existing Google tag exactly once');
expect(customPage.includes("gtag('consent','default',{ad_storage:'denied',analytics_storage:'denied',ad_user_data:'denied',ad_personalization:'denied'"), 'Custom Manufacturing consent defaults are not denied');
expect(!customPage.includes("gtag('consent','default',{ad_storage:'granted'"), 'Custom Manufacturing consent was incorrectly granted');
expect(source.includes("'utm_term'"), 'utm_term is not captured');

console.log('ATTRIBUTION_QA_OK: UTM/click IDs, landing page and referrer persist to RFQ; existing tag loads once with denied defaults');

