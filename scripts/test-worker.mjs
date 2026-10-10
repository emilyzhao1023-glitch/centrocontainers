import fs from 'node:fs';

const workerSource = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
const lockingGearSource = fs.readFileSync(new URL('../landing/container-door-locking-gear.html', import.meta.url), 'utf8');
const rollingShutterSource = fs.readFileSync(new URL('../landing/rolling-shutter-door.html', import.meta.url), 'utf8');
const worker = (await import(`data:text/javascript;base64,${Buffer.from(workerSource).toString('base64')}`)).default;
const env = { TURNSTILE_SECRET_KEY:'test-only-secret', RESEND_API_KEY:'test', RESEND_FROM_EMAIL:'forms@example.com', RESEND_TO_EMAIL:'sales@example.com' };
let outbound = [];
let backendFailure = false;
let verification = { success:true, hostname:'centrocontainers.com' };
let verifyMode = 'ok';
let verifiedRequests = 0;
globalThis.fetch = async (_url, options) => {
  if (_url === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
    verifiedRequests++;
    expect(options.body.get('secret') === env.TURNSTILE_SECRET_KEY, 'Siteverify secret binding missing');
    expect(options.body.get('response') === 'valid-test-token', 'Siteverify token missing');
    expect(options.body.get('remoteip') === '192.0.2.10', 'Siteverify client IP missing');
    if (verifyMode === 'network') throw new Error('network failure');
    if (verifyMode === 'http') return new Response('unavailable', { status:503 });
    if (verifyMode === 'json') return new Response('not json');
    return new Response(JSON.stringify(verification));
  }
  expect(_url === 'https://api.resend.com/emails', 'Unexpected outbound destination');
  outbound.push(JSON.parse(options.body));
  return backendFailure ? new Response('service unavailable', { status: 503 }) : new Response('{"id":"test"}', { status: 200 });
};

function base(overrides = {}) {
  return {
    form_type:'manufacturing', form_start_time:String(Date.now() - 4000), contact_check:'', 'cf-turnstile-response':'valid-test-token',
    name:'Test Buyer', email:'buyer@example.com', company:'Example OEM', country:'Germany',
    project_description:'Steel container component to supplied drawing', drawing_available:'Drawing available',
    batch_quantity:'500', destination:'Hamburg, Germany', ...overrides
  };
}
async function submit(values) {
  const form = new FormData();
  for (const [key, value] of Object.entries(values)) form.append(key, value);
  const request = new Request('https://centrocontainers.com/api/inquiry', { method:'POST', body:form, headers:{'User-Agent':'QA Browser','CF-Connecting-IP':'192.0.2.10'} });
  const response = await worker.fetch(request, env);
  return { status:response.status, body:await response.json() };
}
function expect(condition, message) { if (!condition) throw new Error(message); }

outbound = [];
let result = await submit(base({ annual_volume:'6000' }));
expect(result.status === 200 && result.body.success && outbound.length === 1, '1 normal legitimate RFQ failed');

outbound = [];
result = await submit(base());
expect(result.status === 200 && result.body.success && outbound.length === 1, '2 minimum-fields RFQ failed');

outbound = [];
result = await submit(base({ phone:'+49 30 123456', drawing_type:'STEP', material:'SPA-H steel', annual_volume:'Not confirmed yet', part_numbers:'2', timing:'Q1', target_cost:'EUR, FOB basis', message:'Export packing required', utm_source:'google', utm_medium:'cpc', utm_campaign:'future-test', utm_term:'matched keyword', utm_content:'ad-a', gclid:'test-gclid', gbraid:'test-gbraid', wbraid:'test-wbraid', landing_page:'/custom-container-components', referrer:'https://www.google.com/' }));
expect(result.status === 200 && outbound.length === 1, '3 all-optional-fields RFQ failed');
for (const value of ['SPA-H steel','Not confirmed yet','Delivery Destination','Matched Keyword','future-test']) expect(outbound[0].html.includes(value), `3 email missing ${value}`);

outbound = [];
result = await submit(base({ destination:'' }));
expect(result.status === 400 && !result.body.success && result.body.missing_fields.includes('destination') && outbound.length === 0, '4 missing-required validation failed');

outbound = [];
result = await submit(base({ email:'invalid-email' }));
expect(result.status === 400 && !result.body.success && outbound.length === 0, '5 invalid-email validation failed');

outbound = [];
const originalWarn = console.warn;
const blockedLogs = [];
console.warn = (...args) => blockedLogs.push(args);
result = await submit(base({ contact_check:'spam-bot' }));
expect(result.status === 200 && result.body.success && outbound.length === 0, '6 honeypot spam handling failed');
expect(blockedLogs.some(args => args[0] === 'Blocked inquiry' && args[1]?.reason === 'honeypot'), '6 honeypot blocked log missing');
console.warn = originalWarn;

outbound = [];
result = await submit(base({ website:'https://example.com', contact_check:'' }));
expect(result.status === 200 && result.body.success && outbound.length === 0, '7 website honeypot failed');

outbound = [];
result = await submit(base({ message:'<a href="https://spam.example">offer</a>' }));
expect(result.status === 200 && result.body.success && outbound.length === 0, '8 HTML-link spam handling failed');
result = await submit(base({ message:'Claim your prize at https://spam.example' }));
expect(result.status === 200 && result.body.success && outbound.length === 0, '8 promotional spam handling failed');
result = await submit(base({ message:'https://one.example https://two.example https://three.example https://four.example' }));
expect(result.status === 400 && !result.body.success && outbound.length === 0, '8 excessive-URL handling failed');
result = await submit(base({ message:'aaaaaaaaaa' }));
expect(result.status === 400 && !result.body.success && outbound.length === 0, '8 repeated-character junk handling failed');
result = await submit(base({ batch_quantity:'12345678', message:'Reference https://example.com/spec' }));
expect(result.status === 200 && result.body.success && outbound.length === 0, '8 invalid quantity with link handling failed');

outbound = [];
backendFailure = true;
result = await submit(base());
expect(result.status === 500 && !result.body.success && outbound.length === 1, '9 backend failure handling failed');
backendFailure = false;

outbound = [];
result = await submit(base());
expect(result.status === 200 && result.body.success && outbound.length === 1, '10 confirmed success failed');

outbound = [];
const firstRepeat = await submit(base());
const secondRepeat = await submit(base({ form_start_time:String(Date.now() - 5000) }));
expect(firstRepeat.status === 200 && secondRepeat.status === 200 && outbound.length === 2, '11 legitimate repeat submission failed');

outbound = [];
result = await submit(base({ form_start_time:String(Date.now()) }));
expect(result.status === 200 && result.body.success && outbound.length === 0, 'Anti-spam minimum-age protection failed');

const lockingGearForm = lockingGearSource.match(/<form\b[^>]*id="quoteForm"[\s\S]*?<\/form>/i)?.[0] || '';
const lockingGearType = lockingGearForm.match(/name="form_type"\s+value="([^"]+)"/i)?.[1];
const lockingGearParts = lockingGearForm.match(/name="parts"\s+value="([^"]+)"/i)?.[1];
const intendedLockingGearFields = ['name','email','phone','country','quantity','destination','message'];
expect(lockingGearType === 'rfq', '12 Door Locking Gear form does not post supported rfq form type');
expect(lockingGearForm.includes('data-form-type="rfq"'), '12 Door Locking Gear data-form-type is not rfq');
expect(/name="contact_check"/i.test(lockingGearForm), '12 Door Locking Gear contact_check honeypot missing');
for (const field of intendedLockingGearFields) expect(new RegExp(`name="${field}"`, 'i').test(lockingGearForm), `12 Door Locking Gear form missing ${field}`);

const lockingGearPayload = {
  form_type:lockingGearType, form_start_time:String(Date.now() - 4000), contact_check:'', 'cf-turnstile-response':'valid-test-token', parts:lockingGearParts,
  name:'Landing Buyer', email:'landing.buyer@example.com', phone:'+49 30 555 0199', country:'Germany',
  quantity:'80 sets', destination:'Hamburg, Germany', message:'40 left, 40 right; confirmed rod length and zinc finish',
  utm_source:'google', utm_medium:'cpc', utm_campaign:'locking-gear', utm_term:'matched locking gear keyword',
  utm_content:'ad-landing', gclid:'landing-gclid', gbraid:'landing-gbraid', wbraid:'landing-wbraid',
  landing_page:'/landing/container-door-locking-gear', referrer:'https://www.google.com/'
};
outbound = [];
result = await submit(lockingGearPayload);
expect(result.status === 200 && result.body.success && outbound.length === 1, '12 valid Door Locking Gear landing RFQ failed');
for (const value of ['Door locking gear','80 sets','Hamburg, Germany','40 left, 40 right','Matched Keyword','matched locking gear keyword']) expect(outbound[0].html.includes(value), `12 Door Locking Gear email missing ${value}`);

outbound = [];
backendFailure = true;
result = await submit(lockingGearPayload);
expect(result.status === 500 && !result.body.success && outbound.length === 1, '12 Door Locking Gear backend failure produced false success');
backendFailure = false;

outbound = [];
result = await submit({ ...lockingGearPayload, contact_check:'bot-filled' });
expect(result.status === 200 && result.body.success && outbound.length === 0, '12 Door Locking Gear honeypot handling failed');

const rollingShutterForm = rollingShutterSource.match(/<form\b[^>]*id="quoteForm"[\s\S]*?<\/form>/i)?.[0] || '';
const rollingShutterType = rollingShutterForm.match(/name="form_type"\s+value="([^"]+)"/i)?.[1];
const rollingShutterParts = rollingShutterForm.match(/name="parts"\s+value="([^"]+)"/i)?.[1];
expect(rollingShutterType === 'rfq', '13 Rolling Shutter Door form does not post supported rfq form type');
expect(rollingShutterForm.includes('data-form-type="rfq"'), '13 Rolling Shutter Door data-form-type is not rfq');
expect(rollingShutterParts === 'Industrial rolling shutter door', '13 Rolling Shutter Door hidden product is incorrect');
expect(/name="contact_check"/i.test(rollingShutterForm), '13 Rolling Shutter Door contact_check honeypot missing');

outbound = [];
result = await submit({
  form_type:rollingShutterType, form_start_time:String(Date.now() - 4000), contact_check:'', 'cf-turnstile-response':'valid-test-token', parts:rollingShutterParts,
  name:'Door Buyer', email:'door.buyer@example.com', country:'Australia', quantity:'8 doors',
  destination:'Melbourne, Australia', message:'Confirmed opening sizes and operation requirements'
});
expect(result.status === 200 && result.body.success && outbound.length === 1, '13 valid Rolling Shutter Door RFQ failed');

console.log('WORKER_QA_OK: normal human, contact_check honeypot, website honeypot, manufacturing RFQ, Door Locking Gear, Rolling Shutter Door, and all existing spam/backend regressions');

const auditLogs = [];
const savedWarn = console.warn;
console.warn = (...args) => auditLogs.push(args);
async function blockedCase(overrides, reason, status = 400) {
  outbound = []; auditLogs.length = 0;
  const response = await submit(base(overrides));
  expect(response.status === status && outbound.length === 0, `Failed block: ${reason}`);
  expect(auditLogs.some(([label, detail]) => label === 'Blocked inquiry' && detail.reason === reason && detail.ip === '192.0.2.10'), `Missing log: ${reason}`);
  expect(!JSON.stringify(auditLogs).includes('buyer@example.com'), 'Sensitive email logged');
  return response;
}
const fixedNow = Date.now();
const savedNow = Date.now;
Date.now = () => fixedNow;
try {
  const missing = base(); delete missing.form_start_time;
  outbound = []; auditLogs.length = 0;
  let response = await submit(missing);
  expect(response.status === 400 && outbound.length === 0, 'Missing timestamp accepted');
  expect(auditLogs.some(([,d]) => d.reason === 'missing-form-start-time'), 'Missing timestamp log absent');
  for (const value of ['', ' ', 'invalid', 'NaN', 'Infinity', '0', '-1', '1e12', String(fixedNow)+'.5']) {
    await blockedCase({form_start_time:value}, value.trim() ? 'invalid-form-start-time' : 'missing-form-start-time');
  }
  await blockedCase({form_start_time:String(fixedNow-3900)}, 'too-fast', 200);
  for (const elapsed of [4000, 4100, 6*60*60*1000+1]) {
    outbound = []; auditLogs.length = 0;
    response = await submit(base({form_start_time:String(fixedNow-elapsed)}));
    expect(response.status === 200 && outbound.length === 1, `Valid elapsed rejected: ${elapsed}`);
    if (elapsed > 6*60*60*1000) expect(auditLogs.some(([label,d]) => label === 'Suspicious inquiry' && d.reason === 'long-form-time' && d.ip === '192.0.2.10'), 'Long form warning missing');
  }
  for (const field of ['website','contact_check']) await blockedCase({[field]:'bot'}, 'honeypot', 200);
  const count = verifiedRequests;
  response = await blockedCase({'cf-turnstile-response':''}, 'missing-turnstile-token');
  expect(verifiedRequests === count, 'Missing token called Siteverify');
  expect(response.body.error === 'Security verification could not be completed. Please refresh the page and try again.', 'Verification error missing');
  verification = {success:false};
  await blockedCase({}, 'invalid-turnstile-token');
  verification = {success:true, hostname:'evil.example'};
  await blockedCase({}, 'unexpected-turnstile-hostname');
  for (const hostname of ['www.centrocontainers.com','centrocontainers.com']) {
    verification = {success:true, hostname}; outbound=[];
    response=await submit(base()); expect(outbound.length===1 && response.body.success, 'Allowed hostname rejected');
  }
  for (const mode of ['network','http','json']) { verifyMode=mode; await blockedCase({}, 'turnstile-siteverify-failure'); }
  verifyMode='ok';
  const secret = env.TURNSTILE_SECRET_KEY; delete env.TURNSTILE_SECRET_KEY;
  await blockedCase({}, 'turnstile-unavailable'); env.TURNSTILE_SECRET_KEY=secret;
  for (const phrase of ['XEvil','CAPTCHA SOLVER','solve captcha','captcha killer','SEO/SMM','password recovery','backlink service','guest post service']) {
    for (const field of ['message','project_description','company']) await blockedCase({[field]:phrase}, 'explicit-spam-content', 200);
  }
  for (const message of ['Container manufacturing RFQ: 500 roof panels to drawing.', 'Our marketing team needs a website link for the product promotion and SEO brief.', 'Specifications: https://one.example https://two.example https://three.example']) {
    outbound=[]; response=await submit(base({message})); expect(outbound.length===1 && response.body.success, 'B2B false positive');
  }
  await blockedCase({name:'A'}, 'invalid-name');
  for (const values of [
    {form_type:'contact', message:'Container component inquiry'},
    {form_type:'homepage', product:'Roof panel', message:'Please quote 500 panels'},
    {form_type:'rfq', parts:'Roof panel', quantity:'500'}
  ]) { outbound=[]; response=await submit(base(values)); expect(outbound.length===1 && response.body.success, 'Supported form type rejected'); }
} finally { Date.now=savedNow; console.warn=savedWarn; }
console.log('ANTI_SPAM_QA_OK: timestamp boundaries, dual honeypots, Siteverify failures/hostnames, explicit phrases, B2B false positives, all form types and privacy-safe logs');
