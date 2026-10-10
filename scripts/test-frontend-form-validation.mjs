import fs from 'node:fs';
import vm from 'node:vm';

const quoteModalSource = fs.readFileSync(new URL('../quote-modal.js', import.meta.url), 'utf8');
const contactSource = fs.readFileSync(new URL('../contact.html', import.meta.url), 'utf8');
const lockingGearSource = fs.readFileSync(new URL('../landing/container-door-locking-gear.html', import.meta.url), 'utf8');
const rollingShutterSource = fs.readFileSync(new URL('../landing/rolling-shutter-door.html', import.meta.url), 'utf8');

function expect(condition, message) { if (!condition) throw new Error(message); }
function formBlock(source) { return source.match(/<form\b[^>]*id="quoteForm"[\s\S]*?<\/form>/i)?.[0] || ''; }
function valueOf(form, name) { return form.match(new RegExp(`name="${name}"\\s+value="([^"]+)"`, 'i'))?.[1]; }

function makeForm({ selected = false, choices = false }) {
  const timer = { value:'' };
  const error = { textContent:'', classList:{ remove() {} } };
  const button = { textContent:'Send', disabled:false, parentNode:{insertBefore(){}} };
  const partChoices = choices ? [{ checked:selected, type:'checkbox', name:'parts' }] : [];
  const form = {
    closest(){return null;}, dataset:{ formType:'rfq' }, action:'https://centrocontainers.com/api/inquiry', listener:null,
    querySelector(selector) {
      if (selector === '[name="form_start_time"]') return timer;
      if (selector === '.cc-form-error,.form-status') return error;
      if (selector === '[type="submit"]') return button;
      if (selector.includes('input[name="parts"]') && selector.includes(':checked')) return partChoices.find(choice => choice.checked) || null;
      return null;
    },
    querySelectorAll(selector) { return selector.includes('input[name="parts"]') ? partChoices : []; },
    addEventListener(type, callback) { if (type === 'submit') this.listener = callback; },
    checkValidity() { return true; }, reportValidity() {}, reset() {}
  };
  return { form, timer, error };
}

async function runFrontendCase(options) {
  const test = makeForm(options);
  let fetchCount = 0; let resetCount=0; let widgetOptions; let submittedToken; const scriptTags=[];
  const document = {
    createElement(){return {};}, head:{appendChild(script){scriptTags.push(script)}},
    body:{ insertAdjacentHTML() {}, classList:{ add() {}, remove() {} } },
    activeElement:null,
    addEventListener(type, callback) { if (type === 'DOMContentLoaded') callback(); },
    querySelectorAll(selector) { if (selector === 'form[data-form-type]') return [test.form]; return []; },
    getElementById() { return { hidden:true, querySelector() { return { focus() {} }; } }; },
    contains() { return false; }, querySelector() { return null; }
  };
  const window = {
    turnstile:{render(element,config){widgetOptions=config;config.callback('frontend-test-token');return 0;},reset(){resetCount++;}},
    setTimeout(callback) { callback(); },
    dispatchEvent() {}, dataLayer:[], CentroAttribution:null, gtag() {}
  };
  class FormDataStub { constructor(form) { this.form = form; } set(name,value){expect(name==='cf-turnstile-response','Token field incorrect');submittedToken=value;} }
  const fetch = async () => { fetchCount += 1; return { ok:false, async json() { return options.serverVerificationFailure ? {success:false,code:'verification-failed'} : { success:false }; } }; };
  vm.runInNewContext(quoteModalSource, { window, document, FormData:FormDataStub, fetch, console, CustomEvent:class {}, Date });
  expect(typeof test.form.listener === 'function', 'frontend submit listener was not installed');
  test.timer.value = String(Date.now() - 5000);
  if(options.missingToken)widgetOptions['expired-callback']();
  if(options.widgetError)widgetOptions['error-callback']();
  await test.form.listener({ preventDefault() {} });
  return { fetchCount, error:test.error.textContent, resetCount, submittedToken, widgetOptions };
}

const hiddenProduct = await runFrontendCase({ choices:false });
expect(hiddenProduct.fetchCount === 1, 'Case A: hidden fixed product was incorrectly blocked');
expect(!hiddenProduct.error.includes('select at least one'), 'Case A: false part-selection error was shown');
expect(quoteModalSource.includes('name="contact_check"') && quoteModalSource.includes('class="cc-honeypot"'), 'Case A: shared modal contact_check honeypot is missing');
expect(contactSource.includes('name="contact_check"') && contactSource.includes('class="cc-honeypot"'), 'Case A: Manufacturing RFQ contact_check honeypot is missing');

const noChoice = await runFrontendCase({ choices:true, selected:false });
expect(noChoice.fetchCount === 0, 'Case B: unselected checkbox/radio RFQ was not blocked');
expect(noChoice.error.includes('select at least one'), 'Case B: missing part-selection error was not shown');

const selectedChoice = await runFrontendCase({ choices:true, selected:true });
expect(selectedChoice.fetchCount === 1, 'Case B: selected checkbox/radio RFQ did not proceed');

const lockingForm = formBlock(lockingGearSource);
expect(lockingForm.includes('data-form-type="rfq"'), 'Case A: Door Locking Gear data-form-type is not rfq');
expect(valueOf(lockingForm, 'form_type') === 'rfq', 'Case A: Door Locking Gear Worker form type is not rfq');
expect(valueOf(lockingForm, 'parts') === 'Door locking gear', 'Case A: Door Locking Gear hidden product is incorrect');
expect(lockingForm.includes('name="contact_check"') && lockingForm.includes('class="cc-honeypot"'), 'Case A: Door Locking Gear contact_check honeypot is missing');

const rollingForm = formBlock(rollingShutterSource);
expect(rollingForm.includes('data-form-type="rfq"'), 'Case C: Rolling Shutter Door data-form-type is not rfq');
expect(!rollingForm.includes('data-form-type="landing-door-locking-gear"'), 'Case C: stale analytics form type remains');
expect(valueOf(rollingForm, 'form_type') === 'rfq', 'Case C: Rolling Shutter Door Worker form type is not rfq');
expect(valueOf(rollingForm, 'parts') === 'Industrial rolling shutter door', 'Case C: Rolling Shutter Door hidden product is incorrect');
expect(rollingForm.includes('name="contact_check"') && rollingForm.includes('class="cc-honeypot"'), 'Case C: Rolling Shutter Door contact_check honeypot is missing');

console.log('FRONTEND_FORM_QA_OK: hidden-product RFQ proceeds; empty choices block; selected choice proceeds; landing form types/products are correct');

const securityMessage='Security verification could not be completed. Please refresh the page and try again.';
for (const options of [{missingToken:true},{widgetError:true}]) {
 const result=await runFrontendCase(options);
 expect(result.fetchCount===0 && result.error===securityMessage, 'Expired/missing/error token did not block submission');
}
const serverFailure=await runFrontendCase({serverVerificationFailure:true});
expect(serverFailure.error===securityMessage && serverFailure.resetCount===1,'Server verification failure not shown or token not reset');
expect(hiddenProduct.submittedToken==='frontend-test-token' && hiddenProduct.resetCount===1,'Token submission/retry reset failed');
expect(hiddenProduct.widgetOptions.sitekey==='0x4AAAAAAFS7VfPgJkyl6Egh','Incorrect site key');
console.log('TURNSTILE_FRONTEND_QA_OK: token submission, expiry/error blocking, retry reset and explicit server verification error');
