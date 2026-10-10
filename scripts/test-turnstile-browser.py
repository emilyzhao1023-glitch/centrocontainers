from playwright.sync_api import sync_playwright
from pathlib import Path
import re
# Optional browser regression: Python Playwright and Chromium are required.
# All external requests are mocked or blocked; no real inquiries are sent.
ROOT=Path(__file__).resolve().parents[1] / 'public'
MOCK='''window.turnstile={render:function(el,options){el.textContent='Verification test widget';window.testWidgets=window.testWidgets||[];window.testWidgets.push(options);options.callback('browser-test-token');return window.testWidgets.length-1;},reset:function(id){window.testReset=(window.testReset||0)+1;window.testWidgets[id].callback('browser-test-token');}};window.centroTurnstileReady();'''
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
class Handler(SimpleHTTPRequestHandler):
 def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(ROOT),**kwargs)
 def log_message(self,*args):pass
 def do_GET(self):
  route=self.path.split('?')[0]
  candidate=Path(self.translate_path(route))
  if not candidate.exists() and candidate.with_suffix('.html').is_file():self.path=route+'.html'
  super().do_GET()
server=ThreadingHTTPServer(('127.0.0.1',8001),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
 page=browser.new_page()
 responses={'success':False}
 def route(req):
  url=req.request.url
  if url.startswith('http://127.0.0.1:8001'):req.continue_()
  elif url.startswith('https://challenges.cloudflare.com/turnstile/v0/api.js'):req.fulfill(status=200,content_type='application/javascript',body=MOCK)
  elif url=='https://centrocontainers.com/api/inquiry':req.fulfill(status=200 if responses['success'] else 400,content_type='application/json',headers={'Access-Control-Allow-Origin':'*'},body='{"success":true}' if responses['success'] else '{"success":false,"code":"verification-failed"}')
  else:req.abort()
 page.route('**/*',route)
 errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 count=0
 for path in sorted(ROOT.rglob('*.html')):
  relative=path.relative_to(ROOT).as_posix()
  page.goto('http://127.0.0.1:8001/'+relative)
  page.wait_for_function('window.turnstile && document.querySelector("#rfqForm")')
  expected=page.locator('form[data-form-type]').count()
  for form in page.locator('form[data-form-type]').all():
   assert form.locator('.cc-turnstile').count()==1,relative
  trigger=page.get_by_role('link',name=re.compile(r'^Get (a )?Quote$',re.I)).first
  if trigger.count():trigger.click()
  else:
   assert page.evaluate('document.querySelector("#rfqForm").ccWidget === undefined'),relative
   count+=1
   continue
  page.wait_for_function('document.querySelector("#rfqForm").ccWidget !== undefined')
  assert page.locator('#rfqForm .cc-turnstile').inner_text()=='Verification test widget'
  assert page.evaluate('document.querySelector("#rfqForm").ccToken')=='browser-test-token'
  assert page.evaluate('window.testWidgets.length')==expected,relative
  count+=1
 # Real DOM/FormData, server error and retry reset on contact form.
 page.goto('http://127.0.0.1:8001/contact')
 page.wait_for_function('document.querySelector("#manufacturingForm").ccToken')
 form=page.locator('#manufacturingForm')
 for name,value in [('name','B2B Buyer'),('email','buyer@example.com'),('company','Container OEM'),('country','Germany'),('project_description','Container roof panels to drawing'),('batch_quantity','500'),('destination','Hamburg')]:form.locator('[name="'+name+'"]').fill(value)
 form.locator('[name="drawing_available"]').first.check()
 page.evaluate('document.querySelector("#manufacturingForm [name=form_start_time]").value=String(Date.now()-5000)')
 form.get_by_role('button',name='Submit Manufacturing RFQ').click()
 page.wait_for_function('document.querySelector("#manufacturingForm .cc-form-error").textContent.startsWith("Security verification")')
 assert page.evaluate('window.testReset')==1
 responses['success']=True
 form.get_by_role('button',name='Submit Manufacturing RFQ').click()
 page.wait_for_function('document.querySelector("#successModal").hidden === false')
 assert form.locator('[name="name"]').input_value()==''
 assert page.evaluate('window.testReset')==2
 assert page.evaluate('window.dataLayer.filter(e=>e.event==="rfq_success").length')==1
 assert not errors,errors
 print('BROWSER_QA_OK:',count,'pages: actual DOM widget insertion, hidden modal opening, script onload, form token; contact verification error, successful retry/reset and one success tracking event')
 browser.close()
