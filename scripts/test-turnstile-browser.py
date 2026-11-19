from playwright.sync_api import sync_playwright
from pathlib import Path

# Optional browser regression: Python Playwright and Chromium are required.
# External requests are blocked or mocked; no real inquiries are sent.
ROOT=Path(__file__).resolve().parents[1] / 'public'
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
 cloudflare_requests=[]

 def route(req):
  url=req.request.url
  if 'challenges.cloudflare.com' in url:
   cloudflare_requests.append(url)
   req.abort()
  elif url.startswith('http://127.0.0.1:8001'):
   req.continue_()
  elif url=='https://centrocontainers.com/api/inquiry':
   req.fulfill(status=200 if responses['success'] else 400,content_type='application/json',headers={'Access-Control-Allow-Origin':'*'},body='{"success":true}' if responses['success'] else '{"success":false}')
  else:
   req.abort()

 page.route('**/*',route)
 errors=[]
 page.on('pageerror',lambda error:errors.append(str(error)))
 count=0

 for path in sorted(ROOT.rglob('*.html')):
  relative=path.relative_to(ROOT).as_posix()
  page.goto('http://127.0.0.1:8001/'+relative)
  page.wait_for_function('document.querySelector("#rfqForm")')
  assert page.locator('.cc-turnstile').count()==0,relative
  assert page.locator('input[name="cf-turnstile-response"]').count()==0,relative
  assert page.evaluate('typeof window.turnstile === "undefined"'),relative
  count+=1

 # Real DOM/FormData, generic server error and successful retry on contact form.
 page.goto('http://127.0.0.1:8001/contact')
 form=page.locator('#manufacturingForm')
 for name,value in [('name','B2B Buyer'),('email','buyer@example.com'),('company','Container OEM'),('country','Germany'),('project_description','Container roof panels to drawing'),('batch_quantity','500'),('destination','Hamburg')]:
  form.locator('[name="'+name+'"]').fill(value)
 form.locator('[name="drawing_available"]').first.check()
 page.evaluate('document.querySelector("#manufacturingForm [name=form_start_time]").value=String(Date.now()-5000)')
 form.get_by_role('button',name='Submit Manufacturing RFQ').click()
 page.wait_for_function('document.querySelector("#manufacturingForm .cc-form-error").textContent.length > 0')
 responses['success']=True
 form.get_by_role('button',name='Submit Manufacturing RFQ').click()
 page.wait_for_function('document.querySelector("#successModal").hidden === false')
 assert form.locator('[name="name"]').input_value()==''
 assert page.evaluate('window.dataLayer.filter(e=>e.event==="rfq_success").length')==1
 assert not cloudflare_requests,cloudflare_requests
 assert not errors,errors
 print('BROWSER_QA_OK:',count,'pages: no Cloudflare widget, script or token field; form error/retry and success tracking work')
 browser.close()
