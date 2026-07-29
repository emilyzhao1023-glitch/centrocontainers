(function () {
  "use strict";
  var endpoint = "https://centro-email.emilyzhao1023.workers.dev";
  var conversionId = "AW-18230780035/s1tvCNvnwb0cEIPBjvVD";
  var lastFocus = null;
  var activeModal = null;

  function modalMarkup() {
    return '<div class="cc-modal" id="rfqModal" hidden role="dialog" aria-modal="true" aria-labelledby="rfqTitle"><div class="cc-modal__panel" tabindex="-1"><button class="cc-modal__close" type="button" aria-label="Close quote form">&times;</button><h2 id="rfqTitle">Request a Quote</h2><p class="cc-modal__intro">Tell us what you need and our team will respond within 24 hours.</p>' +
      '<form id="rfqForm" action="' + endpoint + '" method="post" data-form-type="rfq"><input name="website" tabindex="-1" autocomplete="off" aria-hidden="true" style="position:absolute;left:-9999px"/><input type="hidden" name="form_start_time"><input type="hidden" name="form_type" value="rfq"><div class="cc-form-grid">' +
      field('Name','name','text',true,'name') + field('Email','email','email',true,'email') + field('Company','company','text',false,'organization') + field('WhatsApp / Phone','phone','tel',false,'tel') + field('Country / Region','country','text',true,'country-name') +
      select('Buyer Type','buyer_type',['Container repair depot','Regional distributor / wholesaler','Container factory / OEM project','Logistics / shipping company','Trading company'],false) + select('Container Type','container_type',['20ft GP','40ft GP','40ft HC','Spare parts only','Custom / not sure'],false) +
      '<fieldset class="cc-full" style="border:0;padding:0;margin:0"><legend style="color:#0b1f3a;font-size:14px;font-weight:700;margin-bottom:6px">Required Products *</legend><div class="cc-products">' + ['Dry shipping containers','Corner castings','Roof panels','Side panels','Door panels','Door locking gear','Door gaskets','Corner posts','Cross members and rails','Bridge fittings','OEM parts based on drawings'].map(function(p){return '<label><input type="checkbox" name="parts" value="'+p+'">'+p+'</label>';}).join('') + '</div></fieldset>' +
      field('Estimated Quantity','quantity','text',true) + field('Destination Port / Delivery Address','destination','text',false) + select('Required Trade Term','trade_term',['EXW','FOB','CFR','CIF','DDP','Not Sure'],false) + '<div class="cc-full"><label>Message / Specifications<textarea name="message"></textarea></label></div><div class="cc-full"><button class="cc-submit" type="submit">Request a Quote</button><div class="cc-form-error" role="alert" aria-live="polite"></div></div></div></form></div></div>' +
      '<div class="cc-modal" id="successModal" hidden role="dialog" aria-modal="true" aria-labelledby="successTitle"><div class="cc-modal__panel cc-modal__panel--success" tabindex="-1"><button class="cc-modal__close" type="button" aria-label="Close success message">&times;</button><h2 id="successTitle">Thank you!</h2><p>Your inquiry has been submitted successfully. We will contact you within 24 hours.</p><button class="cc-success-close" type="button">Close</button></div></div>';
  }
  function field(label,name,type,required,autocomplete){ return '<div><label>'+label+(required?' *':'')+'<input type="'+type+'" name="'+name+'"'+(autocomplete?' autocomplete="'+autocomplete+'"':'')+(required?' required':'')+'></label></div>'; }
  function select(label,name,options,required){ return '<div><label>'+label+(required?' *':'')+'<select name="'+name+'"'+(required?' required':'')+'><option value="">Select one</option>'+options.map(function(o){return '<option>'+o+'</option>';}).join('')+'</select></label></div>'; }
  function openModal(modal, trigger) { lastFocus=trigger||document.activeElement; activeModal=modal; modal.hidden=false; document.body.classList.add('cc-modal-open'); modal.querySelector('.cc-modal__panel').focus(); }
  function closeModal(modal, restore) { modal.hidden=true; activeModal=null; if(!document.querySelector('.cc-modal:not([hidden])')) document.body.classList.remove('cc-modal-open'); if(restore!==false && lastFocus && document.contains(lastFocus)) lastFocus.focus(); }
  function showSuccess() { if(activeModal) closeModal(activeModal,false); openModal(document.getElementById('successModal'),lastFocus); }
  function startTimer(form){ var timer=form.querySelector('[name="form_start_time"]'); if(timer) timer.value=String(Date.now()); }
  function setupForm(form) {
    if(!form || form.dataset.ccReady) return; form.dataset.ccReady='true'; startTimer(form); var sending=false;
    form.addEventListener('submit',async function(e){ e.preventDefault(); var error=form.querySelector('.cc-form-error, .form-status'); if(error){error.textContent='';error.classList.remove('success');}
      if(form.dataset.formType==='rfq' && !form.querySelector('[name="parts"]:checked')) { error.textContent='Please select at least one required product.'; return; }
      if(!form.checkValidity()){form.reportValidity();return;} if(sending)return; sending=true; var button=form.querySelector('[type="submit"]'), old=button.textContent; button.disabled=true; button.textContent='Sending...';
      try { var response=await fetch(form.action||endpoint,{method:'POST',body:new FormData(form)}); var result=await response.json().catch(function(){return null;}); if(!response.ok||!result||result.success!==true) throw new Error('failed'); form.reset(); startTimer(form); if(typeof window.gtag==='function') window.gtag('event','conversion',{send_to:conversionId}); showSuccess(); }
      catch(err){ if(error) error.textContent='Sorry, your inquiry could not be sent. Please try again or contact us by WhatsApp.'; }
      finally { sending=false;button.disabled=false;button.textContent=old; }
    });
  }
  document.addEventListener('DOMContentLoaded',function(){ document.body.insertAdjacentHTML('beforeend',modalMarkup()); var rfq=document.getElementById('rfqModal');
    Array.prototype.forEach.call(document.querySelectorAll('a,button'),function(el){ if(/^get (a )?quote$/i.test(el.textContent.trim())) el.addEventListener('click',function(e){e.preventDefault();openModal(rfq,el);}); });
    setupForm(document.getElementById('rfqForm')); setupForm(document.getElementById('quoteForm')); setupForm(document.getElementById('contactForm'));
    document.querySelectorAll('.cc-modal').forEach(function(modal){ modal.addEventListener('mousedown',function(e){if(e.target===modal)closeModal(modal);}); modal.querySelectorAll('.cc-modal__close,.cc-success-close').forEach(function(b){b.addEventListener('click',function(){closeModal(modal);});}); });
    document.addEventListener('keydown',function(e){ if(!activeModal)return; if(e.key==='Escape')closeModal(activeModal); if(e.key==='Tab'){var items=activeModal.querySelectorAll('button:not([disabled]),input:not([disabled]):not([tabindex="-1"]),select,textarea,a[href]');if(!items.length)return;var first=items[0],last=items[items.length-1];if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}} });
  });
})();
