(function(){
  'use strict';
  var endpoint='https://centrocontainers.com/api/inquiry';
  var conversionId='AW-18230780035/s1tvCNvnwb0cEIPBjvVD';
  var verificationError='Security verification could not be completed. Please refresh the page and try again.';
  var turnstileForms=[];
  function renderVerification(form){
    if(!window.turnstile||form.ccWidget!==undefined||form.closest('[hidden]'))return;
    form.ccWidget=window.turnstile.render(form.ccVerification,{
      sitekey:'0x4AAAAAAFS7VfPgJkyl6Egh',
      callback:function(token){form.ccToken=token},
      'expired-callback':function(){form.ccToken=''},
      'error-callback':function(){form.ccToken='';var error=form.querySelector('.cc-form-error,.form-status');if(error)error.textContent=verificationError}
    });
  }
  function resetVerification(form){form.ccToken='';if(window.turnstile&&form.ccWidget!==undefined)window.turnstile.reset(form.ccWidget)}
  window.centroTurnstileReady=function(){turnstileForms.forEach(renderVerification)};
  var lastFocus=null;
  var activeModal=null;

  function field(label,name,type,required,autocomplete,placeholder){return '<div><label>'+label+(required?' *':'')+'<input type="'+type+'" name="'+name+'"'+(autocomplete?' autocomplete="'+autocomplete+'"':'')+(placeholder?' placeholder="'+placeholder+'"':'')+(required?' required':'')+'></label></div>'}
  function select(label,name,options,required){return '<div><label>'+label+(required?' *':'')+'<select name="'+name+'"'+(required?' required':'')+'><option value="">Select one</option>'+options.map(function(option){return '<option value="'+option+'">'+option+'</option>'}).join('')+'</select></label></div>'}
  function modalMarkup(){
    return '<div class="cc-modal" id="rfqModal" hidden role="dialog" aria-modal="true" aria-labelledby="rfqTitle"><div class="cc-modal__panel" tabindex="-1"><button class="cc-modal__close" type="button" aria-label="Close manufacturing RFQ">&times;</button><h2 id="rfqTitle">Manufacturing RFQ</h2><p class="cc-modal__intro">Share the technical and volume basics. Sensitive drawings can be arranged after the first review.</p><form id="rfqForm" action="'+endpoint+'" method="post" data-form-type="manufacturing"><input type="text" name="contact_check" tabindex="-1" autocomplete="off" aria-hidden="true" class="cc-honeypot"><input type="hidden" name="form_start_time"><input type="hidden" name="form_type" value="manufacturing"><div class="cc-form-grid">'+
      field('Name','name','text',true,'name')+field('Business Email','email','email',true,'email')+field('Company','company','text',true,'organization')+field('Country / Region','country','text',true,'country-name')+field('WhatsApp / Phone','phone','tel',false,'tel')+
      select('Drawing or Sample','drawing_available',['Drawing available','STEP or 3D file available','Physical sample available','Not yet available'],true)+
      '<div class="cc-full"><label>Component / Project Description *<textarea name="project_description" required placeholder="Part, application and what needs to be manufactured"></textarea></label></div>'+
      field('Quantity per Batch','batch_quantity','text',true,'','e.g. 500 pcs per order')+field('Estimated Annual Volume (optional)','annual_volume','text',false,'','Approximate annual requirement if known')+field('Material / Specification','material','text',false,'','Steel grade, thickness, finish')+field('Delivery Destination','destination','text',true,'','City, country or port')+
      '<div class="cc-full"><label>Additional Requirements<textarea name="message" placeholder="Timing, critical dimensions, inspection or packing notes"></textarea></label></div><div class="cc-full"><button class="cc-submit" type="submit">Submit Manufacturing RFQ</button><div class="cc-form-error" role="alert" aria-live="polite"></div></div></div></form></div></div>'+
      '<div class="cc-modal" id="successModal" hidden role="dialog" aria-modal="true" aria-labelledby="successTitle"><div class="cc-modal__panel cc-modal__panel--success" tabindex="-1"><button class="cc-modal__close" type="button" aria-label="Close success message">&times;</button><h2 id="successTitle">RFQ received</h2><p>Your project details were submitted successfully. The team will review the information and reply by email.</p><button class="cc-success-close" type="button">Close</button></div></div>'
  }
  function openModal(modal,trigger){lastFocus=trigger||document.activeElement;activeModal=modal;modal.hidden=false;var form=modal.querySelector("form");if(form)renderVerification(form);document.body.classList.add('cc-modal-open');var description=modal.querySelector('[name="project_description"]');var heading=document.querySelector('h1');if(description&&!description.value&&heading)description.value=heading.textContent.trim();if(window.CentroAttribution)window.CentroAttribution.attach(modal.querySelector('form'));modal.querySelector('.cc-modal__panel').focus()}
  function closeModal(modal,restore){modal.hidden=true;activeModal=null;if(!document.querySelector('.cc-modal:not([hidden])'))document.body.classList.remove('cc-modal-open');if(restore!==false&&lastFocus&&document.contains(lastFocus))lastFocus.focus()}
  function showSuccess(){if(activeModal)closeModal(activeModal,false);openModal(document.getElementById('successModal'),lastFocus)}
  function startTimer(form){var input=form.querySelector('[name="form_start_time"]');if(input)input.value=String(Date.now())}
  function wait(ms){return new Promise(function(resolve){window.setTimeout(resolve,ms)})}
  function emit(name,detail){if(window.CentroAttribution)window.CentroAttribution.emit(name,detail);else if(Array.isArray(window.dataLayer))window.dataLayer.push({event:name,event_detail:detail||{}})}
  function setupForm(form){
    if(!form||form.dataset.ccReady)return;
    form.dataset.ccReady='true';
    form.ccToken='';form.ccVerification=document.createElement('div');form.ccVerification.className='cc-turnstile';
    var submit=form.querySelector('[type="submit"]');submit.parentNode.insertBefore(form.ccVerification,submit);
    turnstileForms.push(form);renderVerification(form);startTimer(form);if(window.CentroAttribution)window.CentroAttribution.attach(form);var sending=false;
    form.addEventListener('submit',async function(event){
      event.preventDefault();var error=form.querySelector('.cc-form-error,.form-status');if(error){error.textContent='';error.classList.remove('success')}
      var partChoices=form.querySelectorAll('input[name="parts"][type="checkbox"],input[name="parts"][type="radio"]');
      if(form.dataset.formType==='rfq'&&partChoices.length>0&&!form.querySelector('input[name="parts"][type="checkbox"]:checked,input[name="parts"][type="radio"]:checked')){if(error)error.textContent='Please select at least one required product.';return}
      if(!form.checkValidity()){form.reportValidity();return}if(sending)return;
      if(!form.ccToken){if(error)error.textContent=verificationError;return}
      sending=true;var button=form.querySelector('[type="submit"]');var old=button.textContent;button.disabled=true;button.textContent='Sending…';
      try{
        var timer=form.querySelector('[name="form_start_time"]');var remaining=4100-(Date.now()-Number(timer&&timer.value||0));if(remaining>0)await wait(remaining);
        emit('rfq_submit',{form_type:form.dataset.formType||''});
        if(!form.ccToken)throw new Error(verificationError);
        var data=new FormData(form);data.set('cf-turnstile-response',form.ccToken);
        var response=await fetch(form.action||endpoint,{method:'POST',body:data});var result=await response.json().catch(function(){return null});
        if(!response.ok||!result||result.success!==true)throw new Error(result&&result.code==='verification-failed'?verificationError:'submission failed');
        emit('rfq_success',{form_type:form.dataset.formType||''});if(typeof window.gtag==='function')window.gtag('event','conversion',{send_to:conversionId});form.reset();startTimer(form);showSuccess();
      }catch(failure){if(error)error.textContent=failure.message===verificationError?verificationError:'Sorry, the RFQ could not be sent. Please try again or email sales@centrocontainers.com.'}
      finally{resetVerification(form);sending=false;button.disabled=false;button.textContent=old}
    })
  }
  document.addEventListener('DOMContentLoaded',function(){
    document.body.insertAdjacentHTML('beforeend',modalMarkup());var modal=document.getElementById('rfqModal');
    Array.prototype.forEach.call(document.querySelectorAll('a,button'),function(element){if(/^get (a )?quote$/i.test(element.textContent.trim()))element.addEventListener('click',function(event){event.preventDefault();openModal(modal,element)})});
    document.querySelectorAll('form[data-form-type]').forEach(setupForm);
    if(!window.turnstile){var script=document.createElement('script');script.src='https://challenges.cloudflare.com/turnstile/v0/api.js?onload=centroTurnstileReady&render=explicit';script.async=true;script.defer=true;script.onerror=function(){turnstileForms.forEach(function(form){var error=form.querySelector('.cc-form-error,.form-status');if(error)error.textContent=verificationError})};document.head.appendChild(script)}
    document.querySelectorAll('.cc-modal').forEach(function(item){item.addEventListener('mousedown',function(event){if(event.target===item)closeModal(item)});item.querySelectorAll('.cc-modal__close,.cc-success-close').forEach(function(button){button.addEventListener('click',function(){closeModal(item)})})});
    document.addEventListener('keydown',function(event){if(!activeModal)return;if(event.key==='Escape')closeModal(activeModal);if(event.key==='Tab'){var items=activeModal.querySelectorAll('button:not([disabled]),input:not([disabled]):not([tabindex="-1"]),select,textarea,a[href]');if(!items.length)return;var first=items[0],last=items[items.length-1];if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus()}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus()}}})
  })
})();
