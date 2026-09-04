(function(){
  'use strict';
  var keys=['utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','gbraid','wbraid'];
  var storageKey='centro_attribution_v1';
  function readStored(){try{return JSON.parse(sessionStorage.getItem(storageKey)||'{}')}catch(error){return {}}}
  function collect(){
    var values=readStored();
    var params=new URLSearchParams(window.location.search);
    keys.forEach(function(key){var value=params.get(key);if(value)values[key]=value.slice(0,500)});
    if(!values.landing_page)values.landing_page=window.location.pathname;
    if(!values.referrer)values.referrer=document.referrer||'';
    try{sessionStorage.setItem(storageKey,JSON.stringify(values))}catch(error){}
    return values;
  }
  function attach(form,values){
    Object.keys(values).forEach(function(key){
      var input=form.querySelector('input[name="'+key+'"]');
      if(!input){input=document.createElement('input');input.type='hidden';input.name=key;form.appendChild(input)}
      input.value=values[key];
    });
  }
  function emit(name,detail){
    window.dispatchEvent(new CustomEvent(name,{detail:detail||{}}));
    if(Array.isArray(window.dataLayer))window.dataLayer.push({event:name,event_detail:detail||{}});
  }
  document.addEventListener('DOMContentLoaded',function(){
    var values=collect();
    document.querySelectorAll('form[data-form-type]').forEach(function(form){attach(form,values);form.addEventListener('focusin',function once(){emit('rfq_start',{form_type:form.dataset.formType||''});form.removeEventListener('focusin',once)})});
    document.addEventListener('click',function(event){var link=event.target.closest('a');if(!link)return;var href=link.getAttribute('href')||'';if(href.indexOf('mailto:')===0)emit('email_click');if(href.indexOf('wa.me')>-1)emit('whatsapp_click');if(link.matches('[data-cta]'))emit('cta_click',{cta:link.dataset.cta||'',destination:href})});
  });
  window.CentroAttribution={attach:function(form){attach(form,collect())},emit:emit};
})();
