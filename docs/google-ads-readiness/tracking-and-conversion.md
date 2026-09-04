# Tracking and conversion readiness

## Implemented locally

- First-party capture of `utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, `utm_content`, `gclid`, `gbraid`, `wbraid`, landing page and referrer.
- Hidden attribution fields are attached to inquiry forms.
- Worker email includes attribution and Cloudflare request metadata when available.
- Events: `cta_click`, `email_click`, `whatsapp_click`, `rfq_start`, `rfq_submit`, `rfq_success`.
- `rfq_success` is emitted only after the Worker confirms successful delivery.

## Primary conversion recommendation

Use confirmed `rfq_success` as the primary conversion. Keep email, WhatsApp and form-start interactions secondary until lead quality is known. Imported qualified-lead or won-opportunity events should become the optimization signal when CRM data is available.

## Before production

- Verify the destination Google tag and conversion label in the owner's Ads account.
- Test consent behavior for every target market.
- Submit controlled test inquiries and verify Worker delivery, Ads diagnostics and analytics event payloads.
- Never use the thank-you view alone as the conversion trigger.

No production tag, campaign, budget or billing setting has been changed.
