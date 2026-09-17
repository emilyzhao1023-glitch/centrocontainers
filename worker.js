const RESEND_API_URL = "https://api.resend.com/emails";
const MIN_SUBMISSION_AGE_MS = 3000;
const MAX_URL_COUNT = 3;
const MAX_FIELD_LENGTH = 2000;
const URL_REGEX = /https?:\/\/|www\./gi;
const JUNK_REPEAT_REGEX = /(.)\1{9,}/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HTML_LINK_REGEX = /<\s*a\b[^>]*\bhref\s*=|\bhref\s*=\s*["']/i;
const PROMOTIONAL_SPAM_REGEX = /\b(?:promo(?:tional)?\s*code|golden\s*ticket|jackpot|lottery|giveaway|claim\s+(?:your|the)\s+(?:prize|reward|bonus)|cash\s+(?:prize|reward|bonus)|coupon\s*code|free\s+(?:gift|money|bonus)|winner\s+(?:announcement|offer)|win\s+(?:up\s+to|\$|€|£))\b/i;
const PHONE_LIKE_QUANTITY_REGEX = /^\d{8,}$/;

const FORM_CONFIG = {
  contact: { subject: "New Contact Message - Centro Containers", heading: "New Contact Message" },
  homepage: { subject: "New Homepage Product Inquiry - Centro Containers", heading: "Homepage Product Inquiry" },
  rfq: { subject: "New Request for Quotation - Centro Containers", heading: "Request for Quotation" },
  manufacturing: { subject: "New Manufacturing RFQ - Centro Containers", heading: "Manufacturing RFQ" }
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Cache-Control": "no-store" } });
}
function trimField(value, max = MAX_FIELD_LENGTH) { return typeof value === "string" ? value.trim().slice(0, max) : ""; }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[character]); }
function countUrls(text) { return (text.match(URL_REGEX) || []).length; }

function extractClientMetadata(request, fields) {
  return {
    ipAddress: request.headers.get("CF-Connecting-IP") || "",
    countryCode: request.cf?.country || "",
    userAgent: request.headers.get("User-Agent") || "",
    requestReferrer: request.headers.get("Referer") || "",
    landingPage: fields.landingPage,
    submittedReferrer: fields.referrer,
    submissionTime: new Date().toISOString()
  };
}

function fieldRows(fields, definitions) {
  return definitions.filter(([key]) => Array.isArray(fields[key]) ? fields[key].length : fields[key]).map(([key, label]) => {
    const rawValue = Array.isArray(fields[key]) ? fields[key].join(", ") : fields[key];
    const safe = escapeHtml(rawValue).replace(/\n/g, "<br>");
    const value = key === "email" ? `<a href="mailto:${escapeHtml(rawValue)}" style="color:#123f73">${safe}</a>` : safe;
    return `<tr><td style="padding:7px 12px 7px 0;color:#64748b;vertical-align:top;white-space:nowrap">${label}</td><td style="padding:7px 0;color:#1f2937;overflow-wrap:anywhere">${value}</td></tr>`;
  }).join("");
}
function section(title, rows) { return rows ? `<section style="margin-top:18px"><h2 style="font-size:15px;color:#123f73;margin:0 0 6px">${title}</h2><table style="width:100%;border-collapse:collapse;font-size:14px">${rows}</table></section>` : ""; }
function emailShell(heading, content, metadata) {
  const technicalRows = fieldRows(metadata, [["landingPage", "Landing page"], ["submittedReferrer", "Stored referrer"], ["requestReferrer", "Request referrer"], ["countryCode", "Cloudflare country"], ["ipAddress", "IP address"], ["userAgent", "User agent"], ["submissionTime", "Submission time"]]);
  return `<!doctype html><html><body style="margin:0;background:#f5f7fb;font-family:Arial,sans-serif;color:#1f2937"><div style="max-width:720px;margin:20px auto;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:24px"><div style="color:#0b1f3a;font-size:16px;font-weight:800;letter-spacing:.05em">CENTRO CONTAINERS</div><h1 style="font-size:22px;margin:5px 0 16px;color:#123f73">${heading}</h1>${content}${section("Technical Details", technicalRows)}</div></body></html>`;
}

function buildContactEmail(fields, metadata) {
  const sender = fieldRows(fields, [["name", "Name"], ["email", "Email"], ["company", "Company"], ["phone", "WhatsApp / Phone"], ["country", "Country / Region"]]);
  return emailShell(FORM_CONFIG.contact.heading, `${section("Contact Details", sender)}${section("Message", fieldRows(fields, [["message", "Message"]]))}`, metadata);
}
function buildHomepageEmail(fields, metadata) {
  const inquiry = fieldRows(fields, [["product", "Product Interested In"], ["quantity", "Estimated Quantity"], ["message", "Message / Specifications"]]);
  const contact = fieldRows(fields, [["name", "Name"], ["email", "Email"], ["company", "Company"], ["country", "Country / Region"], ["phone", "WhatsApp / Phone"]]);
  return emailShell(FORM_CONFIG.homepage.heading, `${section("Product Inquiry", inquiry)}${section("Customer Details", contact)}${section("Attribution", attributionRows(fields))}`, metadata);
}
function buildRfqEmail(fields, metadata) {
  const requirements = fieldRows(fields, [["parts", "Required Products"], ["quantity", "Estimated Quantity"], ["containerType", "Container Type"], ["destination", "Destination"], ["tradeTerm", "Trade Term"], ["message", "Specifications"]]);
  const buyer = fieldRows(fields, [["name", "Contact Name"], ["email", "Business Email"], ["company", "Company"], ["phone", "WhatsApp / Phone"], ["country", "Country / Region"], ["buyerType", "Buyer Type"]]);
  return emailShell(FORM_CONFIG.rfq.heading, `${section("Quotation Requirements", requirements)}${section("Buyer Information", buyer)}${section("Attribution", attributionRows(fields))}`, metadata);
}
function attributionRows(fields) {
  return fieldRows(fields, [["utmSource", "UTM source"], ["utmMedium", "UTM medium"], ["utmCampaign", "UTM campaign"], ["utmTerm", "Matched Keyword"], ["utmContent", "UTM content"], ["gclid", "GCLID"], ["gbraid", "GBRAID"], ["wbraid", "WBRAID"]]);
}
function buildManufacturingEmail(fields, metadata) {
  const project = fieldRows(fields, [["projectDescription", "Component / Project"], ["drawingAvailable", "Drawing / Sample Status"], ["drawingType", "Drawing / File Type"], ["material", "Material / Specification"], ["batchQuantity", "Quantity per Batch"], ["annualVolume", "Estimated Annual Volume"], ["partNumbers", "Number of Part Numbers"], ["destination", "Delivery Destination"], ["timing", "Required Timing"], ["targetCost", "Current / Target Unit Cost"], ["message", "Additional Requirements"]]);
  const buyer = fieldRows(fields, [["name", "Contact Name"], ["email", "Business Email"], ["company", "Company"], ["country", "Country / Region"], ["phone", "WhatsApp / Phone"]]);
  return emailShell(FORM_CONFIG.manufacturing.heading, `${section("Manufacturing Project", project)}${section("Buyer Information", buyer)}${section("Attribution", attributionRows(fields))}`, metadata);
}
function buildEmailHtml(formType, fields, metadata) {
  if (formType === "contact") return buildContactEmail(fields, metadata);
  if (formType === "homepage") return buildHomepageEmail(fields, metadata);
  if (formType === "manufacturing") return buildManufacturingEmail(fields, metadata);
  return buildRfqEmail(fields, metadata);
}
function requiredFieldsFor(formType) {
  if (formType === "contact") return ["name", "email", "message"];
  if (formType === "homepage") return ["name", "email", "product", "message"];
  if (formType === "manufacturing") return ["name", "email", "company", "country", "projectDescription", "drawingAvailable", "batchQuantity", "destination"];
  return ["name", "email", "country", "parts", "quantity"];
}
function validateSubmission(formType, fields, honeypotValue, formStartTime, now) {
  if (honeypotValue) return { error: "Spam detected", reason: "honeypot", isSpam: true };
  const parsedStart = Number(formStartTime);
  if (!Number.isFinite(parsedStart) || now - parsedStart < MIN_SUBMISSION_AGE_MS) return { error: "Submission rejected" };
  const missing = requiredFieldsFor(formType).filter(field => field === "parts" ? !fields.parts.length : !fields[field]);
  if (missing.length) return { error: "Missing required fields", missing_fields: missing };
  if (fields.name.length < 2 || fields.name.length > 120) return { error: "Please provide a valid name" };
  if (!EMAIL_REGEX.test(fields.email)) return { error: "Please provide a valid email" };
  if (fields.message && fields.message.length > 8000) return { error: "Message is too long" };
  const combined = Object.values(fields).flat().filter(Boolean).join(" ");
  const urlCount = countUrls(combined);
  if (HTML_LINK_REGEX.test(combined)) return { error: "Spam detected", reason: "html-link", isSpam: true };
  if (urlCount && PROMOTIONAL_SPAM_REGEX.test(combined)) return { error: "Spam detected", reason: "promotional-link", isSpam: true };
  if (urlCount && PHONE_LIKE_QUANTITY_REGEX.test((fields.quantity || fields.batchQuantity || "").replace(/[\s,.-]/g, ""))) return { error: "Spam detected", reason: "invalid-quantity-with-link", isSpam: true };
  if (urlCount > MAX_URL_COUNT) return { error: "Too many URLs in submission" };
  if (JUNK_REPEAT_REGEX.test(combined)) return { error: "Suspicious content detected" };
  return null;
}
async function sendInquiryEmail(env, formType, fields, metadata, config) {
  const response = await fetch(RESEND_API_URL, { method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ from: env.RESEND_FROM_EMAIL, to: [env.RESEND_TO_EMAIL], subject: config.subject, html: buildEmailHtml(formType, fields, metadata), reply_to: fields.email }) });
  if (!response.ok) throw new Error(`Resend error (${response.status}): ${await response.text()}`);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Cache-Control": "no-store" } });
    if (request.method !== "POST") return jsonResponse({ success: false, error: "Method not allowed" }, 405);
    try {
      const data = await request.formData();
      const formType = trimField(data.get("form_type"), 40);
      const config = FORM_CONFIG[formType];
      if (!config) return jsonResponse({ success: false, error: "Invalid form type" }, 400);
      const fields = {
        name: trimField(data.get("name"), 120), email: trimField(data.get("email"), 254), company: trimField(data.get("company"), 200), phone: trimField(data.get("phone"), 100), country: trimField(data.get("country"), 120),
        buyerType: trimField(data.get("buyer_type"), 120), containerType: trimField(data.get("container_type"), 120), parts: data.getAll("parts").map(value => trimField(value, 160)).filter(Boolean).slice(0, 30), product: trimField(data.get("product"), 200), quantity: trimField(data.get("quantity"), 200),
        projectDescription: trimField(data.get("project_description"), 4000), drawingAvailable: trimField(data.get("drawing_available"), 120), drawingType: trimField(data.get("drawing_type"), 120), material: trimField(data.get("material"), 1000), batchQuantity: trimField(data.get("batch_quantity"), 200), annualVolume: trimField(data.get("annual_volume"), 200), partNumbers: trimField(data.get("part_numbers"), 120),
        destination: trimField(data.get("destination"), 300), tradeTerm: trimField(data.get("trade_term"), 80), timing: trimField(data.get("timing"), 300), targetCost: trimField(data.get("target_cost"), 300), message: trimField(data.get("message"), 8000),
        utmSource: trimField(data.get("utm_source"), 500), utmMedium: trimField(data.get("utm_medium"), 500), utmCampaign: trimField(data.get("utm_campaign"), 500), utmTerm: trimField(data.get("utm_term"), 500), utmContent: trimField(data.get("utm_content"), 500), gclid: trimField(data.get("gclid"), 500), gbraid: trimField(data.get("gbraid"), 500), wbraid: trimField(data.get("wbraid"), 500), landingPage: trimField(data.get("landing_page"), 1000), referrer: trimField(data.get("referrer"), 1000)
      };
      const validationError = validateSubmission(formType, fields, trimField(data.get("website"), 500), trimField(data.get("form_start_time"), 40), Date.now());
      if (validationError) {
        if (validationError.isSpam) { console.warn("Blocked inquiry", { reason: validationError.reason, ip: request.headers.get("CF-Connecting-IP") || "" }); return jsonResponse({ success: true }); }
        return jsonResponse({ success: false, ...validationError }, 400);
      }
      await sendInquiryEmail(env, formType, fields, extractClientMetadata(request, fields), config);
      return jsonResponse({ success: true });
    } catch (error) {
      console.error("Inquiry submission failed", { message: error instanceof Error ? error.message : "Unknown error" });
      return jsonResponse({ success: false, error: "Failed to submit inquiry" }, 500);
    }
  }
};
