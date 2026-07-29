const RESEND_API_URL = "https://api.resend.com/emails";
const MIN_SUBMISSION_AGE_MS = 3000;
const MAX_URL_COUNT = 3;
const URL_REGEX = /https?:\/\/|www\./gi;
const JUNK_REPEAT_REGEX = /(.)\1{9,}/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const FORM_CONFIG = {
  contact: { subject: "New Contact Message - Centro Containers", heading: "New Contact Message" },
  homepage: { subject: "New Homepage Product Inquiry - Centro Containers", heading: "Homepage Product Inquiry" },
  rfq: { subject: "New Request for Quotation - Centro Containers", heading: "Request for Quotation" }
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
}
function trimField(value) { return typeof value === "string" ? value.trim() : ""; }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[character]); }
function countUrls(text) { return (text.match(URL_REGEX) || []).length; }

function extractClientMetadata(request) {
  return {
    ipAddress: request.headers.get("CF-Connecting-IP") || "",
    countryCode: request.cf?.country || "",
    userAgent: request.headers.get("User-Agent") || "",
    referrer: request.headers.get("Referer") || "",
    submissionTime: new Date().toISOString()
  };
}

function fieldRows(fields, definitions) {
  return definitions.filter(([key]) => Array.isArray(fields[key]) ? fields[key].length : fields[key]).map(([key, label]) => {
    const rawValue = Array.isArray(fields[key]) ? fields[key].join(", ") : fields[key];
    const value = key === "email" ? `<a href="mailto:${escapeHtml(rawValue)}" style="color:#123f73">${escapeHtml(rawValue)}</a>` : escapeHtml(rawValue).replace(/\n/g, "<br>");
    return `<tr><td style="padding:7px 12px 7px 0;color:#64748b;vertical-align:top;white-space:nowrap">${label}</td><td style="padding:7px 0;color:#1f2937">${value}</td></tr>`;
  }).join("");
}

function section(title, rows) {
  return rows ? `<section style="margin-top:18px"><h2 style="font-size:15px;color:#123f73;margin:0 0 6px">${title}</h2><table style="width:100%;border-collapse:collapse;font-size:14px">${rows}</table></section>` : "";
}

function emailShell(heading, content, metadata) {
  const technicalRows = fieldRows(metadata, [["ipAddress", "IP address"], ["countryCode", "Detected Country (IP)"], ["userAgent", "User agent"], ["referrer", "Referrer"], ["submissionTime", "Submission time"]]);
  return `<!doctype html><html><body style="margin:0;background:#f5f7fb;font-family:Arial,sans-serif;color:#1f2937"><div style="max-width:680px;margin:20px auto;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:24px"><div style="color:#0b1f3a;font-size:16px;font-weight:800;letter-spacing:.05em">CENTRO CONTAINERS</div><h1 style="font-size:22px;margin:5px 0 16px;color:#123f73">${heading}</h1>${content}${section("Technical Details", technicalRows)}</div></body></html>`;
}

function buildContactEmail(fields, metadata) {
  const sender = fieldRows(fields, [["name", "Name"], ["email", "Email"], ["company", "Company"], ["phone", "WhatsApp / Phone"], ["country", "Country / Region"]]);
  const message = fieldRows(fields, [["message", "Message"]]);
  return emailShell(FORM_CONFIG.contact.heading, `${section("Contact Details", sender)}${section("Message", message)}`, metadata);
}

function buildHomepageEmail(fields, metadata) {
  const inquiry = fieldRows(fields, [["product", "Product Interested In"], ["quantity", "Estimated Quantity"], ["message", "Message / Specifications"]]);
  const contact = fieldRows(fields, [["name", "Name"], ["email", "Email"], ["company", "Company"], ["country", "Country / Region"], ["phone", "WhatsApp / Phone"]]);
  return emailShell(FORM_CONFIG.homepage.heading, `${section("Product Inquiry", inquiry)}${section("Customer Details", contact)}`, metadata);
}

function buildRfqEmail(fields, metadata) {
  const requirements = fieldRows(fields, [["parts", "Required Products"], ["quantity", "Estimated Quantity"], ["containerType", "Container Type"], ["destination", "Destination Port / Delivery Address"], ["tradeTerm", "Required Trade Term"], ["message", "Specifications"]]);
  const buyer = fieldRows(fields, [["name", "Contact Name"], ["email", "Business Email"], ["company", "Company"], ["phone", "WhatsApp / Phone"], ["country", "Country / Region"], ["buyerType", "Buyer Type"]]);
  return emailShell(FORM_CONFIG.rfq.heading, `${section("Quotation Requirements", requirements)}${section("Buyer Information", buyer)}`, metadata);
}

function buildEmailHtml(formType, fields, metadata) {
  if (formType === "contact") return buildContactEmail(fields, metadata);
  if (formType === "homepage") return buildHomepageEmail(fields, metadata);
  return buildRfqEmail(fields, metadata);
}

function requiredFieldsFor(formType) {
  if (formType === "contact") return ["name", "email", "message"];
  if (formType === "homepage") return ["name", "email", "product", "message"];
  return ["name", "email", "country", "parts", "quantity"];
}

function validateSubmission(formType, fields, honeypotValue, formStartTime, now) {
  if (honeypotValue) return { error: "Spam detected" };
  const parsedStart = Number(formStartTime);
  if (!Number.isFinite(parsedStart) || now - parsedStart < MIN_SUBMISSION_AGE_MS) return { error: "Submission rejected" };
  const missing = requiredFieldsFor(formType).filter(field => field === "parts" ? !fields.parts.length : !fields[field]);
  if (missing.length) return { error: "Missing required fields", missing_fields: missing };
  if (fields.name.length < 2 || fields.name.length > 120) return { error: "Please provide a valid name" };
  if (!EMAIL_REGEX.test(fields.email)) return { error: "Please provide a valid email" };
  if (fields.message && fields.message.length > 8000) return { error: "Message is too long" };
  const combined = Object.values(fields).flat().filter(Boolean).join(" ");
  if (countUrls(combined) > MAX_URL_COUNT) return { error: "Too many URLs in submission" };
  if (JUNK_REPEAT_REGEX.test(combined)) return { error: "Suspicious content detected" };
  return null;
}

async function sendInquiryEmail(env, formType, fields, metadata, config) {
  const response = await fetch(RESEND_API_URL, { method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ from: env.RESEND_FROM_EMAIL, to: [env.RESEND_TO_EMAIL], subject: config.subject, html: buildEmailHtml(formType, fields, metadata), reply_to: fields.email }) });
  if (!response.ok) throw new Error(`Resend error (${response.status}): ${await response.text()}`);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" } });
    if (request.method !== "POST") return jsonResponse({ success: false, error: "Method not allowed" }, 405);
    try {
      const data = await request.formData();
      const formType = trimField(data.get("form_type"));
      const config = FORM_CONFIG[formType];
      if (!config) return jsonResponse({ success: false, error: "Invalid form type" }, 400);
      const fields = {
        name: trimField(data.get("name")), email: trimField(data.get("email")), company: trimField(data.get("company")), phone: trimField(data.get("phone")), country: trimField(data.get("country")),
        buyerType: trimField(data.get("buyer_type")), containerType: trimField(data.get("container_type")), parts: data.getAll("parts").map(trimField).filter(Boolean), product: trimField(data.get("product")), quantity: trimField(data.get("quantity")),
        destination: trimField(data.get("destination")), tradeTerm: trimField(data.get("trade_term")), message: trimField(data.get("message"))
      };
      const validationError = validateSubmission(formType, fields, trimField(data.get("website")), trimField(data.get("form_start_time")), Date.now());
      if (validationError) return jsonResponse({ success: false, ...validationError }, 400);
      await sendInquiryEmail(env, formType, fields, extractClientMetadata(request), config);
      return jsonResponse({ success: true });
    } catch (error) { return jsonResponse({ success: false, error: "Failed to submit inquiry" }, 500); }
  }
};
