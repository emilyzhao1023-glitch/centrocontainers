const RESEND_API_URL = "https://api.resend.com/emails";
const MIN_SUBMISSION_AGE_MS = 3000;
const MAX_URL_COUNT = 3;
const URL_REGEX = /https?:\/\/|www\./gi;
const JUNK_REPEAT_REGEX = /(.)\1{9,}/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

function trimField(value) {
  return typeof value === "string" ? value.trim() : "";
}

function countUrls(text) {
  return (text.match(URL_REGEX) || []).length;
}

function hasSuspiciousContent(text) {
  return JUNK_REPEAT_REGEX.test(text);
}

function extractClientMetadata(request) {
  return {
    ipAddress: request.headers.get("CF-Connecting-IP") || "Unknown",
    country: request.headers.get("CF-IPCountry") || "Unknown",
    userAgent: request.headers.get("User-Agent") || "Unknown",
    referer: request.headers.get("Referer") || "Unknown",
    submissionTime: new Date().toISOString()
  };
}

function buildEmailText(fields, metadata) {
  return `New inquiry received:

Name: ${fields.name}
Company: ${fields.company || "N/A"}
Email: ${fields.email}
Country: ${fields.country || "N/A"}
Product: ${fields.product || "N/A"}
Message:
${fields.message}

---
Sender Metadata
IP Address: ${metadata.ipAddress}
Country: ${metadata.country}
User-Agent: ${metadata.userAgent}
Referer: ${metadata.referer}
Submission Time: ${metadata.submissionTime}
---`;
}

async function sendInquiryEmail(env, fields, metadata) {
  const payload = {
    from: env.RESEND_FROM_EMAIL,
    to: [env.RESEND_TO_EMAIL],
    subject: `New Inquiry from ${fields.name}`,
    text: buildEmailText(fields, metadata),
    reply_to: fields.email
  };

  const resendResponse = await fetch(RESEND_API_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!resendResponse.ok) {
    const resendError = await resendResponse.text();
    throw new Error(`Resend error (${resendResponse.status}): ${resendError}`);
  }
}

function validateSubmission(fields, honeypotValue, formStartTime, now) {
  if (honeypotValue) {
    return "Spam detected";
  }

  const parsedStart = Number(formStartTime);
  if (!Number.isFinite(parsedStart) || now - parsedStart < MIN_SUBMISSION_AGE_MS) {
    return "Submission rejected";
  }

  if (!fields.name || fields.name.length < 2 || fields.name.length > 120) {
    return "Please provide a valid name";
  }

  if (!fields.email || !EMAIL_REGEX.test(fields.email)) {
    return "Please provide a valid email";
  }

  if (!fields.message) {
    return "Message is required";
  }

  if (fields.message.length > 8000) {
    return "Message is too long";
  }

  const combinedContent = [
    fields.name,
    fields.company,
    fields.email,
    fields.country,
    fields.product,
    fields.message
  ].join(" ");

  if (countUrls(combinedContent) > MAX_URL_COUNT) {
    return "Too many URLs in submission";
  }

  if (hasSuspiciousContent(combinedContent)) {
    return "Suspicious content detected";
  }

  return null;
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }

    if (request.method !== "POST") {
      return jsonResponse({ success: false, error: "Method not allowed" }, 405);
    }

    try {
      const formData = await request.formData();
      const fields = {
        name: trimField(formData.get("name")),
        company: trimField(formData.get("company")),
        email: trimField(formData.get("email")),
        country: trimField(formData.get("country")),
        product: trimField(formData.get("product")),
        message: trimField(formData.get("message"))
      };

      const honeypotValue = trimField(formData.get("website"));
      const formStartTime = trimField(formData.get("form_start_time"));
      const validationError = validateSubmission(fields, honeypotValue, formStartTime, Date.now());

      if (validationError) {
        return jsonResponse({ success: false, error: validationError }, 400);
      }

      const metadata = extractClientMetadata(request);
      await sendInquiryEmail(env, fields, metadata);

      return jsonResponse({ success: true });
    } catch (error) {
      return jsonResponse({ success: false, error: "Failed to submit inquiry" }, 500);
    }
  }
};
