// SE2 Events API worker (v0.8.0)
// - Supports NFC-ready multi-headphone check-ins with Stripe demo pre-auths
// - Generates global HID identifiers via KV (with reserve + release helpers)
// - Sends transactional email receipts with Resend
// - Stores check-ins in KV with signature hashing + webhook logging
// - Admin dashboards for live monitoring, lookup, and event defaults
// - Includes lightweight rate limiting + shared admin key guard (staging only)

const CORS_ORIGIN = "https://app.silentdiscohq.com";
const STRIPE_API_BASE = "https://api.stripe.com/v1";
const RESEND_API_BASE = "https://api.resend.com/emails";
const ADMIN_ACCOUNTS_KEY = "admins:accounts";
const ADMIN_ACTIVITY_PREFIX = "adminlog:";
const SESSION_PREFIX = "session:";
const SESSION_ADMIN_PREFIX = "session:active:";
const AUTH_SESSION_PREFIX = "authsession:";
const HID_COUNTER_KEY = "global:HID_COUNTER";
const HID_RELEASE_POOL_KEY = "headphones:pool";
const EVENTS_LIST_KEY = "events:list";
const NFC_TAG_PREFIX = "nfctag:";
const ACTIVE_STATUSES = new Set(["checked_out", "partially_returned", "partially_lost"]);

const corsHeaders = {
  "Access-Control-Allow-Origin": CORS_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,x-admin-key",
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function unauthorizedResponse() {
  return jsonResponse({ ok: false, error: "Unauthorized" }, 401);
}

function sanitizeAdminAccount(account) {
  if (!account) return null;
  const { passwordHash, usernameLower, apiKey, ...rest } = account;
  return rest;
}

function ensureArray(value) {
  return Array.isArray(value) ? value : [];
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password || "");
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return toHex(hashBuffer);
}

async function verifyPassword(password, hash) {
  if (!hash) return false;
  const computed = await hashPassword(password || "");
  return computed === hash;
}

async function ensureDefaultSuperAdmin(env) {
  if (!env.CHECKINS) return [];
  const now = new Date().toISOString();
  const defaultAccount = {
    id: "adm_super_seed",
    name: "Super Admin",
    email: "",
    role: "super",
    username: "Kbell629",
    usernameLower: "kbell629",
    passwordHash: await hashPassword("3087"),
    createdAt: now,
    updatedAt: now,
  };
  await env.CHECKINS.put(ADMIN_ACCOUNTS_KEY, JSON.stringify([defaultAccount]));
  return [defaultAccount];
}

async function getAdminAccounts(env) {
  if (!env.CHECKINS) return [];
  const raw = await env.CHECKINS.get(ADMIN_ACCOUNTS_KEY);
  if (!raw) {
    return await ensureDefaultSuperAdmin(env);
  }
  try {
    const list = ensureArray(JSON.parse(raw));
    if (list.length === 0) {
      return await ensureDefaultSuperAdmin(env);
    }
    return list;
  } catch {
    return await ensureDefaultSuperAdmin(env);
  }
}

async function saveAdminAccounts(env, accounts) {
  if (!env.CHECKINS) return;
  await env.CHECKINS.put(ADMIN_ACCOUNTS_KEY, JSON.stringify(accounts));
}

async function getAdminByUsername(env, username) {
  if (!username) return null;
  const needle = String(username).toLowerCase();
  const accounts = await getAdminAccounts(env);
  return accounts.find((acct) => acct.usernameLower === needle) || null;
}

async function getAdminById(env, adminId) {
  if (!adminId) return null;
  const accounts = await getAdminAccounts(env);
  return accounts.find((acct) => acct.id === adminId) || null;
}

async function createAuthSession(env, admin) {
  if (!env.CHECKINS || !admin) return null;
  const token = generateId("authtoken");
  const now = new Date().toISOString();
  const record = {
    id: token,
    adminId: admin.id,
    role: admin.role,
    createdAt: now,
  };
  await env.CHECKINS.put(`${AUTH_SESSION_PREFIX}${token}`, JSON.stringify(record), {
    expirationTtl: 60 * 60 * 12,
  });
  return record;
}

async function getAuthSession(env, token) {
  if (!env.CHECKINS || !token) return null;
  const raw = await env.CHECKINS.get(`${AUTH_SESSION_PREFIX}${token}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function destroyAuthSession(env, token) {
  if (!env.CHECKINS || !token) return;
  await env.CHECKINS.delete(`${AUTH_SESSION_PREFIX}${token}`);
}

function extractAuthToken(request, url) {
  const authHeader = request.headers.get("authorization") || "";
  if (authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.slice(7).trim();
  }
  const headerToken = request.headers.get("x-admin-token") || "";
  if (headerToken) return headerToken;
  const queryToken = url.searchParams.get("token") || url.searchParams.get("adminToken") || "";
  if (queryToken) return queryToken;
  return "";
}

function generateId(prefix) {
  if (typeof crypto.randomUUID === "function") {
    return `${prefix}_${crypto.randomUUID()}`;
  }
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

async function recordAdminActivity(env, admin, action, payload = {}) {
  if (!env.CHECKINS || !admin) return;
  const entry = {
    id: generateId("log"),
    adminId: admin.id,
    adminName: admin.name || "",
    action,
    payload,
    at: new Date().toISOString(),
  };
  const key = `${ADMIN_ACTIVITY_PREFIX}${admin.id}:${entry.id}`;
  await env.CHECKINS.put(key, JSON.stringify(entry), { expirationTtl: 60 * 60 * 24 * 180 });
}

async function fetchAdminActivity(env, adminId, limit = 100) {
  if (!env.CHECKINS || !adminId) return [];
  const prefix = `${ADMIN_ACTIVITY_PREFIX}${adminId}:`;
  const list = await env.CHECKINS.list({ prefix });
  const items = [];
  for (const key of list.keys) {
    const raw = await env.CHECKINS.get(key.name);
    if (!raw) continue;
    try {
      items.push(JSON.parse(raw));
    } catch {
      continue;
    }
  }
  items.sort((a, b) => new Date(b.at || 0) - new Date(a.at || 0));
  return items.slice(0, limit);
}

async function requireAdmin(request, url, env, options = {}) {
  const expectedRole = options.role || "admin";
  const token = extractAuthToken(request, url);
  if (!token) {
    return { ok: false, response: unauthorizedResponse() };
  }
  const authSession = await getAuthSession(env, token);
  if (!authSession) {
    return { ok: false, response: unauthorizedResponse() };
  }
  const admin = await getAdminById(env, authSession.adminId);
  if (!admin) {
    await destroyAuthSession(env, token);
    return { ok: false, response: unauthorizedResponse() };
  }
  if (expectedRole === "super" && admin.role !== "super") {
    return { ok: false, response: unauthorizedResponse() };
  }
  return { ok: true, admin, token, authSession };
}

async function checkRateLimit(env, request, limit = 8, windowSeconds = 60) {
  if (!env.CHECKINS) return { ok: true };
  const ip = request.headers.get("cf-connecting-ip") || "anon";
  const key = `ratelimit:${ip}`;
  const countRaw = await env.CHECKINS.get(key);
  const count = Number(countRaw || 0);
  if (count >= limit) {
    return { ok: false };
  }
  await env.CHECKINS.put(key, String(count + 1), { expirationTtl: windowSeconds });
  return { ok: true };
}

async function createStripePreauth(env, { amountCents, currency, description, metadata }) {
  if (!env.STRIPE_SECRET_KEY) {
    throw new Error("STRIPE_SECRET_KEY not configured");
  }
  const params = new URLSearchParams();
  params.append("amount", String(amountCents));
  params.append("currency", currency);
  params.append("capture_method", "manual");
  params.append("confirm", "true");
  params.append("payment_method", "pm_card_visa");
  if (description) params.append("description", description);
  if (metadata) {
    for (const [key, value] of Object.entries(metadata)) {
      params.append(`metadata[${key}]`, String(value));
    }
  }
  const stripeRes = await fetch(`${STRIPE_API_BASE}/payment_intents`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params,
  });
  const stripeData = await stripeRes.json();
  if (!stripeRes.ok) {
    throw new Error(stripeData?.error?.message || "Stripe error");
  }
  return {
    id: stripeData.id,
    client_secret: stripeData.client_secret,
    status: stripeData.status,
    amount: stripeData.amount,
    currency: stripeData.currency,
    created: stripeData.created,
  };
}

async function saveCheckin(env, record) {
  if (!env.CHECKINS) return;
  const key = `checkin:${record.id}`;
  await env.CHECKINS.put(key, JSON.stringify(record), {
    expirationTtl: 60 * 60 * 24 * 365,
  });
  if (!Array.isArray(record.headphones)) return;
  const active = record.headphones.filter((h) => h && h.id && !h.returnedAt && !h.lost);
  for (const hp of active) {
    await env.CHECKINS.put(`headphone:${hp.id}`, record.id, {
      expirationTtl: 60 * 60 * 24 * 365,
    });
    if (hp.metadata?.nfcTagId) {
      await saveNfcTagMapping(env, hp.metadata.nfcTagId, record.id);
    }
  }
}

async function getCheckinById(env, id) {
  if (!env.CHECKINS) return null;
  const raw = await env.CHECKINS.get(`checkin:${id}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function getCheckinByHeadphone(env, headphoneId) {
  if (!env.CHECKINS) return null;
  const mapKey = `headphone:${headphoneId}`;
  const checkinId = await env.CHECKINS.get(mapKey);
  if (!checkinId) return null;
  return await getCheckinById(env, checkinId);
}

async function clearHeadphoneMapping(env, headphoneId) {
  if (!env.CHECKINS) return;
  await env.CHECKINS.delete(`headphone:${headphoneId}`);
}

function normalizeTagKey(tagId) {
  if (!tagId) return "";
  return String(tagId).trim().toLowerCase();
}

async function saveNfcTagMapping(env, tagId, checkinId) {
  if (!env.CHECKINS) return;
  const normalized = normalizeTagKey(tagId);
  if (!normalized) return;
  await env.CHECKINS.put(`${NFC_TAG_PREFIX}${normalized}`, checkinId, {
    expirationTtl: 60 * 60 * 24 * 365,
  });
}

async function getCheckinByNfcTag(env, tagId) {
  if (!env.CHECKINS) return null;
  const normalized = normalizeTagKey(tagId);
  if (!normalized) return null;
  const checkinId = await env.CHECKINS.get(`${NFC_TAG_PREFIX}${normalized}`);
  if (!checkinId) return null;
  return await getCheckinById(env, checkinId);
}

async function clearNfcTagMapping(env, tagId) {
  if (!env.CHECKINS) return;
  const normalized = normalizeTagKey(tagId);
  if (!normalized) return;
  await env.CHECKINS.delete(`${NFC_TAG_PREFIX}${normalized}`);
}

async function clearHeadphoneReferences(env, headphone) {
  if (!headphone || !headphone.id) return;
  await clearHeadphoneMapping(env, headphone.id);
  const tagId = headphone.metadata?.nfcTagId || headphone.metadata?.sourceTag;
  if (tagId) {
    await clearNfcTagMapping(env, tagId);
  }
}

async function saveCurrentEvent(env, event) {
  if (!env.CHECKINS) return;
  if (!event) {
    await env.CHECKINS.delete("event:current");
    return;
  }
  await env.CHECKINS.put("event:current", JSON.stringify(event), {
    expirationTtl: 60 * 60 * 24 * 180,
  });
}

async function getCurrentEvent(env) {
  if (!env.CHECKINS) return null;
  const raw = await env.CHECKINS.get("event:current");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function getEventsList(env) {
  if (!env.CHECKINS) return [];
  const raw = await env.CHECKINS.get(EVENTS_LIST_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function saveEventsList(env, events) {
  if (!env.CHECKINS) return;
  await env.CHECKINS.put(EVENTS_LIST_KEY, JSON.stringify(events), {
    expirationTtl: 60 * 60 * 24 * 365,
  });
}

function pickPrimaryEvent(events) {
  if (!Array.isArray(events) || events.length === 0) return null;
  return events.find((evt) => evt.active) || events[0];
}

function countHeadphonesOut(record) {
  if (!Array.isArray(record.headphones)) return 0;
  return record.headphones.filter((h) => h && h.id && !h.returnedAt && !h.lost).length;
}

function formatHid(counter) {
  return `HID${String(counter).padStart(9, "0")}`;
}

async function getReleasedPool(env) {
  if (!env.CHECKINS) return [];
  const raw = await env.CHECKINS.get(HID_RELEASE_POOL_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function saveReleasedPool(env, pool) {
  if (!env.CHECKINS) return;
  await env.CHECKINS.put(HID_RELEASE_POOL_KEY, JSON.stringify(pool));
}

async function reserveHeadphones(env, qty) {
  if (!env.CHECKINS) throw new Error("KV not configured");
  if (!qty || qty < 1) qty = 1;
  const pool = await getReleasedPool(env);
  const assigned = [];
  while (pool.length > 0 && assigned.length < qty) {
    assigned.push(pool.pop());
  }
  if (pool.length === 0) {
    await env.CHECKINS.delete(HID_RELEASE_POOL_KEY);
  } else {
    await saveReleasedPool(env, pool);
  }
  if (assigned.length < qty) {
    const needed = qty - assigned.length;
    const rawCounter = await env.CHECKINS.get(HID_COUNTER_KEY);
    let counter = Number(rawCounter || 1);
    for (let i = 0; i < needed; i++) {
      assigned.push(formatHid(counter));
      counter += 1;
    }
    await env.CHECKINS.put(HID_COUNTER_KEY, String(counter));
  }
  return assigned;
}

async function releaseHeadphones(env, ids = []) {
  if (!env.CHECKINS || !ids || ids.length === 0) return;
  const cleaned = Array.from(new Set(ids.filter(Boolean)));
  if (cleaned.length === 0) return;
  const pool = await getReleasedPool(env);
  const merged = Array.from(new Set(pool.concat(cleaned)));
  await saveReleasedPool(env, merged);
}

async function saveSession(env, session) {
  if (!env.CHECKINS || !session || !session.id) return;
  await env.CHECKINS.put(`${SESSION_PREFIX}${session.id}`, JSON.stringify(session), {
    expirationTtl: 60 * 60 * 24,
  });
}

async function getSession(env, sessionId) {
  if (!env.CHECKINS || !sessionId) return null;
  const raw = await env.CHECKINS.get(`${SESSION_PREFIX}${sessionId}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function setActiveSessionForAdmin(env, adminId, sessionId) {
  if (!env.CHECKINS || !adminId) return;
  if (!sessionId) {
    await env.CHECKINS.delete(`${SESSION_ADMIN_PREFIX}${adminId}`);
    return;
  }
  await env.CHECKINS.put(`${SESSION_ADMIN_PREFIX}${adminId}`, sessionId, { expirationTtl: 60 * 60 * 24 });
}

async function getSessionForAdmin(env, adminId) {
  if (!env.CHECKINS || !adminId) return null;
  const sessionId = await env.CHECKINS.get(`${SESSION_ADMIN_PREFIX}${adminId}`);
  if (!sessionId) return null;
  return await getSession(env, sessionId);
}

async function endSession(env, sessionId) {
  if (!env.CHECKINS || !sessionId) return null;
  const session = await getSession(env, sessionId);
  if (!session) return null;
  session.active = false;
  session.endedAt = new Date().toISOString();
  await saveSession(env, session);
  if (session.adminId) {
    await setActiveSessionForAdmin(env, session.adminId, null);
  }
  return session;
}

async function hashSignature(dataUrl) {
  if (!dataUrl) return null;
  const encoder = new TextEncoder();
  const bytes = encoder.encode(dataUrl);
  const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sendWebhook(env, payload) {
  if (!env.WEBHOOK_URL) return;
  try {
    await fetch(env.WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.warn("Webhook send failed", err);
  }
}

async function sendEmail(env, { to, subject, html, text }) {
  if (!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL || !to) return;
  try {
    await fetch(RESEND_API_BASE, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.RESEND_FROM_EMAIL,
        to: [to],
        subject,
        html,
        text,
      }),
    });
  } catch (err) {
    console.warn("Resend send failed", err);
  }
}

function renderCheckinEmail(record) {
  const customer = record.customer || {};
  const event = record.event || {};
  const headphones = Array.isArray(record.headphones) ? record.headphones : [];
  const headphoneList = headphones
    .map((h) => `<li><strong>${h.id}</strong> · assigned ${h.assignedAt || record.createdAt}</li>`)
    .join("");
  const html = `
    <div style="font-family:system-ui,Arial,sans-serif;padding:16px;color:#111;background:#f5f7ff;">
      <h2 style="margin-bottom:4px;">Silent Disco Check-In Confirmed</h2>
      <p style="margin:0 0 12px;">Hi ${customer.fullName || "there"}, here are your check-in details.</p>
      <div style="background:#fff;border-radius:12px;padding:16px;border:1px solid #dde4ff;">
        <p><strong>Event:</strong> ${event.name || "TBA"} · ${event.date || ""} ${event.venue ? "· " + event.venue : ""}</p>
        <p><strong>Check-in ID:</strong> ${record.id}</p>
        <p><strong>Headphones:</strong></p>
        <ul>${headphoneList}</ul>
        <p><strong>Timestamp:</strong> ${record.createdAt}</p>
        <p style="font-size:13px;color:#5a627a;">By signing you agreed to the loss/damage terms (up to $80 per headphone) and media consent.</p>
      </div>
    </div>`;
  const text = `Silent Disco check-in confirmed. Event: ${event.name || ""} ${event.date || ""}. Headphones: ${headphones
    .map((h) => h.id)
    .join(", ")}. Check-in ID: ${record.id}.`;
  return { html, text };
}

function renderReturnEmail(record) {
  const customer = record.customer || {};
  const event = record.event || {};
  const html = `
    <div style="font-family:system-ui,Arial,sans-serif;padding:16px;color:#111;background:#f5f7ff;">
      <h2 style="margin-bottom:4px;">Headphones Returned – Thank you!</h2>
      <p style="margin:0 0 12px;">${customer.fullName || "Guest"}, we have recorded that all headphones were returned.</p>
      <div style="background:#fff;border-radius:12px;padding:16px;border:1px solid #dde4ff;">
        <p><strong>Event:</strong> ${event.name || "TBA"}</p>
        <p><strong>Return time:</strong> ${record.returnedAt || new Date().toISOString()}</p>
        <p>No additional charges were incurred. Liability hold has been released.</p>
      </div>
    </div>`;
  const text = `All headphones for your Silent Disco check-in (${record.id}) have been returned. Thank you!`;
  return { html, text };
}

function sanitizeNfcTagId(value) {
  const normalized = normalizeTagKey(value);
  return normalized || null;
}

function normalizeHeadphonesFromBody(body, now) {
  const ids = Array.isArray(body.headphoneIds) ? body.headphoneIds : [];
  const meta = Array.isArray(body.headphonesMeta) ? body.headphonesMeta : [];
  const seen = new Set();
  const headphones = [];
  for (let i = 0; i < ids.length; i++) {
    const id = String(ids[i] || "").trim();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const detail = meta[i] || {};
    const rawTag = detail.sourceTag || detail.nfcTagId || "";
    const normalizedTag = sanitizeNfcTagId(rawTag);
    headphones.push({
      id,
      assignedAt: now,
      returnedAt: null,
      lost: false,
      metadata: {
        nfcTagId: normalizedTag,
        sourceTag: rawTag ? String(rawTag).trim() : null,
      },
    });
  }
  return headphones;
}

function isActiveCheckin(record) {
  if (!record) return false;
  return ACTIVE_STATUSES.has(record.status);
}

function summarizeHolder(record) {
  if (!record) return null;
  return {
    fullName: record.customer?.fullName || "",
    phone: record.customer?.phone || "",
    email: record.customer?.email || "",
    event: record.event || null,
    checkinId: record.id,
  };
}

function flattenCheckin(record, { includeReturned = false } = {}) {
  const base = {
    id: record.id,
    status: record.status,
    createdAt: record.createdAt,
    returnedAt: record.returnedAt || null,
    customer: record.customer || null,
    event: record.event || null,
    eventId: record.eventId || null,
    handledBy: record.handledBy || null,
    sessionId: record.sessionId || null,
  };
  if (!Array.isArray(record.headphones) || record.headphones.length === 0) {
    return [
      {
        ...base,
        headphone: null,
      },
    ];
  }
  const rows = [];
  for (const hp of record.headphones) {
    if (!hp || !hp.id) continue;
    if (!includeReturned && (hp.returnedAt || hp.lost)) continue;
    rows.push({ ...base, headphone: hp });
  }
  return rows;
}

async function listCheckinsByAdmin(env, adminId, limit = 200) {
  if (!env.CHECKINS || !adminId) return [];
  const list = await env.CHECKINS.list({ prefix: "checkin:" });
  const matches = [];
  for (const key of list.keys) {
    const id = key.name.substring("checkin:".length);
    const rec = await getCheckinById(env, id);
    if (!rec || !rec.handledBy || rec.handledBy.id !== adminId) continue;
    matches.push(rec);
  }
  matches.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  return matches.slice(0, limit);
}

async function sendCheckinEmails(env, record) {
  const { html, text } = renderCheckinEmail(record);
  if (record.customer?.email) {
    await sendEmail(env, {
      to: record.customer.email,
      subject: "Silent Disco check-in confirmed",
      html,
      text,
    });
  }
}

async function sendReturnEmails(env, record) {
  const { html, text } = renderReturnEmail(record);
  if (record.customer?.email) {
    await sendEmail(env, {
      to: record.customer.email,
      subject: "Silent Disco headphones returned",
      html,
      text,
    });
  }
}

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const { pathname, searchParams } = url;

  if (pathname === "/health" && request.method === "GET") {
    return jsonResponse({ ok: true, service: "SE2 Events API", timestamp: new Date().toISOString() });
  }

  if (pathname === "/version" && request.method === "GET") {
    return jsonResponse({ ok: true, app: "Silent Disco HQ", api: "v0.8.0", env: "staging" });
  }

  if (pathname === "/auth/register" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const name = String(body.name || "").trim();
    const email = String(body.email || "").trim();
    const username = String(body.username || "").trim();
    const password = String(body.password || "").trim();
    if (!name || !username || !password) {
      return jsonResponse({ ok: false, error: "Name, username, and password are required" }, 400);
    }
    const usernameLower = username.toLowerCase();
    const accounts = await getAdminAccounts(env);
    if (accounts.some((acct) => acct.usernameLower === usernameLower)) {
      return jsonResponse({ ok: false, error: "Username already in use" }, 409);
    }
    const now = new Date().toISOString();
    const newAccount = {
      id: generateId("adm"),
      name,
      email,
      role: "admin",
      username,
      usernameLower,
      passwordHash: await hashPassword(password),
      createdAt: now,
      updatedAt: now,
    };
    accounts.push(newAccount);
    await saveAdminAccounts(env, accounts);
    const session = await createAuthSession(env, newAccount);
    await recordAdminActivity(env, newAccount, "auth.register", {});
    return jsonResponse({ ok: true, admin: sanitizeAdminAccount(newAccount), token: session?.id || null });
  }

  if (pathname === "/auth/login" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const username = String(body.username || "").trim();
    const password = String(body.password || "").trim();
    if (!username || !password) {
      return jsonResponse({ ok: false, error: "Username and password are required" }, 400);
    }
    const admin = await getAdminByUsername(env, username);
    if (!admin) {
      return unauthorizedResponse();
    }
    const valid = await verifyPassword(password, admin.passwordHash);
    if (!valid) {
      return unauthorizedResponse();
    }
    const session = await createAuthSession(env, admin);
    await recordAdminActivity(env, admin, "auth.login", {});
    return jsonResponse({ ok: true, admin: sanitizeAdminAccount(admin), token: session?.id || null });
  }

  if (pathname === "/auth/logout" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    await destroyAuthSession(env, auth.token);
    await recordAdminActivity(env, auth.admin, "auth.logout", {});
    return jsonResponse({ ok: true });
  }

  if (pathname === "/auth/profile" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    const session = await getSessionForAdmin(env, auth.admin.id);
    return jsonResponse({ ok: true, admin: sanitizeAdminAccount(auth.admin), session });
  }

  if (pathname === "/auth/password" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const currentPassword = String(body.currentPassword || "").trim();
    const newPassword = String(body.newPassword || "").trim();
    if (!currentPassword || !newPassword) {
      return jsonResponse({ ok: false, error: "Current and new passwords are required" }, 400);
    }
    const valid = await verifyPassword(currentPassword, auth.admin.passwordHash);
    if (!valid) {
      return jsonResponse({ ok: false, error: "Current password is incorrect" }, 403);
    }
    const accounts = await getAdminAccounts(env);
    const idx = accounts.findIndex((acct) => acct.id === auth.admin.id);
    if (idx === -1) {
      return unauthorizedResponse();
    }
    accounts[idx].passwordHash = await hashPassword(newPassword);
    accounts[idx].updatedAt = new Date().toISOString();
    await saveAdminAccounts(env, accounts);
    await recordAdminActivity(env, auth.admin, "auth.password", {});
    return jsonResponse({ ok: true });
  }

  if (pathname === "/super/admins" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env, { role: "super" });
    if (!auth.ok) return auth.response;
    const accounts = await getAdminAccounts(env);
    const sanitized = accounts.map((acct) => sanitizeAdminAccount(acct));
    return jsonResponse({ ok: true, admins: sanitized });
  }

  if (pathname === "/super/admins" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env, { role: "super" });
    if (!auth.ok) return auth.response;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const name = String(body.name || "").trim();
    if (!name) {
      return jsonResponse({ ok: false, error: "Name is required" }, 400);
    }
    const email = String(body.email || "").trim();
    const role = body.role === "super" ? "super" : "admin";
    const username = String(body.username || "").trim();
    const password = String(body.password || "").trim();
    if (!username) {
      return jsonResponse({ ok: false, error: "Username is required" }, 400);
    }
    const accounts = await getAdminAccounts(env);
    if (accounts.some((acct) => acct.usernameLower === username.toLowerCase())) {
      return jsonResponse({ ok: false, error: "Username already exists" }, 409);
    }
    const plainPassword = password || Math.random().toString(36).slice(2, 10);
    const now = new Date().toISOString();
    const newAccount = {
      id: generateId("adm"),
      name,
      email,
      role,
      username,
      usernameLower: username.toLowerCase(),
      passwordHash: await hashPassword(plainPassword),
      createdAt: now,
      updatedAt: now,
    };
    accounts.push(newAccount);
    await saveAdminAccounts(env, accounts);
    await recordAdminActivity(env, auth.admin, "admin.create", { targetId: newAccount.id });
    return jsonResponse({ ok: true, admin: sanitizeAdminAccount(newAccount), tempPassword: password ? null : plainPassword });
  }

  if (pathname === "/super/admins/delete" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env, { role: "super" });
    if (!auth.ok) return auth.response;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const adminId = String(body.adminId || "").trim();
    if (!adminId) {
      return jsonResponse({ ok: false, error: "adminId required" }, 400);
    }
    let accounts = await getAdminAccounts(env);
    const before = accounts.length;
    accounts = accounts.filter((acct) => acct.id !== adminId);
    if (accounts.length === before) {
      return jsonResponse({ ok: false, error: "Admin not found" }, 404);
    }
    await saveAdminAccounts(env, accounts);
    await recordAdminActivity(env, auth.admin, "admin.delete", { targetId: adminId });
    return jsonResponse({ ok: true, admins: accounts.map(sanitizeAdminAccount) });
  }

  if (pathname === "/super/admins/activity" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env, { role: "super" });
    if (!auth.ok) return auth.response;
    const adminId = searchParams.get("adminId");
    const limit = Number(searchParams.get("limit") || 100) || 100;
    if (!adminId) {
      return jsonResponse({ ok: false, error: "adminId required" }, 400);
    }
    const activity = await fetchAdminActivity(env, adminId, limit);
    return jsonResponse({ ok: true, activity });
  }

  if (pathname === "/super/admins/checkins" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env, { role: "super" });
    if (!auth.ok) return auth.response;
    const adminId = searchParams.get("adminId");
    const limit = Number(searchParams.get("limit") || 200) || 200;
    const includeReturned = searchParams.get("includeReturned") !== "false";
    if (!adminId) {
      return jsonResponse({ ok: false, error: "adminId required" }, 400);
    }
    const records = await listCheckinsByAdmin(env, adminId, limit);
    const flattened = records.flatMap((rec) => flattenCheckin(rec, { includeReturned }));
    return jsonResponse({ ok: true, adminId, count: records.length, flattened, records });
  }

  if (pathname === "/public/events" && request.method === "GET") {
    const allEvents = await getEventsList(env);
    const active = allEvents.filter((evt) => evt.active);
    return jsonResponse({ ok: true, events: active, allEvents });
  }

  if (pathname === "/public/event" && request.method === "GET") {
    const events = await getEventsList(env);
    const primary = pickPrimaryEvent(events);
    if (primary) {
      return jsonResponse({ ok: true, event: { name: primary.name, date: primary.date, venue: primary.venue }, eventId: primary.id });
    }
    const event = await getCurrentEvent(env);
    return jsonResponse({ ok: true, event });
  }

  if (pathname === "/public/session" && request.method === "GET") {
    const sessionId = searchParams.get("sessionId");
    if (!sessionId) {
      return jsonResponse({ ok: false, error: "sessionId required" }, 400);
    }
    const session = await getSession(env, sessionId);
    if (!session || !session.active) {
      return jsonResponse({ ok: false, error: "Session not found" }, 404);
    }
    return jsonResponse({ ok: true, session });
  }

  if (pathname === "/admin/session" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    const session = await getSessionForAdmin(env, auth.admin.id);
    return jsonResponse({ ok: true, session });
  }

  if (pathname === "/admin/session" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const eventId = String(body.eventId || "").trim();
    if (!eventId) {
      return jsonResponse({ ok: false, error: "eventId required" }, 400);
    }
    const events = await getEventsList(env);
    const target = events.find((evt) => evt.id === eventId);
    if (!target) {
      return jsonResponse({ ok: false, error: "Event not found" }, 404);
    }
    const now = new Date().toISOString();
    const session = {
      id: generateId("sess"),
      adminId: auth.admin.id,
      adminName: auth.admin.name,
      adminEmail: auth.admin.email,
      adminRole: auth.admin.role,
      adminSnapshot: sanitizeAdminAccount(auth.admin),
      eventId: target.id,
      eventSnapshot: {
        id: target.id,
        name: target.name,
        date: target.date,
        venue: target.venue,
      },
      startedAt: now,
      active: true,
    };
    await saveSession(env, session);
    await setActiveSessionForAdmin(env, auth.admin.id, session.id);
    await recordAdminActivity(env, auth.admin, "session.start", { eventId: target.id, sessionId: session.id });
    return jsonResponse({ ok: true, session });
  }

  if (pathname === "/admin/session" && request.method === "DELETE") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    let sessionId = searchParams.get("sessionId");
    if (!sessionId && env.CHECKINS) {
      sessionId = await env.CHECKINS.get(`${SESSION_ADMIN_PREFIX}${auth.admin.id}`);
    }
    if (!sessionId) {
      return jsonResponse({ ok: true, session: null });
    }
    const session = await endSession(env, sessionId);
    if (session) {
      await recordAdminActivity(env, auth.admin, "session.end", { sessionId });
    }
    return jsonResponse({ ok: true, session });
  }

  if (pathname === "/headphones/reserve" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const qty = Number(body.qty || 1) || 1;
    try {
      const ids = await reserveHeadphones(env, qty);
      return jsonResponse({ ok: true, headphones: ids });
    } catch (err) {
      return jsonResponse({ ok: false, error: err.message || String(err) }, 500);
    }
  }

  if (pathname === "/headphones/release" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    await releaseHeadphones(env, body.headphoneIds || []);
    return jsonResponse({ ok: true });
  }

  if (pathname === "/checkin/demo" && request.method === "POST") {
    const rate = await checkRateLimit(env, request);
    if (!rate.ok) {
      return jsonResponse({ ok: false, error: "Too many submissions. Try again shortly." }, 429);
    }
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON body" }, 400);
    }
    const now = new Date().toISOString();
    const recordId = "chk_" + Math.random().toString(36).slice(2, 10);
    let session = null;
    const sessionId = typeof body.sessionId === "string" ? body.sessionId.trim() : "";
    if (sessionId) {
      session = await getSession(env, sessionId);
      if (!session || !session.active) {
        return jsonResponse(
          { ok: false, error: "Invalid or expired session", errorCode: "session_invalid" },
          400
        );
      }
    }
    const headphones = normalizeHeadphonesFromBody(body, now);
    if (headphones.length === 0) {
      return jsonResponse({ ok: false, error: "At least one headphone required" }, 400);
    }

    for (const hp of headphones) {
      const existing = await getCheckinByHeadphone(env, hp.id);
      if (existing && isActiveCheckin(existing)) {
        return jsonResponse(
          {
            ok: false,
            error: "Headphone is already checked out.",
            errorCode: "headphone_in_use",
            headphoneId: hp.id,
            currentHolder: summarizeHolder(existing),
          },
          409
        );
      }
    }

    const seenTags = new Set();
    for (const hp of headphones) {
      const tagId = hp.metadata?.nfcTagId;
      if (!tagId) continue;
      if (seenTags.has(tagId)) {
        return jsonResponse(
          {
            ok: false,
            error: "The same NFC tag was scanned twice in this check-in. Remove the duplicate.",
            errorCode: "nfc_tag_duplicate",
            tagId: hp.metadata?.sourceTag || tagId,
          },
          400
        );
      }
      seenTags.add(tagId);
      const existingByTag = await getCheckinByNfcTag(env, tagId);
      if (existingByTag && isActiveCheckin(existingByTag)) {
        return jsonResponse(
          {
            ok: false,
            error: "This NFC tag is currently checked out.",
            errorCode: "nfc_tag_in_use",
            tagId: hp.metadata?.sourceTag || tagId,
            currentHolder: summarizeHolder(existingByTag),
          },
          409
        );
      }
    }

    let eventId = typeof body.eventId === "string" ? body.eventId.trim() : String(body.eventId || "").trim();
    if (!eventId) eventId = "";
    let eventInfo = {
      name: body.eventName || "",
      date: body.eventDate || "",
      venue: body.eventVenue || "",
    };
    if (session?.eventSnapshot) {
      eventId = session.eventSnapshot.id || session.eventId || eventId;
      eventInfo = {
        name: session.eventSnapshot.name || "",
        date: session.eventSnapshot.date || "",
        venue: session.eventSnapshot.venue || "",
      };
    } else if (eventId) {
      const events = await getEventsList(env);
      const found = events.find((evt) => evt.id === eventId);
      if (found) {
        eventInfo = { name: found.name || "", date: found.date || "", venue: found.venue || "" };
      }
    }

    const holdAmountCents = 100;
    const currency = "usd";
    let stripeSummary;
    try {
      stripeSummary = await createStripePreauth(env, {
        amountCents: holdAmountCents,
        currency,
        description: "Silent Disco HQ $1 pre-auth (test)",
        metadata: {
          env: "staging-demo",
          checkin_id: recordId,
          headphonesQty: headphones.length,
          customerName: body.fullName || "Guest",
          primaryHeadphone: headphones[0]?.id || "",
        },
      });
    } catch (err) {
      return jsonResponse({ ok: false, error: "Stripe pre-auth failed", details: err.message }, 502);
    }

    const signatureHash = await hashSignature(body.signature?.dataUrl || "");

    const record = {
      id: recordId,
      createdAt: now,
      returnedAt: null,
      status: "checked_out",
      holdAmountCents,
      holdCurrency: currency,
      headphonesQty: headphones.length,
      headphones,
      headphoneId: headphones[0]?.id || "",
      customer: {
        fullName: body.fullName || "",
        email: body.email || "",
        phone: body.phone || "",
      },
      eventId: eventId || null,
      event: eventInfo,
      sessionId: session?.id || null,
      handledBy: session?.adminSnapshot || null,
      consents: body.consents || {},
      signature: body.signature || null,
      signatureHash,
      raw: body,
      stripe: stripeSummary,
      loss: null,
      history: [
        {
          type: "checkin",
          at: now,
          description: `Check-in created with ${headphones.length} headphone(s)`,
          sessionId: session?.id || null,
        },
      ],
    };

    try {
      await saveCheckin(env, record);
    } catch (err) {
      console.error("KV saveCheckin failed", err);
    }

    if (session?.adminSnapshot) {
      ctx.waitUntil(
        recordAdminActivity(env, session.adminSnapshot, "checkin.create", {
          checkinId: record.id,
          sessionId: session.id,
          eventId: record.eventId,
          headphones: record.headphones.map((h) => h.id),
        })
      );
    }

    ctx.waitUntil(sendCheckinEmails(env, record));
    ctx.waitUntil(sendWebhook(env, { type: "checkin", recordId, headphones: record.headphones }));

    return jsonResponse({
      ok: true,
      message: "Demo check-in recorded.",
      checkin: {
        id: record.id,
        createdAt: record.createdAt,
        status: record.status,
        holdAmountCents,
        holdCurrency: currency,
        headphonesQty: record.headphonesQty,
        headphoneIds: record.headphones.map((h) => h.id),
      },
      stripe: stripeSummary,
    });
  }

  if (pathname === "/admin/checkin" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    const id = searchParams.get("id");
    if (!id) return jsonResponse({ ok: false, error: "Missing id" }, 400);
    const record = await getCheckinById(env, id);
    if (!record) return jsonResponse({ ok: false, error: "Check-in not found" }, 404);
    return jsonResponse({ ok: true, checkin: record });
  }

  if (pathname === "/admin/headphone" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    const hp = searchParams.get("headphoneId");
    if (!hp) return jsonResponse({ ok: false, error: "Missing headphoneId" }, 400);
    const record = await getCheckinByHeadphone(env, hp);
    if (!record)
      return jsonResponse({ ok: false, error: "No active check-in found for this headphoneId" }, 404);
    return jsonResponse({ ok: true, headphoneId: hp, checkin: record });
  }

  if (pathname === "/admin/headphone/return" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON body" }, 400);
    }
    const hpId = String(body.headphoneId || "").trim();
    if (!hpId) return jsonResponse({ ok: false, error: "Missing headphoneId" }, 400);
    const record = await getCheckinByHeadphone(env, hpId);
    if (!record)
      return jsonResponse({ ok: false, error: "No active check-in found for this headphoneId" }, 404);

    const now = new Date().toISOString();
    let updated = false;
    let targetHp = null;
    for (const hp of record.headphones || []) {
      if (hp && hp.id === hpId && !hp.returnedAt && !hp.lost) {
        hp.returnedAt = now;
        targetHp = hp;
        updated = true;
        break;
      }
    }
    if (!updated) {
      return jsonResponse({ ok: false, error: "Headphone already returned or lost" }, 409);
    }

    if (targetHp) {
      await clearHeadphoneReferences(env, targetHp);
    }
    const remaining = countHeadphonesOut(record);
    if (remaining === 0) {
      record.status = "returned";
      record.returnedAt = now;
    } else {
      record.status = "partially_returned";
    }
    record.history = record.history || [];
    record.history.push({ type: "return", at: now, headphoneId: hpId });

    await saveCheckin(env, record);
    await releaseHeadphones(env, [hpId]);
    ctx.waitUntil(sendWebhook(env, { type: "return", headphoneId: hpId, recordId: record.id }));
    if (remaining === 0) {
      ctx.waitUntil(sendReturnEmails(env, record));
    }
    ctx.waitUntil(
      recordAdminActivity(env, auth.admin, "headphone.return", {
        headphoneId: hpId,
        checkinId: record.id,
        remaining,
      })
    );
    return jsonResponse({ ok: true, headphoneId: hpId, checkin: record });
  }

  if (pathname === "/admin/checkin/lost" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const checkinId = String(body.checkinId || "").trim();
    if (!checkinId) return jsonResponse({ ok: false, error: "Missing checkinId" }, 400);
    const lostIds = Array.isArray(body.lostHeadphoneIds)
      ? body.lostHeadphoneIds.map((x) => String(x).trim()).filter(Boolean)
      : [];
    if (lostIds.length === 0) {
      return jsonResponse({ ok: false, error: "No lostHeadphoneIds provided" }, 400);
    }
    const perCents =
      typeof body.lossPerHeadphoneCents === "number" && body.lossPerHeadphoneCents > 0
        ? body.lossPerHeadphoneCents
        : 8000;
    const record = await getCheckinById(env, checkinId);
    if (!record) return jsonResponse({ ok: false, error: "Check-in not found" }, 404);
    const now = new Date().toISOString();
    let marked = false;
    for (const hp of record.headphones || []) {
      if (!hp || !hp.id) continue;
      if (lostIds.includes(hp.id)) {
        hp.lost = true;
        hp.returnedAt = null;
        await clearHeadphoneReferences(env, hp);
        marked = true;
      }
    }
    if (!marked) {
      return jsonResponse({ ok: false, error: "None of those headphones were on this check-in" }, 400);
    }
    const remaining = countHeadphonesOut(record);
    const anyReturned = (record.headphones || []).some((h) => h.returnedAt && !h.lost);
    if (remaining === 0 && anyReturned) record.status = "partially_lost";
    else if (remaining === 0) record.status = "lost";
    else record.status = "partially_lost";
    const totalLossCents = lostIds.length * perCents;
    record.loss = {
      lostHeadphoneIds: lostIds,
      lossPerHeadphoneCents: perCents,
      totalLossCents,
      markedAt: now,
    };
    record.history = record.history || [];
    record.history.push({ type: "loss", at: now, headphoneIds: lostIds });
    await saveCheckin(env, record);
    ctx.waitUntil(sendWebhook(env, { type: "loss", checkinId, lostIds }));
    ctx.waitUntil(
      recordAdminActivity(env, auth.admin, "headphone.loss", {
        checkinId,
        lostHeadphoneIds: lostIds,
        totalLossCents,
      })
    );
    return jsonResponse({
      ok: true,
      checkin: record,
      note: "Loss recorded in KV only (TEST mode).",
    });
  }

  if (pathname === "/admin/checkins/active" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    if (!env.CHECKINS) return jsonResponse({ ok: false, error: "KV not configured" }, 500);
    const list = await env.CHECKINS.list({ prefix: "checkin:" });
    const rows = [];
    for (const key of list.keys) {
      const id = key.name.substring("checkin:".length);
      const rec = await getCheckinById(env, id);
      if (!rec) continue;
      const flattened = flattenCheckin(rec, { includeReturned: false });
      for (const row of flattened) {
        if (!row.headphone) continue;
        rows.push(row);
      }
    }
    rows.sort((a, b) => new Date(a.createdAt || 0) - new Date(b.createdAt || 0));
    return jsonResponse({ ok: true, items: rows });
  }

  if (pathname === "/admin/checkins/log" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    if (!env.CHECKINS) return jsonResponse({ ok: false, error: "KV not configured" }, 500);
    const limit = Number(searchParams.get("limit") || 200) || 200;
    const list = await env.CHECKINS.list({ prefix: "checkin:" });
    const rows = [];
    for (const key of list.keys) {
      const id = key.name.substring("checkin:".length);
      const rec = await getCheckinById(env, id);
      if (!rec) continue;
      const flattened = flattenCheckin(rec, { includeReturned: true });
      rows.push(...flattened);
    }
    rows.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    return jsonResponse({ ok: true, items: rows.slice(0, limit) });
  }

  if (pathname === "/admin/events" && request.method === "GET") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    const events = await getEventsList(env);
    events.sort((a, b) => new Date(b.updatedAt || 0) - new Date(a.updatedAt || 0));
    return jsonResponse({ ok: true, events });
  }

  if (pathname === "/admin/events" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const name = body.eventName || body.name || "";
    if (!name) {
      return jsonResponse({ ok: false, error: "Event name required" }, 400);
    }
    const date = body.eventDate || body.date || "";
    const venue = body.eventVenue || body.venue || "";
    const now = new Date().toISOString();
    const events = await getEventsList(env);
    let eventId = typeof body.eventId === "string" ? body.eventId.trim() : String(body.eventId || "").trim();
    if (!eventId) {
      eventId = "evt_" + Math.random().toString(36).slice(2, 10);
    }
    let target = events.find((evt) => evt.id === eventId);
    const active = body.active === undefined ? true : Boolean(body.active);
    if (target) {
      target.name = name;
      target.date = date;
      target.venue = venue;
      target.active = active;
      target.updatedAt = now;
    } else {
      target = {
        id: eventId,
        name,
        date,
        venue,
        active,
        createdAt: now,
        updatedAt: now,
      };
      events.push(target);
    }
    await saveEventsList(env, events);
    if (target.active) {
      await saveCurrentEvent(env, {
        id: target.id,
        name: target.name,
        date: target.date,
        venue: target.venue,
        active: true,
      });
    }
    ctx.waitUntil(
      recordAdminActivity(env, auth.admin, "event.save", {
        eventId: target.id,
        active: target.active,
      })
    );
    return jsonResponse({ ok: true, event: target, events });
  }

  if (pathname === "/admin/events/activate" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const eventId = typeof body.eventId === "string" ? body.eventId.trim() : "";
    if (!eventId) {
      return jsonResponse({ ok: false, error: "eventId required" }, 400);
    }
    const events = await getEventsList(env);
    const target = events.find((evt) => evt.id === eventId);
    if (!target) {
      return jsonResponse({ ok: false, error: "Event not found" }, 404);
    }
    target.active = Boolean(body.active);
    target.updatedAt = new Date().toISOString();
    await saveEventsList(env, events);
    const primary = pickPrimaryEvent(events);
    if (primary) {
      await saveCurrentEvent(env, {
        id: primary.id,
        name: primary.name,
        date: primary.date,
        venue: primary.venue,
        active: true,
      });
    } else {
      await saveCurrentEvent(env, null);
    }
    ctx.waitUntil(
      recordAdminActivity(env, auth.admin, "event.activate", {
        eventId: target.id,
        active: target.active,
      })
    );
    return jsonResponse({ ok: true, event: target, events });
  }

  if (pathname === "/admin/event" && request.method === "POST") {
    const auth = await requireAdmin(request, url, env);
    if (!auth.ok) return auth.response;
    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: "Invalid JSON" }, 400);
    }
    const event = {
      name: body.eventName || "",
      date: body.eventDate || "",
      venue: body.eventVenue || "",
      updatedAt: new Date().toISOString(),
    };
    await saveCurrentEvent(env, event);
    const events = await getEventsList(env);
    const existing = events.find(
      (evt) => evt.name === event.name && evt.date === event.date && evt.venue === event.venue
    );
    if (existing) {
      existing.active = true;
      existing.updatedAt = event.updatedAt;
    } else {
      events.push({
        id: "evt_" + Math.random().toString(36).slice(2, 10),
        name: event.name,
        date: event.date,
        venue: event.venue,
        active: true,
        createdAt: event.updatedAt,
        updatedAt: event.updatedAt,
      });
    }
    await saveEventsList(env, events);
    ctx.waitUntil(
      recordAdminActivity(env, auth.admin, "event.save_manual", {
        name: event.name,
        date: event.date,
        venue: event.venue,
      })
    );
    return jsonResponse({ ok: true, event, events, message: "Event settings updated." });
  }

  return jsonResponse({ ok: false, error: "Not found" }, 404);
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }
    let response;
    try {
      response = await handleRequest(request, env, ctx);
    } catch (err) {
      console.error("Worker error", err);
      response = jsonResponse({ ok: false, error: "Internal server error" }, 500);
    }
    const headers = new Headers(response.headers);
    for (const [key, value] of Object.entries(corsHeaders)) {
      headers.set(key, value);
    }
    return new Response(response.body, { status: response.status, headers });
  },
};
