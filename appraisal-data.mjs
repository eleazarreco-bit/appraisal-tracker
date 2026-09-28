import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import { promisify } from "node:util";
import APP_HTML from "../lib/app-ui.mjs";

/* ------------------------------------------------------------------
   Configuration
   Set BOTH of these in Netlify -> Site configuration -> Environment variables.
   There are deliberately NO fallback values: if either is missing, sign-in
   is refused with a clear message instead of using a guessable default.
     MASTER_PASSWORD  a long passphrase only the administrator knows
     SESSION_SECRET   32+ random characters, different from the password
   ------------------------------------------------------------------ */
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const configError = () =>
  !MASTER_PASSWORD || !SESSION_SECRET || SESSION_SECRET.length < 32
    ? "Sign-in is not configured. The administrator must set MASTER_PASSWORD and SESSION_SECRET (32+ characters) in Netlify environment variables."
    : null;

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;   // sessions last 12 hours
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;      // failure counting / lock window
const MAX_FAILED_PER_IP = 8;                   // any sign-in, per IP
const MAX_FAILED_PER_ACCOUNT = 5;              // leads / employees, per phone or ID (any IP)
const MAX_FAILED_MASTER = 10;                  // master password, all IPs combined

const DATA_KEYS = new Set(["employees", "incidents"]);

/* Only used the very first time, when no roster has been stored yet. */
  const SEED_EMPLOYEES = [
    // -- Lazar's team (previously loaded) --
    ["Dheeraj Kumar Jamalpur", "IBS-305", "Lazar"], ["Pavan Kumar B.V.S", "IBS-424", "Lazar"],
    ["Suresh Babu Kusuma", "IBS-432", "Lazar"], ["Bindu Sagar Kusuma", "IBS-449", "Lazar"],
    ["Mounika Vikrayala", "IBS-455", "Lazar"], ["Padma Korra", "IBS-474", "Lazar"],
    ["Pardha Saradhi Appikatla", "IBS-481", "Lazar"], ["Shiva Ram Jogu", "IBS-491", "Lazar"],
    ["Lokesh Varma Gunturi", "IBS-502", "Lazar"], ["Sampath Kumar Chevuri", "IBS-514", "Lazar"],
    ["Ankit Pati", "IBS-537", "Lazar"], ["Revanth Kumar Yarrabothini", "IBS-543", "Lazar"],
    ["Azhar Mohammed", "IBS-544", "Lazar"], ["Nandini Bokkisam", "IBS-548", "Lazar"],
    ["Praveen Bhukya", "IBS-568", "Lazar"], ["Vamshi Koduru", "IBS-593", "Lazar"],
    ["Ananda Rao Garnepudi", "IBS-602", "Lazar"], ["Anvesh Dharmarapu", "IBS-606", "Lazar"],
    ["Mahesh M", "IBS-608", "Lazar"], ["Azgar Ali Syed", "IBS-613", "Lazar"],
    ["Upender Ummaneni", "IBS-620", "Lazar"], ["Pavan Cheemikala", "IBS-627", "Lazar"],
    ["Ashok Kumar Bandi", "IBS-632", "Lazar"], ["Akhilesh Goud Kancharla", "IBS-633", "Lazar"],
    ["Satya Hemalatha Gundumalla", "IBS-636", "Lazar"], ["Venu Basa", "IBS-640", "Lazar"],
    ["Kotha Bhuvanesh Gupta", "IBS-641", "Lazar"], ["Sameer Shaik", "IBS-644", "Lazar"],
    ["Vineela Barigela", "IBS-647", "Lazar"], ["Prashanth Paka", "IBS-650", "Lazar"],
    ["Aman Abdul", "IBS-654", "Lazar"],
    // -- Aakash's team --
    ["Sharmila Sahu", "IBS-383", "Aakash"], ["Mahesh Bandi", "IBS-441", "Aakash"],
    ["Tejaswi Rachakonda", "IBS-468", "Aakash"], ["Jaya Venkata Bai Nandlal", "IBS-477", "Aakash"],
    ["Venkatesh Pendem", "IBS-530", "Aakash"], ["Rahul Rishi Dana", "IBS-563", "Aakash"],
    ["Sravana Kumar Poosala", "IBS-585", "Aakash"], ["Naveen Gandhalam", "IBS-623", "Aakash"],
    ["Manikanth Aatigada", "IBS-626", "Aakash"], ["Abhishek T", "IBS-634", "Aakash"],
    ["Rakesh Pulgam", "IBS-638", "Aakash"], ["Rahul Reddy Kankanala", "IBS-653", "Aakash"],
    ["Omkar Palavi", "CON-001", "Aakash"], ["Srikar Sanvally", "CON-002", "Aakash"],
    ["Abhilasha Jagannadham", "CON-003", "Aakash"], ["Kalyani Palle", "CON-004", "Aakash"],
    // -- Ahmed's team --
    ["Jaya Prakash Vittamsetti", "IBS-396", "Ahmed"], ["Sravan Kumar Sanda", "IBS-401", "Ahmed"],
    ["Shiva Sana", "IBS-501", "Ahmed"], ["Sai Kiran Ankari", "IBS-580", "Ahmed"],
    ["Ansaruddin Mohd", "IBS-591", "Ahmed"], ["K Bhanuprakash Goud", "IBS-600", "Ahmed"],
    ["Mehrajuddin", "IBS-601", "Ahmed"], ["Nushanth Goud Karingla", "IBS-603", "Ahmed"],
    ["Venkata Pradeep Siva Ramaraju Patsamatla", "IBS-605", "Ahmed"], ["Sai Naga Venkata Komal Garlapati", "IBS-630", "Ahmed"],
    ["Mahesh Anand Ulpi", "IBS-637", "Ahmed"], ["Charan Raparthi", "IBS-639", "Ahmed"],
    ["Veerababu Chellapu", "CON-005", "Ahmed"]
  ].map((e, i) => ({ id: "emp_" + (i + 1), name: e[0], empId: e[1], reportingManager: e[2] }));

/* ------------------------------ helpers ------------------------------ */
const JSON_HEADERS = { "content-type": "application/json", "cache-control": "no-store" };
const json = (status, obj) => new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return body + "." + sig;
}
function readToken(token) {
  if (!token || typeof token !== "string") return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return p && p.exp > Date.now() ? p : null;
  } catch { return null; }
}

const normId = (s) => String(s || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const last10 = (s) => String(s || "").replace(/\D/g, "").slice(-10);

/* ---------------- PINs (second factor for leads and employees) ----------------
   Stored ONLY as salted scrypt hashes, in a separate "creds" blob that is never
   sent to any browser. "ver" changes on every reset, and is copied into the
   session token, so resetting a PIN ends that person's existing sessions.   */
const scrypt = promisify(crypto.scrypt);
const newPin = () => String(crypto.randomInt(0, 1000000)).padStart(6, "0");
const hashPin = (pin, saltHex) => scrypt(String(pin), Buffer.from(saltHex, "hex"), 32);
async function makeCred(pin) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: (await hashPin(pin, salt)).toString("hex"), ver: crypto.randomBytes(6).toString("hex") };
}
const DUMMY_CRED = { salt: "00".repeat(16), hash: "00".repeat(32) };
/* Always does the same amount of work, even for unknown accounts. */
async function checkPin(pin, cred) {
  const c = cred || DUMMY_CRED;
  const derived = await hashPin(pin, c.salt);
  return crypto.timingSafeEqual(derived, Buffer.from(c.hash, "hex")) && !!cred;
}
async function getCreds(store) {
  const c = await store.get("creds", { type: "json" });
  return { leads: (c && c.leads) || {}, employees: (c && c.employees) || {} };
}

async function getAccess(store) {
  const a = await store.get("access", { type: "json" });
  return {
    leads: Array.isArray(a && a.leads) ? a.leads : [],
    enabledEmployees: Array.isArray(a && a.enabledEmployees) ? a.enabledEmployees : []
  };
}
async function getEmployees(store) {
  const e = await store.get("employees", { type: "json" });
  if (Array.isArray(e) && e.length) return e;
  if (Array.isArray(e)) return e;               // an intentionally emptied roster stays empty
  await store.setJSON("employees", SEED_EMPLOYEES);
  await store.setJSON("incidents", (await store.get("incidents", { type: "json" })) || []);
  return SEED_EMPLOYEES;
}

/* Re-checks the live access list on every request, so removing a lead or
   un-ticking an employee cuts them off immediately, not at token expiry. */
async function authenticate(req, store) {
  if (configError()) return null;
  const h = req.headers.get("authorization") || "";
  const p = readToken(h.startsWith("Bearer ") ? h.slice(7) : "");
  if (!p) return null;
  if (p.r === "master") return { role: "master" };
  const access = await getAccess(store);
  const creds = await getCreds(store);
  if (p.r === "lead") {
    const lead = access.leads.find((l) => l.id === p.s);
    const cr = lead && creds.leads[lead.id];
    return cr && cr.ver === p.c ? { role: "lead", name: lead.name || "" } : null;
  }
  if (p.r === "employee") {
    if (!access.enabledEmployees.includes(p.s)) return null;
    const cr = creds.employees[p.s];
    if (!cr || cr.ver !== p.c) return null;
    const emp = (await getEmployees(store)).find((e) => e.id === p.s);
    return emp ? { role: "employee", sub: emp.id, name: emp.name } : null;
  }
  return null;
}

/* ------------------------------ activity log ------------------------------
   Append-only: every event is its own blob ("log-<UTC timestamp>-<rand>"), so two
   people acting at the same moment can never overwrite each other's entries.
   There is intentionally NO endpoint that edits or deletes log entries.
   Plain PINs, the master password and session tokens are never written here.  */
const CAT = {
  login_ok: "auth", login_fail: "auth", login_locked: "auth", session_open: "auth",
  incident_added: "incident", incident_removed: "incident", incident_modified: "incident",
  employee_added: "employee", employee_removed: "employee", employee_modified: "employee",
  pin_created: "pin", pin_reset: "pin", pin_removed: "pin",
  lead_added: "access", lead_removed: "access", employee_access_on: "access", employee_access_off: "access",
  data_read: "view", export: "export"
};
async function audit(store, actor, action, detail, ip) {
  try {
    const now = new Date();
    const key = "log-" + now.toISOString().replace(/[-:.]/g, "") + "-" + crypto.randomBytes(3).toString("hex");
    await store.setJSON(key, {
      ts: now.toISOString(),
      actor: { role: (actor && actor.role) || "unknown", name: String((actor && actor.name) || "").slice(0, 100) },
      action, cat: CAT[action] || "other",
      detail: String(detail || "").slice(0, 600), ip: String(ip || "").slice(0, 64)
    });
  } catch (e) { console.error("audit write failed", e); }   // logging must never break the request itself
}
const auditMany = (store, actor, ip, items) => Promise.all(items.map((i) => audit(store, actor, i.action, i.detail, ip)));

const short = (v, n = 60) => { v = String(v ?? "").replace(/\s+/g, " ").trim(); return v.length > n ? v.slice(0, n - 1) + "…" : v; };
const last4 = (p) => "…" + String(p || "").replace(/\D/g, "").slice(-4);
const leadLabel = (l) => (l.name ? l.name + " " : "") + "(" + last4(l.phone) + ")";
const empLabel = (roster, id) => { const e = roster.find((x) => x.id === id); return e ? `${e.name} (${e.empId})` : String(id); };

const INC_FIELDS = ["incidentId", "employeeId", "date", "description", "effect", "instanceCount", "business", "process", "team"];
const EMP_FIELDS = ["name", "empId", "reportingManager"];
function diffById(oldArr, newArr, fields) {
  const om = new Map(oldArr.map((x) => [x && x.id, x])), nm = new Map(newArr.map((x) => [x && x.id, x]));
  const added = [], removed = [], changed = [];
  for (const [id, n] of nm) {
    if (!om.has(id)) { added.push(n); continue; }
    const o = om.get(id);
    const diffs = fields.filter((f) => JSON.stringify(o[f] ?? null) !== JSON.stringify(n[f] ?? null))
      .map((f) => `${f}: "${short(o[f], 40)}" → "${short(n[f], 40)}"`);
    if (diffs.length) changed.push({ item: n, diffs });
  }
  for (const [id, o] of om) if (!nm.has(id)) removed.push(o);
  return { added, removed, changed };
}
function describeIncident(i, roster) {
  const impacts = ["business", "process", "team"].filter((k) => i[k]).map((k) => k[0].toUpperCase() + k.slice(1)).join("+") || "no impact";
  return `${i.incidentId || i.id} · ${empLabel(roster, i.employeeId)} · ${i.effect} · ${impacts} · instance ${i.instanceCount || 1} · "${short(i.description, 70)}"`;
}
function diffIncidents(oldArr, newArr, roster) {
  const d = diffById(oldArr, newArr, INC_FIELDS);
  return [
    ...d.added.map((i) => ({ action: "incident_added", detail: describeIncident(i, roster) })),
    ...d.removed.map((i) => ({ action: "incident_removed", detail: describeIncident(i, roster) })),
    ...d.changed.map((c) => ({ action: "incident_modified", detail: `${c.item.incidentId || c.item.id} · ${empLabel(roster, c.item.employeeId)} — ${c.diffs.join("; ")}` }))
  ];
}
function diffEmployees(oldArr, newArr) {
  const d = diffById(oldArr, newArr, EMP_FIELDS);
  const lbl = (e) => `${e.name} (${e.empId}) · manager ${e.reportingManager || "—"}`;
  return [
    ...d.added.map((e) => ({ action: "employee_added", detail: lbl(e) })),
    ...d.removed.map((e) => ({ action: "employee_removed", detail: lbl(e) })),
    ...d.changed.map((c) => ({ action: "employee_modified", detail: `${c.item.name} (${c.item.empId}) — ${c.diffs.join("; ")}` }))
  ];
}
function diffAccess(oldA, newA, roster) {
  const items = [];
  const oldLeads = new Map(oldA.leads.map((l) => [l.id, l])), newLeads = new Map(newA.leads.map((l) => [l.id, l]));
  for (const [id, l] of newLeads) if (!oldLeads.has(id)) items.push({ action: "lead_added", detail: leadLabel(l) });
  for (const [id, l] of oldLeads) if (!newLeads.has(id)) items.push({ action: "lead_removed", detail: leadLabel(l) });
  const was = new Set(oldA.enabledEmployees), now = new Set(newA.enabledEmployees);
  const known = new Set(roster.map((e) => e.id));
  for (const id of now) if (!was.has(id) && known.has(id)) items.push({ action: "employee_access_on", detail: empLabel(roster, id) });
  for (const id of was) if (!now.has(id) && known.has(id)) items.push({ action: "employee_access_off", detail: empLabel(roster, id) });
  return items;
}

/* -------- brute-force protection (per IP AND per account, in the same blob store) -------- */
const rlKey = (kind, id) => "rl-" + kind + "-" + String(id || "unknown").replace(/[^a-zA-Z0-9]/g, "_");
const acctKey = (raw) => rlKey("acct", sha(raw).toString("hex").slice(0, 32));
async function isLockedOut(store, key, max) {
  const rec = await store.get(key, { type: "json" });
  return !!rec && rec.count >= max && Date.now() - rec.first < LOCKOUT_WINDOW_MS;
}
async function recordFailure(store, key) {
  const rec = await store.get(key, { type: "json" });
  const fresh = !rec || Date.now() - rec.first >= LOCKOUT_WINDOW_MS;
  const next = fresh ? { count: 1, first: Date.now() } : { count: rec.count + 1, first: rec.first };
  await store.setJSON(key, next);
  return next.count;
}
const clearFailures = (store, key) => store.delete(key).catch(() => {});

/* --------------------------------- login --------------------------------- */
async function handleLogin(req, store, ip) {
  const cfg = configError();
  if (cfg) return json(503, { error: cfg });
  const ipKey = rlKey("ip", ip);
  const LOCKED = json(429, { error: "Too many failed attempts. Please wait 15 minutes and try again." });
  if (await isLockedOut(store, ipKey, MAX_FAILED_PER_IP)) return LOCKED;

  let body;
  try { body = await req.json(); } catch { return json(400, { error: "invalid request" }); }
  const mode = body && body.mode;
  const value = String((body && body.value) ?? "").trim().slice(0, 200);
  const pin = String((body && body.pin) ?? "").trim().slice(0, 20);
  if (!value) return json(400, { error: "Please enter a value." });

  const mask = (v) => { const c = v.replace(/[\s().+\-]/g, ""); return /^\d{10,15}$/.test(c) ? "phone " + last4(c) : "ID “" + v.slice(0, 30) + "”"; };
  const who = mode === "master" ? "Master password" : mask(value);
  const deny = async (aKey, aMax, reason) => {
    const ci = await recordFailure(store, ipKey);
    const ca = aKey ? await recordFailure(store, aKey) : 0;
    await audit(store, { role: "unknown", name: "" }, "login_fail", `${who} — ${reason}`, ip);
    if (aKey && ca === aMax) await audit(store, { role: "unknown", name: "" }, "login_locked", `${who} locked for 15 minutes after ${aMax} failed attempts`, ip);
    if (ci === MAX_FAILED_PER_IP) await audit(store, { role: "unknown", name: "" }, "login_locked", `This IP address locked for 15 minutes after ${MAX_FAILED_PER_IP} failed attempts`, ip);
    return json(401, { error: mode === "master" ? "Incorrect password." : "Phone / Employee ID or PIN not recognised. If you think this is a mistake, contact your manager." });
  };
  const ok = async (payload, extra, aKey, actor) => {
    await clearFailures(store, ipKey);
    if (aKey) await clearFailures(store, aKey);
    await audit(store, actor, "login_ok", who, ip);
    return json(200, { token: signToken({ ...payload, exp: Date.now() + SESSION_TTL_MS }), ...extra });
  };

  if (mode === "master") {
    const mKey = rlKey("acct", "master");
    if (await isLockedOut(store, mKey, MAX_FAILED_MASTER)) return LOCKED;
    return safeEqual(value, MASTER_PASSWORD)
      ? ok({ r: "master" }, { role: "master" }, mKey, { role: "master", name: "Master" })
      : deny(mKey, MAX_FAILED_MASTER, "wrong password");
  }

  if (mode === "access") {
    const compact = value.replace(/[\s().+\-]/g, "");
    const isPhone = /^\d{10,15}$/.test(compact);
    const aKey = acctKey(isPhone ? "p:" + last10(compact) : "e:" + normId(value));
    if (await isLockedOut(store, aKey, MAX_FAILED_PER_ACCOUNT)) return LOCKED;

    const access = await getAccess(store);
    const creds = await getCreds(store);
    let bucket = null, subject = null;
    if (isPhone) {                                            // phone number -> lead
      subject = access.leads.find((l) => last10(l.phone) === last10(compact)) || null;
      bucket = "leads";
    } else {                                                  // otherwise -> Employee ID
      const wanted = normId(value);
      if (wanted) {
        subject = (await getEmployees(store)).find(
          (e) => normId(e.empId) === wanted && access.enabledEmployees.includes(e.id)
        ) || null;
      }
      bucket = "employees";
    }
    const cred = subject ? creds[bucket][subject.id] || null : null;
    const pinOk = await checkPin(pin, cred);                  // runs even when there is no such account
    if (!subject) return deny(aKey, MAX_FAILED_PER_ACCOUNT, "unknown or disabled account");
    if (!cred) return deny(aKey, MAX_FAILED_PER_ACCOUNT, "account has no PIN yet");
    if (!pinOk) return deny(aKey, MAX_FAILED_PER_ACCOUNT, "wrong PIN for " + (bucket === "leads" ? leadLabel(subject) : empLabel([subject], subject.id)));
    return bucket === "leads"
      ? ok({ r: "lead", s: subject.id, c: cred.ver }, { role: "lead" }, aKey, { role: "lead", name: subject.name || "" })
      : ok({ r: "employee", s: subject.id, c: cred.ver }, { role: "employee" }, aKey, { role: "employee", name: subject.name });
  }
  return json(400, { error: "invalid request" });
}

/* ------------------------------ main handler ------------------------------ */
export function createHandler(getStoreFn) {
  return async (req, context) => {
    const url = new URL(req.url);
    const action = url.searchParams.get("action") || "data";
    const store = getStoreFn("appraisal-tracker");
    const ip = (context && context.ip) || req.headers.get("x-nf-client-connection-ip") || "unknown";

    if (action === "login") {
      if (req.method !== "POST") return json(405, { error: "method not allowed" });
      return handleLogin(req, store, ip);
    }

    const session = await authenticate(req, store);
    if (!session) return json(401, { error: "unauthorized" });
    const actor = { role: session.role, name: session.role === "master" ? "Master" : session.name || "" };

    /* The tool itself is only ever sent to a signed-in browser. */
    if (action === "app") {
      await audit(store, actor, "session_open", "Opened the tool", ip);
      const safe = JSON.stringify({ role: session.role, name: session.name || "" }).replace(/</g, "\\u003c");
      return new Response(APP_HTML.replace("__AR_SESSION__", () => safe), {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex" }
      });
    }

    /* Master issues (or resets) PINs. The plain PIN is returned ONCE and never stored. */
    if (action === "setpin") {
      if (req.method !== "POST") return json(405, { error: "method not allowed" });
      if (session.role !== "master") return json(403, { error: "forbidden" });
      let b;
      try { b = await req.json(); } catch { return json(400, { error: "invalid JSON body" }); }
      const bucket = b && b.kind === "lead" ? "leads" : b && b.kind === "employee" ? "employees" : null;
      const ids = Array.isArray(b && b.ids) ? b.ids.map((x) => String(x)).slice(0, 500) : [];
      if (!bucket || !ids.length) return json(400, { error: "invalid request" });
      const leadsNow = (await getAccess(store)).leads, roster = await getEmployees(store);
      const valid = new Set(bucket === "leads" ? leadsNow.map((l) => l.id) : roster.map((e) => e.id));
      const creds = await getCreds(store);
      const pins = [], events = [];
      for (const id of ids) {
        if (!valid.has(id)) continue;
        const existed = !!creds[bucket][id];
        const pin = newPin();
        creds[bucket][id] = await makeCred(pin);
        pins.push({ id, pin });
        const label = bucket === "leads" ? "lead " + leadLabel(leadsNow.find((l) => l.id === id)) : empLabel(roster, id);
        events.push({ action: existed ? "pin_reset" : "pin_created", detail: label });   // never the PIN itself
      }
      await store.setJSON("creds", creds);
      await auditMany(store, actor, ip, events);
      return json(200, { pins });
    }

    /* Browser-side CSV downloads report themselves here so exports show up in the log. */
    if (action === "audit") {
      if (req.method !== "POST") return json(405, { error: "method not allowed" });
      let b;
      try { b = await req.json(); } catch { return json(400, { error: "invalid JSON body" }); }
      const EVENTS = {
        export_summary: "Downloaded the employee summary as CSV",
        export_incidents: "Downloaded the incident log as CSV",
        export_pins: "Downloaded a PIN sheet as CSV (PIN values are not logged)",
        export_activity_log: "Downloaded the activity log as CSV"
      };
      const ev = String((b && b.event) || "");
      if (!EVENTS[ev]) return json(400, { error: "unknown event" });
      if ((ev === "export_pins" || ev === "export_activity_log") && session.role !== "master") return json(403, { error: "forbidden" });
      const rows = Math.max(0, Math.min(1e6, parseInt(b && b.rows, 10) || 0));
      await audit(store, actor, "export", `${EVENTS[ev]} — ${rows} row(s)`, ip);
      return json(200, { ok: true });
    }

    /* Master reads the activity log, newest first, in pages. */
    if (action === "log") {
      if (session.role !== "master") return json(403, { error: "forbidden" });
      const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit"), 10) || 200, 1), 500);
      const before = url.searchParams.get("before") || "";
      const listing = await store.list({ prefix: "log-" });
      const keys = (listing.blobs || []).map((b) => b.key).sort().reverse().filter((k) => !before || k < before);
      const page = keys.slice(0, limit);
      const entries = [];
      for (let i = 0; i < page.length; i += 25) {
        const chunk = await Promise.all(page.slice(i, i + 25).map(async (k) => {
          const v = await store.get(k, { type: "json" });
          return v ? { key: k, ...v } : null;
        }));
        entries.push(...chunk.filter(Boolean));
      }
      return json(200, { entries, next: keys.length > limit ? page[page.length - 1] : null, remaining: Math.max(0, keys.length - page.length) });
    }

    if (action !== "data") return json(400, { error: "unknown action" });

    const key = url.searchParams.get("key");
    const isData = DATA_KEYS.has(key);
    if (!isData && key !== "access") return json(400, { error: "invalid or missing key" });
    const canEdit = session.role === "master" || session.role === "lead";

    if (req.method === "GET") {
      if (key === "access") {
        if (session.role !== "master") return json(403, { error: "forbidden" });
        const acc = await getAccess(store);
        const creds = await getCreds(store);
        await audit(store, actor, "data_read", "Viewed access settings", ip);
        return json(200, { value: {
          leads: acc.leads.map((l) => ({ ...l, hasPin: !!creds.leads[l.id] })),
          enabledEmployees: acc.enabledEmployees,
          pinnedEmployees: Object.keys(creds.employees)
        } });
      }
      if (key === "employees") {
        const all = await getEmployees(store);
        const out = canEdit ? all : all.filter((e) => e.id === session.sub);
        await audit(store, actor, "data_read", `Loaded employees — ${out.length} row(s)`, ip);
        return json(200, { value: out });
      }
      const inc = (await store.get("incidents", { type: "json" })) || [];
      const out = canEdit ? inc : inc.filter((i) => i.employeeId === session.sub);
      await audit(store, actor, "data_read", `Loaded incidents — ${out.length} row(s)`, ip);
      return json(200, { value: out });
    }

    if (req.method === "POST") {
      if (key === "access" ? session.role !== "master" : !canEdit) return json(403, { error: "forbidden" });
      let body;
      try { body = await req.json(); } catch { return json(400, { error: "invalid JSON body" }); }
      let value = body && body.value;
      if (isData) {
        if (!Array.isArray(value)) return json(400, { error: "expected an array" });
      } else {
        const str = (v, n) => String(v ?? "").slice(0, n);
        value = {
          leads: (Array.isArray(value && value.leads) ? value.leads : []).slice(0, 200).map((l) => ({
            id: str(l.id, 60), name: str(l.name, 100), phone: str(l.phone, 30), addedAt: str(l.addedAt, 40)
          })).filter((l) => l.id && last10(l.phone).length === 10),
          enabledEmployees: (Array.isArray(value && value.enabledEmployees) ? value.enabledEmployees : [])
            .slice(0, 5000).map((s) => str(s, 60)).filter(Boolean)
        };
      }
      /* Read what is stored now so every add / remove / change can be logged. */
      const roster = await getEmployees(store);
      const before = key === "access" ? await getAccess(store)
        : key === "employees" ? roster
        : (await store.get("incidents", { type: "json" })) || [];
      await store.setJSON(key, value);
      const events = key === "access" ? diffAccess(before, value, roster)
        : key === "employees" ? diffEmployees(before, value)
        : diffIncidents(before, value, roster);
      if (key === "access") {                       // a removed lead's PIN is deleted with them
        const creds = await getCreds(store);
        const keep = new Set(value.leads.map((l) => l.id));
        const gone = Object.keys(creds.leads).filter((id) => !keep.has(id));
        if (gone.length) {
          gone.forEach((id) => {
            delete creds.leads[id];
            const l = before.leads.find((x) => x.id === id);
            events.push({ action: "pin_removed", detail: "lead " + (l ? leadLabel(l) : id) + " (removed with the lead)" });
          });
          await store.setJSON("creds", creds);
        }
      }
      await auditMany(store, actor, ip, events);
      return json(200, { ok: true });
    }
    return json(405, { error: "method not allowed" });
  };
}

export default createHandler(getStore);
