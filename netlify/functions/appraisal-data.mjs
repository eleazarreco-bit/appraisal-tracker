import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import APP_HTML from "../lib/app-ui.mjs";

/* ------------------------------------------------------------------
   Configuration
   Set these in Netlify → Site configuration → Environment variables.
   The fallbacks below only exist so the site works before you do.
   ------------------------------------------------------------------ */
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || "08b21a0556";
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.createHash("sha256").update("appraisal-tracker-session::" + MASTER_PASSWORD).digest("hex");

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;   // sessions last 12 hours
const MAX_FAILED_LOGINS = 8;                   // per IP…
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;      // …within 15 minutes

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
  const h = req.headers.get("authorization") || "";
  const p = readToken(h.startsWith("Bearer ") ? h.slice(7) : "");
  if (!p) return null;
  if (p.r === "master") return { role: "master" };
  const access = await getAccess(store);
  if (p.r === "lead") {
    const lead = access.leads.find((l) => l.id === p.s);
    return lead ? { role: "lead", name: lead.name || "" } : null;
  }
  if (p.r === "employee") {
    if (!access.enabledEmployees.includes(p.s)) return null;
    const emp = (await getEmployees(store)).find((e) => e.id === p.s);
    return emp ? { role: "employee", sub: emp.id, name: emp.name } : null;
  }
  return null;
}

/* -------- brute-force protection (per IP, stored in the same blob store) -------- */
const rlKey = (ip) => "rl-" + String(ip || "unknown").replace(/[^a-zA-Z0-9]/g, "_");
async function isLockedOut(store, ip) {
  const rec = await store.get(rlKey(ip), { type: "json" });
  return !!rec && rec.count >= MAX_FAILED_LOGINS && Date.now() - rec.first < LOCKOUT_WINDOW_MS;
}
async function recordFailure(store, ip) {
  const rec = await store.get(rlKey(ip), { type: "json" });
  const fresh = !rec || Date.now() - rec.first >= LOCKOUT_WINDOW_MS;
  await store.setJSON(rlKey(ip), fresh ? { count: 1, first: Date.now() } : { count: rec.count + 1, first: rec.first });
}
const clearFailures = (store, ip) => store.delete(rlKey(ip)).catch(() => {});

/* --------------------------------- login --------------------------------- */
async function handleLogin(req, store, ip) {
  if (await isLockedOut(store, ip)) {
    return json(429, { error: "Too many failed attempts. Please wait 15 minutes and try again." });
  }
  let body;
  try { body = await req.json(); } catch { return json(400, { error: "invalid request" }); }
  const mode = body && body.mode;
  const value = String((body && body.value) ?? "").trim().slice(0, 200);
  const deny = async () => {
    await recordFailure(store, ip);
    return json(401, { error: mode === "master" ? "Incorrect password." : "Access not recognised. If you think this is a mistake, contact your manager." });
  };
  const ok = async (payload, extra) => {
    await clearFailures(store, ip);
    return json(200, { token: signToken({ ...payload, exp: Date.now() + SESSION_TTL_MS }), ...extra });
  };

  if (!value) return json(400, { error: "Please enter a value." });

  if (mode === "master") {
    return safeEqual(value, MASTER_PASSWORD) ? ok({ r: "master" }, { role: "master" }) : deny();
  }

  if (mode === "access") {
    const access = await getAccess(store);
    const compact = value.replace(/[\s().+\-]/g, "");
    if (/^\d{10,15}$/.test(compact)) {                       // phone number → lead
      const lead = access.leads.find((l) => last10(l.phone) === last10(compact));
      return lead ? ok({ r: "lead", s: lead.id }, { role: "lead" }) : deny();
    }
    const wanted = normId(value);                            // otherwise → Employee ID
    if (wanted) {
      const emp = (await getEmployees(store)).find(
        (e) => normId(e.empId) === wanted && access.enabledEmployees.includes(e.id)
      );
      if (emp) return ok({ r: "employee", s: emp.id }, { role: "employee" });
    }
    return deny();
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

    /* The tool itself is only ever sent to a signed-in browser. */
    if (action === "app") {
      const safe = JSON.stringify({ role: session.role, name: session.name || "" }).replace(/</g, "\\u003c");
      return new Response(APP_HTML.replace("__AR_SESSION__", () => safe), {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex" }
      });
    }

    if (action !== "data") return json(400, { error: "unknown action" });

    const key = url.searchParams.get("key");
    const isData = DATA_KEYS.has(key);
    if (!isData && key !== "access") return json(400, { error: "invalid or missing key" });
    const canEdit = session.role === "master" || session.role === "lead";

    if (req.method === "GET") {
      if (key === "access") {
        if (session.role !== "master") return json(403, { error: "forbidden" });
        return json(200, { value: await getAccess(store) });
      }
      if (key === "employees") {
        const all = await getEmployees(store);
        return json(200, { value: canEdit ? all : all.filter((e) => e.id === session.sub) });
      }
      const inc = (await store.get("incidents", { type: "json" })) || [];
      return json(200, { value: canEdit ? inc : inc.filter((i) => i.employeeId === session.sub) });
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
      await store.setJSON(key, value);
      return json(200, { ok: true });
    }
    return json(405, { error: "method not allowed" });
  };
}

export default createHandler(getStore);
