import { getStore } from "@netlify/blobs";

const ALLOWED_KEYS = new Set(["employees", "incidents", "dataVersion"]);

export default async (req) => {
  const url = new URL(req.url);
  const key = url.searchParams.get("key");

  if (!key || !ALLOWED_KEYS.has(key)) {
    return new Response(JSON.stringify({ error: "invalid or missing key" }), {
      status: 400,
      headers: { "content-type": "application/json" }
    });
  }

  const store = getStore("appraisal-tracker");

  if (req.method === "GET") {
    const value = await store.get(key, { type: "json" });
    return new Response(JSON.stringify({ value: value ?? null }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  }

  if (req.method === "POST") {
    let body;
    try {
      body = await req.json();
    } catch (err) {
      return new Response(JSON.stringify({ error: "invalid JSON body" }), {
        status: 400,
        headers: { "content-type": "application/json" }
      });
    }
    await store.setJSON(key, body.value ?? null);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  }

  return new Response(JSON.stringify({ error: "method not allowed" }), {
    status: 405,
    headers: { "content-type": "application/json" }
  });
};
