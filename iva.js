const express = require("express");
const https   = require("https");
const zlib    = require("zlib");

const router = express.Router();

/* ================= CONFIG ================= */
const BASE_URL  = "https://www.ivasms.com";
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36";

/* ================= COOKIES ================= */
let COOKIES = {
  "cf_clearance":     process.env.CF       || "",
  "XSRF-TOKEN":       process.env.XSRF     || "",
  "ivas_sms_session": process.env.SESSION  || ""
};

let otpHistory = [];

/* ================= HELPERS ================= */
function getToday() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;
}

function getDateRange() {
  const today     = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  const fmt = d =>
    `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;
  return { start: fmt(yesterday), end: fmt(today) };
}

function cookieString() {
  return `cf_clearance=${COOKIES["cf_clearance"]}; XSRF-TOKEN=${COOKIES["XSRF-TOKEN"]}; ivas_sms_session=${COOKIES["ivas_sms_session"]}`;
}

function getXsrf() {
  try { return decodeURIComponent(COOKIES["XSRF-TOKEN"]); }
  catch { return COOKIES["XSRF-TOKEN"]; }
}

function safeJSON(text) {
  try { return JSON.parse(text); }
  catch { return { error: "Invalid JSON", preview: text.substring(0, 300) }; }
}

function clean(text) {
  return (text || "")
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&").replace(/&#039;/g, "'")
    .replace(/\s+/g, " ").trim();
}

function extractOTP(message) {
  const match = message.match(/\b\d{4,8}\b/);
  return match ? match[0] : null;
}

/* ================= HTTP REQUEST ================= */
function makeRequest(method, path, body, contentType, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const headers = {
      "User-Agent":       USER_AGENT,
      "Accept":           "*/*",
      "Accept-Encoding":  "gzip, deflate, br",
      "Accept-Language":  "en-US,en;q=0.9",
      "Cookie":           cookieString(),
      "X-Requested-With": "XMLHttpRequest",
      "X-XSRF-TOKEN":     getXsrf(),
      "X-CSRF-TOKEN":     getXsrf(),
      "Origin":           BASE_URL,
      "Referer":          `${BASE_URL}/portal`,
      ...extraHeaders
    };

    if (method === "POST" && body) {
      headers["Content-Type"]   = contentType;
      headers["Content-Length"] = Buffer.byteLength(body);
    }

    const req = https.request(BASE_URL + path, { method, headers }, res => {
      // Auto-update cookies from response
      if (res.headers["set-cookie"]) {
        res.headers["set-cookie"].forEach(c => {
          const sc = c.split(";")[0];
          const ki = sc.indexOf("=");
          if (ki > -1) {
            const k = sc.substring(0, ki).trim();
            const v = sc.substring(ki + 1).trim();
            if (["XSRF-TOKEN", "ivas_sms_session", "cf_clearance"].includes(k)) {
              COOKIES[k] = v;
            }
          }
        });
      }

      let chunks = [];
      res.on("data", d => chunks.push(d));
      res.on("end", () => {
        let buf = Buffer.concat(chunks);
        try {
          const enc = res.headers["content-encoding"];
          if (enc === "gzip") buf = zlib.gunzipSync(buf);
          else if (enc === "br") buf = zlib.brotliDecompressSync(buf);
        } catch {}

        const text = buf.toString("utf-8");

        if (res.statusCode === 401 || res.statusCode === 419 ||
            text.includes('"message":"Unauthenticated"')) {
          return reject(new Error("SESSION_EXPIRED"));
        }

        resolve({ status: res.statusCode, body: text });
      });
    });

    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

/* ================= FETCH _token ================= */
async function fetchToken() {
  const resp = await makeRequest("GET", "/portal", null, null, {
    "Accept":         "text/html,application/xhtml+xml,*/*",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin"
  });
  const match = resp.body.match(/name="_token"\s+value="([^"]+)"/) ||
                resp.body.match(/"csrf-token"\s+content="([^"]+)"/);
  return match ? match[1] : null;
}

/* ================= GET NUMBERS ================= */
async function getNumbers(token) {
  const ts   = Date.now();
  const path = `/portal/numbers?draw=1`
    + `&columns[0][data]=number_id&columns[0][name]=id&columns[0][orderable]=false`
    + `&columns[1][data]=Number`
    + `&columns[2][data]=range`
    + `&columns[3][data]=A2P`
    + `&columns[4][data]=LimitA2P`
    + `&columns[5][data]=limit_cli_a2p`
    + `&columns[6][data]=limit_cli_did_a2p`
    + `&columns[7][data]=action&columns[7][searchable]=false&columns[7][orderable]=false`
    + `&order[0][column]=1&order[0][dir]=desc`
    + `&start=0&length=5000&search[value]=&_=${ts}`;

  const resp = await makeRequest("GET", path, null, null, {
    "Referer": `${BASE_URL}/portal/numbers`,
    "Accept":  "application/json, text/javascript, */*; q=0.01",
    "X-CSRF-TOKEN": token
  });

  const json = safeJSON(resp.body);
  return fixNumbers(json);
}

function fixNumbers(json) {
  if (!json || !json.data) return json;
  const aaData = json.data.map(row => [
    row.range  || "",
    "",
    String(row.Number || ""),
    "Weekly",
    ""
  ]);
  return {
    sEcho:                2,
    iTotalRecords:        String(json.recordsTotal || aaData.length),
    iTotalDisplayRecords: String(json.recordsFiltered || aaData.length),
    aaData
  };
}

/* ================= GET SMS ================= */
async function getSMS(token) {
  const { start, end } = getDateRange();
  const boundary = "----WebKitFormBoundary6I2Js7TBhcJuwIqw";

  const parts = [
    `--${boundary}\r\nContent-Disposition: form-data; name="from"\r\n\r\n${start}`,
    `--${boundary}\r\nContent-Disposition: form-data; name="to"\r\n\r\n${end}`,
    `--${boundary}\r\nContent-Disposition: form-data; name="_token"\r\n\r\n${token}`,
    `--${boundary}--`
  ].join("\r\n");

  // Step 1: Get ranges
  const r1 = await makeRequest(
    "POST", "/portal/sms/received/getsms", parts,
    `multipart/form-data; boundary=${boundary}`,
    { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01" }
  );

  const ranges = [...r1.body.matchAll(/toggleRange\('([^']+)'/g)].map(m => m[1]);
  console.log(`[IVAS] Ranges: ${ranges.join(", ")}`);

  if (ranges.length === 0) {
    return { sEcho: 1, iTotalRecords: "0", iTotalDisplayRecords: "0", aaData: [] };
  }

  const allRows = [];

  for (const range of ranges) {
    // Step 2: Get numbers per range
    const b2 = new URLSearchParams({ _token: token, start, end, range }).toString();
    const r2  = await makeRequest(
      "POST", "/portal/sms/received/getsms/number", b2,
      "application/x-www-form-urlencoded",
      { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01" }
    ).catch(() => null);

    if (!r2) continue;

    const numbers = [...r2.body.matchAll(/toggleNum[^(]+\('(\d+)'/g)].map(m => m[1]);
    console.log(`[IVAS] ${range} → numbers: ${numbers.join(", ")}`);

    for (const number of numbers) {
      // Step 3: Get SMS per number
      const b3 = new URLSearchParams({ _token: token, start, end, Number: number, Range: range }).toString();
      const r3  = await makeRequest(
        "POST", "/portal/sms/received/getsms/number/sms", b3,
        "application/x-www-form-urlencoded",
        { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01" }
      ).catch(() => null);

      if (!r3) continue;

      const msgs = parseSMSMessages(r3.body, range, number, end);
      allRows.push(...msgs);
    }
  }

  return {
    sEcho:                1,
    iTotalRecords:        String(allRows.length),
    iTotalDisplayRecords: String(allRows.length),
    aaData:               allRows
  };
}

function parseSMSMessages(html, range, number, date) {
  const rows = [];
  const trAll = [...html.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)];

  for (const trM of trAll) {
    const row = trM[1];
    if (row.includes("<th")) continue;

    const senderM = row.match(/class="cli-tag"[^>]*>([^<]+)</);
    const sender  = senderM ? senderM[1].trim() : "SMS";

    const msgM    = row.match(/class="msg-text"[^>]*>([\s\S]*?)<\/div>/i);
    const message = msgM ? clean(msgM[1]) : "";

    const timeM = row.match(/class="time-cell"[^>]*>\s*([0-9:]+)\s*</);
    const time  = timeM ? timeM[1].trim() : "00:00:00";

    if (message) {
      rows.push([`${date} ${time}`, range, number, sender, message, "$", 0]);
    }
  }

  return rows;
}

/* ================= ROUTES ================= */

// Main API
router.get("/", async (req, res) => {
  const { type } = req.query;
  if (!type) return res.json({ error: "Use ?type=numbers or ?type=sms" });

  try {
    const token = await fetchToken();
    if (!token) {
      return res.status(401).json({ error: "Session expired — update cookies" });
    }

    if (type === "numbers") return res.json(await getNumbers(token));
    if (type === "sms")     return res.json(await getSMS(token));

    res.json({ error: "Invalid type. Use numbers or sms" });

  } catch (err) {
    if (err.message === "SESSION_EXPIRED") {
      return res.status(401).json({ error: "Session expired — update cookies" });
    }
    res.status(500).json({ error: err.message });
  }
});

// OTP history endpoint
router.get("/otp", async (req, res) => {
  try {
    const token = await fetchToken();
    const { start, end } = getDateRange();
    const boundary = "----WebKitFormBoundary6I2Js7TBhcJuwIqw";

    const parts = [
      `--${boundary}\r\nContent-Disposition: form-data; name="from"\r\n\r\n${start}`,
      `--${boundary}\r\nContent-Disposition: form-data; name="to"\r\n\r\n${end}`,
      `--${boundary}\r\nContent-Disposition: form-data; name="_token"\r\n\r\n${token}`,
      `--${boundary}--`
    ].join("\r\n");

    const r1 = await makeRequest(
      "POST", "/portal/sms/received/getsms", parts,
      `multipart/form-data; boundary=${boundary}`,
      { "Referer": `${BASE_URL}/portal/sms/received` }
    );

    const ranges = [...r1.body.matchAll(/toggleRange\('([^']+)'/g)].map(m => m[1]);
    if (!ranges.length) return res.json({ error: "No ranges found" });

    for (const range of ranges) {
      const r2 = await makeRequest(
        "POST", "/portal/sms/received/getsms/number",
        new URLSearchParams({ _token: token, start, end, range }).toString(),
        "application/x-www-form-urlencoded"
      );

      const numbers = [...r2.body.matchAll(/toggleNum[^(]+\('(\d+)'/g)].map(m => m[1]);

      for (const number of numbers) {
        const r3 = await makeRequest(
          "POST", "/portal/sms/received/getsms/number/sms",
          new URLSearchParams({ _token: token, start, end, Number: number, Range: range }).toString(),
          "application/x-www-form-urlencoded"
        );

        const rows = [...r3.body.matchAll(/class="msg-text"[^>]*>([\s\S]*?)<\/div>/gi)];
        for (const m of rows) {
          const msg = clean(m[1]);
          const otp = extractOTP(msg);
          if (otp && !otpHistory.find(e => e.otp === otp && e.number === number)) {
            otpHistory.unshift({ number, otp, range, time: new Date().toLocaleTimeString() });
          }
        }
      }
    }

    if (otpHistory.length > 30) otpHistory = otpHistory.slice(0, 30);
    res.json({ history: otpHistory });

  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Update cookies via GET (simple, pakai key)
router.get("/set-cookie", (req, res) => {
  const { xsrf, session, cf, key } = req.query;

  if (key !== "oklogin123") {
    return res.status(403).json({ error: "Unauthorized" });
  }
  if (!xsrf || !session) {
    return res.status(400).json({ error: "Missing xsrf or session" });
  }

  COOKIES["XSRF-TOKEN"]       = xsrf;
  COOKIES["ivas_sms_session"] = session;
  if (cf) COOKIES["cf_clearance"] = cf;

  console.log("✅ [IVAS] Cookies updated via set-cookie");
  res.json({
    status: "✅ Cookies updated",
    cf_set: !!cf,
    keys:   Object.keys(COOKIES)
  });
});

// Update cookies via POST (JSON body)
router.post("/update-session", express.json(), (req, res) => {
  const { xsrf, session, cf } = req.body || {};
  if (!xsrf || !session) {
    return res.status(400).json({
      error: "Required: xsrf and session",
      example: { xsrf: "...", session: "...", cf: "... (optional)" }
    });
  }
  COOKIES["XSRF-TOKEN"]       = xsrf;
  COOKIES["ivas_sms_session"] = session;
  if (cf) COOKIES["cf_clearance"] = cf;

  console.log("✅ [IVAS] Cookies updated via update-session");
  res.json({ success: true, message: "Cookies updated!", cf_set: !!cf });
});

// Status
router.get("/status", async (req, res) => {
  try {
    const token = await fetchToken();
    res.json({
      status:     token ? "✅ Session active" : "❌ Session expired",
      hasToken:   !!token,
      cookieKeys: Object.keys(COOKIES),
      cf_set:     !!COOKIES["cf_clearance"]
    });
  } catch (e) {
    res.json({ status: "❌ Session expired", error: e.message });
  }
});

module.exports = router;
