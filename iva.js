const express = require("express");
const fs = require("fs");
const https   = require("https");
const zlib    = require("zlib");
let otpHistory = [];
let seenOTPs = new Set();
let history = [];
let COOKIES = {
  "XSRF-TOKEN": process.env.XSRF || "",
  "ivas_sms_session": process.env.SESSION || ""
};
const router = express.Router();

/* ================= CONFIG ================= */
const BASE_URL       = "https://www.ivasms.com";
const TERMINATION_ID = "1029603"
const USER_AGENT     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36";

/* ================= COOKIES (Update when expired) ================= */


/* ================= HELPERS ================= */
function getToday() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;
}

function getDateRange() {
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);

  const format = (d) =>
    `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;

  return {
    start: format(yesterday),
    end: format(today)
  };
}



function cookieString() {
  return `XSRF-TOKEN=${COOKIES["XSRF-TOKEN"]}; ivas_sms_session=${COOKIES["ivas_sms_session"]}`;
}

function getXsrf() {
  return COOKIES["XSRF-TOKEN"];
}

function safeJSON(text) {
  try { return JSON.parse(text); }
  catch { return { error: "Invalid JSON", preview: text.substring(0, 300) }; }
}

/* ================= HTTP REQUEST ================= */
function makeRequest(method, path, body, contentType, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const headers = {
      "User-Agent":       USER_AGENT,
      "Accept":           "*/*",
      "Accept-Encoding":  "gzip, deflate, br",
      "Accept-Language":  "en-PK,en;q=0.9",
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
            if (k === "XSRF-TOKEN" || k === "ivas_sms_session") {
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




/* ================= FETCH _token FROM PORTAL ================= */
async function fetchToken() {
  const resp = await makeRequest("GET", "/portal", null, null, {
    "Accept": "text/html,application/xhtml+xml,*/*"
  });
  const match = resp.body.match(/name="_token"\s+value="([^"]+)"/) ||
                resp.body.match(/"csrf-token"\s+content="([^"]+)"/);
  return match ? match[1] : null;
}

/* ================= PARSE HTML HELPERS ================= */
function stripHTML(html) {
  return (html || "").replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
}

function parseNumbersHTML(html) {
  const results = [];
  // Extract range names
  const rangeMatches = html.matchAll(/toggleRange\(['"](.*?)['"]\s*,\s*['"](.*?)['"]/g);
  const ranges = {};
  for (const m of rangeMatches) {
    ranges[m[2]] = m[1]; // id -> name
  }

  // Extract numbers under each range
  const numberMatches = html.matchAll(/data-number="([^"]+)"[^>]*data-range="([^"]+)"|class="num[^"]*"[^>]*>([^<]+)<\/|<td[^>]*>([0-9]{6,15})<\/td>/g);

  // Simple: extract all phone numbers (6-15 digits)
  const phonePattern = /(\d{7,15})/g;
  const rangePattern = /toggleRange\(['"]([^'"]+)['"]/g;

  let rangeNames = [];
  let rm;
  while ((rm = rangePattern.exec(html)) !== null) {
    rangeNames.push(rm[1]);
  }

  // Get number rows - look for number containers
  const rowPattern = /class="num(?:ber)?[^"]*"[^>]*>([\s\S]*?)<\/(?:div|td|tr)/g;
  let rowMatch;
  let idx = 0;
  while ((rowMatch = rowPattern.exec(html)) !== null) {
    const text = stripHTML(rowMatch[1]);
    const nums = text.match(/\d{7,15}/g);
    if (nums) {
      nums.forEach(n => {
        results.push({
          number: n,
          range:  rangeNames[idx] || "",
          status: "Active"
        });
      });
      idx++;
    }
  }

  // Fallback: just extract all numbers from HTML
  if (results.length === 0) {
    const allNums = html.match(/\d{9,15}/g) || [];
    const unique  = [...new Set(allNums)];
    unique.forEach(n => results.push({ number: n, range: "", status: "Active" }));
  }

  return { total: results.length, aaData: results };
}

function parseSMSHTML(html) {
  const results = [];

  // Try JSON first
  try {
    const json = JSON.parse(html);
    if (json.data || json.aaData || Array.isArray(json)) return json;
  } catch {}

  // Parse HTML table rows
  const rowPattern = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
  let rowMatch;
  while ((rowMatch = rowPattern.exec(html)) !== null) {
    const row  = rowMatch[1];
    const cols = [];
    const tdPattern = /<td[^>]*>([\s\S]*?)<\/td>/gi;
    let tdMatch;
    while ((tdMatch = tdPattern.exec(row)) !== null) {
      cols.push(stripHTML(tdMatch[1]));
    }
    if (cols.length >= 3) {
      results.push({
        date:    cols[0] || "",
        number:  cols[1] || "",
        message: cols[2] || "",
        status:  cols[3] || "",
        raw:     cols
      });
    }
  }

  return { total: results.length, aaData: results, rawPreview: results.length === 0 ? html.substring(0, 500) : undefined };
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
    "Referer":      `${BASE_URL}/portal/numbers`,
    "Accept":       "application/json, text/javascript, */*; q=0.01",
    "X-CSRF-TOKEN": token
  });

  const json = safeJSON(resp.body);
  return fixNumbers(json);
}

function fixNumbers(json) {
  if (!json || !json.data) return json;

  // Format: [range, "", number, "Weekly", ""]
  const aaData = json.data.map(row => [
    row.range  || "",
    "",
    String(row.Number || ""),
    "Weekly",
    ""
  ]);

  return {
    sEcho:              2,
    iTotalRecords:      String(json.recordsTotal || aaData.length),
    iTotalDisplayRecords: String(json.recordsFiltered || aaData.length),
    aaData
  };
}

/* ================= GET SMS ================= */
async function getSMS(token) {
  const today    = getToday();
  const boundary = "----WebKitFormBoundary6I2Js7TBhcJuwIqw";
  const ua       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36";

  const parts = [
    `--${boundary}\r\nContent-Disposition: form-data; name="from"\r\n\r\n${today}`,
    `--${boundary}\r\nContent-Disposition: form-data; name="to"\r\n\r\n${today}`,
    `--${boundary}\r\nContent-Disposition: form-data; name="_token"\r\n\r\n${token}`,
    `--${boundary}--`
  ].join("\r\n");

  // Step 1: Get ranges
  const r1 = await makeRequest(
    "POST", "/portal/sms/received/getsms", parts,
    `multipart/form-data; boundary=${boundary}`,
    { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01", "User-Agent": ua }
  );

  const ranges = [...r1.body.matchAll(/toggleRange\('([^']+)'/g)].map(m => m[1]);
  console.log(`[IVAS] Ranges: ${ranges.join(", ")}`);

  const allRows = [];

  for (const range of ranges) {
    // Step 2: Get numbers per range
    const b2 = new URLSearchParams({ _token: token, start, end, range }).toString();
    const r2  = await makeRequest(
      "POST", "/portal/sms/received/getsms/number", b2,
      "application/x-www-form-urlencoded",
      { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01", "User-Agent": ua }
    ).catch(() => null);

    if (!r2) continue;

    // Extract numbers from HTML: toggleNum..('NUMBER','NUMBER_ID')
    const numbers = [...r2.body.matchAll(/toggleNum[^(]+\('(\d+)'/g)].map(m => m[1]);
    console.log(`[IVAS] ${range} → numbers: ${numbers.join(", ")}`);

    for (const number of numbers) {
      // Step 3: Get actual OTP SMS for each number
      const b3 = new URLSearchParams({ _token: token, start, end, Number: number, Range: range }).toString();
      const r3  = await makeRequest(
        "POST", "/portal/sms/received/getsms/number/sms", b3,
        "application/x-www-form-urlencoded",
        { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01", "User-Agent": ua }
      ).catch(() => null);

      if (!r3) continue;

      // Parse OTP messages from HTML
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
  const rows  = [];
  const clean = t => (t || "")
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&").replace(/&#039;/g, "'")
    .replace(/\s+/g, " ").trim();

  // Extract all <tr> rows (skip header)
  const trAll = [...html.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)];

  for (const trM of trAll) {
    const row = trM[1];
    if (row.includes("<th")) continue;

    // Sender from cli-tag
    const senderM = row.match(/class="cli-tag"[^>]*>([^<]+)</);
    const sender  = senderM ? senderM[1].trim() : "SMS";

    // Message from msg-text div (multiline content)
    const msgM   = row.match(/class="msg-text"[^>]*>([\s\S]*?)<\/div>/i);
    const message = msgM ? clean(msgM[1]) : "";

    // Time from time-cell
    const timeM = row.match(/class="time-cell"[^>]*>\s*([0-9:]+)\s*</);
    const time  = timeM ? timeM[1].trim() : "00:00:00";

    if (message) {
      rows.push([
        `${date} ${time}`,
        range,
        number,
        sender,
        message,
        "$",
        0
      ]);
    }
  }

  return rows;
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
    "Referer":      `${BASE_URL}/portal/numbers`,
    "Accept":       "application/json, text/javascript, */*; q=0.01",
    "X-CSRF-TOKEN": token
  });

  const json = safeJSON(resp.body);
  return fixNumbers(json);
}

function fixNumbers(json) {
  if (!json || !json.data) return json;

  // Format: [range, "", number, "Weekly", ""]
  const aaData = json.data.map(row => [
    row.range  || "",
    "",
    String(row.Number || ""),
    "Weekly",
    ""
  ]);

  return {
    sEcho:              2,
    iTotalRecords:      String(json.recordsTotal || aaData.length),
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

  // Step 1: Get ranges list
  const r1 = await makeRequest(
    "POST", "/portal/sms/received/getsms", parts,
    `multipart/form-data; boundary=${boundary}`,
    {
      "Referer":    `${BASE_URL}/portal/sms/received`,
      "Accept":     "text/html, */*; q=0.01",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
    }
  );

  // Extract range names from HTML
  const rangeMatches = [...r1.body.matchAll(/toggleRange\('([^']+)'/g)];
  const ranges = rangeMatches.map(m => m[1]);
  console.log(`[IVAS] Found ranges: ${ranges.join(", ")}`);

  if (ranges.length === 0) {
    return { sEcho: 1, iTotalRecords: "0", iTotalDisplayRecords: "0", aaData: [] };
  }

  // Step 2: Fetch numbers+OTP for each range
  const allRows = [];
  for (const range of ranges) {
    try {
      const body = new URLSearchParams({
        _token: token,
        start,
        end,
        range:  range
      }).toString();

      const r2 = await makeRequest(
        "POST", "/portal/sms/received/getsms/number", body,
        "application/x-www-form-urlencoded",
        {
          "Referer":    `${BASE_URL}/portal/sms/received`,
          "Accept":     "text/html, */*; q=0.01",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
      );

      // Parse number rows from HTML
      const rows = parseNumberRows(r2.body, range);
      allRows.push(...rows);
    } catch(e) {
      console.warn(`[IVAS] Range ${range} failed:`, e.message);
    }
  }

  return {
    sEcho:                1,
    iTotalRecords:        String(allRows.length),
    iTotalDisplayRecords: String(allRows.length),
    aaData:               allRows
  };
}

function parseNumberRows(html, range) {
  const rows = [];

  // Pattern: number rows contain number + message
  // Look for data attributes or text content
  const numPattern  = /data-number="([^"]+)"|class="[^"]*number[^"]*"[^>]*>([^<]+)<|\b(\d{7,15})\b/g;
  const msgPattern  = /data-message="([^"]+)"|class="[^"]*message[^"]*"[^>]*>([^<]+)<|class="[^"]*sms[^"]*"[^>]*>([^<]+)</g;

  // Try row-based parsing
  const rowPattern = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
  let rowMatch;
  while ((rowMatch = rowPattern.exec(html)) !== null) {
    const row  = rowMatch[1];
    const tds  = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map(m =>
      m[1].replace(/<[^>]+>/g, "").trim()
    );
    if (tds.length >= 2) {
      const number  = tds.find(t => /^\d{7,15}$/.test(t.replace(/\s/,""))) || "";
      const message = tds.find(t => t.length > 5 && !/^\d+$/.test(t) && t !== number) || "";
      if (number || message) {
        rows.push([
          new Date().toISOString().replace("T"," ").substring(0,19),
          range,
          number,
          "SMS",
          message,
          "$",
          0
        ]);
      }
    }
  }

  // Fallback: extract numbers and messages from divs
  if (rows.length === 0) {
    const divNums = [...html.matchAll(/\b(\d{9,15})\b/g)].map(m => m[1]);
    const msgs    = [...html.matchAll(/class="[^"]*msg[^"]*"[^>]*>([^<]+)</gi)].map(m => m[1].trim());
    const unique  = [...new Set(divNums)];
    unique.forEach((num, i) => {
      rows.push([
        new Date().toISOString().replace("T"," ").substring(0,19),
        range, num, "SMS",
        msgs[i] || "",
        "$", 0
      ]);
    });
  }

  return rows;
}

/* ================= ROUTES ================= */




router.get("/set-cookie", (req, res) => {
  const { xsrf, session, key } = req.query;

  // 🔐 simple protection
  if (key !== "oklogin123") {
    return res.status(403).send("Unauthorized");
  }

  if (!xsrf || !session) {
    return res.status(400).json({ error: "Missing xsrf or session" });
  }

  // 🔥 update runtime cookies
  COOKIES["XSRF-TOKEN"] = xsrf;
  COOKIES["ivas_sms_session"] = session;

  res.json({
    status: "✅ Cookies updated (no restart needed)"
  });
});


// Main API
router.get("/", async (req, res) => {
  const { type } = req.query;
  if (!type) return res.json({ error: "Use ?type=numbers or ?type=sms" });

  try {
    const token = await fetchToken();
    if (!token) {
      return res.status(401).json({
        error: "Session expired",
        fix:   "POST /api/ivasms/update-session with xsrf and session cookies"
      });
    }

    if (type === "numbers") return res.json(await getNumbers(token));
    if (type === "sms")     return res.json(await getSMS(token));

    res.json({ error: "Invalid type. Use numbers or sms" });

  } catch (err) {
    if (err.message === "SESSION_EXPIRED") {
      return res.status(401).json({
        error: "Session expired — update cookies",
        fix:   "POST /api/ivasms/update-session with xsrf and session"
      });
    }
    res.status(500).json({ error: err.message });
  }
});



// Raw debug: show actual OTP SMS HTML (level 3)
function clean(text) {
  return (text || "")
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function extractOTP(message) {
  const match = message.match(/\b\d{4,8}\b/);
  return match ? match[0] : null;
}

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

// STEP 1: ranges
    const r1 = await makeRequest(
  "POST",
  "/portal/sms/received/getsms",
  parts,
  `multipart/form-data; boundary=${boundary}`,
  { "Referer": `${BASE_URL}/portal/sms/received` }
);

    const rangeMatches = [...r1.body.matchAll(/toggleRange\('([^']+)'/g)];
    if (!rangeMatches.length) return res.json({ error: "No ranges" });

    const ranges = rangeMatches.map(m => m[1]);

// 🔥 LOOP RANGES
    for (const range of ranges) {

  // STEP 2: numbers
      const r2 = await makeRequest(
    "POST",
    "/portal/sms/received/getsms/number",
        new URLSearchParams({
      _token: token,
      start,
      end,
      range
    }).toString(),
    "application/x-www-form-urlencoded"
  );

      const numberMatches = [...r2.body.matchAll(/toggleNum[^(]+\('(\d+)'/g)];
      const numbers = numberMatches.map(m => m[1]);

  // 🔥 LOOP NUMBERS
      for (const number of numbers) {

        const r3 = await makeRequest(
      "POST",
      "/portal/sms/received/getsms/number/sms",
          new URLSearchParams({
        _token: token,
        start,
        end,
        Number: number,
        Range: range
      }).toString(),
      "application/x-www-form-urlencoded"
    );

    // Extract messages
      const rows = [...r3.body.matchAll(/class="msg-text"[^>]*>([\s\S]*?)<\/div>/gi)];
      const messages = rows.map(m => clean(m[1]));

      for (const msg of messages) {
        const otp = extractOTP(msg);

        if (otp) {
          const entry = {
          number,
          otp,
          range,
          time: new Date().toLocaleTimeString()
        };

        // duplicate avoid
          if (!otpHistory.find(e => e.otp === otp && e.number === number)) {
          otpHistory.unshift(entry);
        }
      }
    }
  }
}

// limit 30
if (otpHistory.length > 30) {
  otpHistory = otpHistory.slice(0, 30);
}

res.json({
  history: otpHistory
});

} catch (e) {
  res.status(500).json({ error: e.message });
}

}); // 🔥 ye router.get ka closing hai




// Cookie update endpoint — POST with JSON body
// { "xsrf": "...", "session": "..." }
router.post("/update-session", express.json(), (req, res) => {
  const { xsrf, session } = req.body || {};
  if (!xsrf || !session) {
    return res.status(400).json({
      error: "Required: xsrf and session",
      example: { xsrf: "XSRF-TOKEN value", session: "ivas_sms_session value" }
    });
  }
  COOKIES["XSRF-TOKEN"]       = xsrf;
  COOKIES["ivas_sms_session"] = session;
  console.log("✅ [IVAS] Cookies updated manually");
  res.json({ success: true, message: "Cookies updated!" });
});

// Check session status
router.get("/status", async (req, res) => {
  try {
    const token = await fetchToken();
    res.json({
      status:    token ? "✅ Session active" : "❌ Session expired",
      hasToken:  !!token,
      cookieKeys: Object.keys(COOKIES)
    });
  } catch (e) {
    res.json({ status: "❌ Session expired", error: e.message });
  }
});

module.exports = router;

