/**
 * ============================================================
 * Web Application Vulnerability Scanner - Backend
 * Academic / Educational Use Only
 * ============================================================
 * This server simulates vulnerability scanning by sending
 * harmless test payloads and analyzing responses.
 * It does NOT perform any real attacks.
 * ============================================================
 */

const express = require("express");
const axios = require("axios");
const cors = require("cors");

const app = express();
const PORT = 3000;

// ── Middleware ───────────────────────────────────────────────
app.use(cors());                        // Allow requests from the frontend
app.use(express.json());                // Parse incoming JSON bodies
app.use(express.static("../frontend")); // Serve the frontend files

// ── SQL Injection Test Payloads ──────────────────────────────
// These are classic detection strings used in security auditing.
// They are sent as URL query parameters to observe server behavior.
const SQL_PAYLOADS = [
  "' OR '1'='1",
  "admin' --",
  "' OR 1=1 --",
  "1; DROP TABLE users--",  // purely observational; server response is analyzed
  "' UNION SELECT null--",
];

// ── SQL Error Signatures ─────────────────────────────────────
// Common database error strings that leak when SQL injection is possible.
const SQL_ERROR_SIGNATURES = [
  "sql syntax",
  "mysql_fetch",
  "ora-",
  "sqlite",
  "syntax error",
  "unclosed quotation",
  "odbc driver",
  "microsoft ole db",
  "warning: mysql",
  "pg_query",
  "postgresql",
  "division by zero",
  "you have an error in your sql",
  "supplied argument is not a valid mysql",
  "invalid query",
  "db2 sql error",
  "jdbc",
  "sqlexception",
];

// ── XSS Test Payloads ────────────────────────────────────────
// These strings are echoed into the URL / query params.
// If they appear unescaped in the HTML response, the site is vulnerable.
const XSS_PAYLOADS = [
  "<script>alert('xss')</script>",
  "<img src=x onerror=alert(1)>",
  "'\"><svg onload=alert(1)>",
  "<body onload=alert('XSS')>",
];

// ── Helper: Build test URL ───────────────────────────────────
// Appends a payload to the target URL as a query parameter.
function buildTestUrl(baseUrl, payload) {
  try {
    const url = new URL(baseUrl);
    // Inject payload into a generic 'q' search parameter
    url.searchParams.set("q", payload);
    return url.toString();
  } catch {
    // If URL parsing fails, fall back to simple string append
    const separator = baseUrl.includes("?") ? "&" : "?";
    return `${baseUrl}${separator}q=${encodeURIComponent(payload)}`;
  }
}

// ── Helper: Validate URL input ───────────────────────────────
function isValidUrl(str) {
  try {
    const url = new URL(str);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

// ============================================================
// POST /scan/sql
// Tests target URL for SQL Injection vulnerability indicators.
// ============================================================
app.post("/scan/sql", async (req, res) => {
  const { url } = req.body;

  // ── Input validation ──────────────────────────────────────
  if (!url || typeof url !== "string") {
    return res.status(400).json({
      result: "error",
      message: "A valid URL string is required.",
    });
  }

  if (!isValidUrl(url)) {
    return res.status(400).json({
      result: "error",
      message: "URL must start with http:// or https://",
    });
  }

  const findings = [];  // Store per-payload results
  let vulnerable = false;

  // ── Test each SQL payload ─────────────────────────────────
  for (const payload of SQL_PAYLOADS) {
    const testUrl = buildTestUrl(url, payload);

    try {
      const response = await axios.get(testUrl, {
        timeout: 8000,         // 8-second timeout per request
        validateStatus: null,  // Accept any HTTP status code
        headers: {
          "User-Agent": "VulnScannerEdu/1.0 (Academic Research)",
        },
        maxRedirects: 3,
      });

      const body = (response.data || "").toString().toLowerCase();

      // Check if any known SQL error signature is present in the response body
      const matchedSignature = SQL_ERROR_SIGNATURES.find((sig) =>
        body.includes(sig)
      );

      if (matchedSignature) {
        vulnerable = true;
        findings.push({
          payload,
          status: response.status,
          finding: `SQL error detected: "${matchedSignature}"`,
          verdict: "vulnerable",
        });
        break; // One confirmed finding is enough to flag as vulnerable
      } else {
        findings.push({
          payload,
          status: response.status,
          finding: "No SQL error signature detected.",
          verdict: "safe",
        });
      }
    } catch (err) {
      findings.push({
        payload,
        finding: `Request failed: ${err.message}`,
        verdict: "error",
      });
    }
  }

  // ── Return consolidated result ────────────────────────────
  return res.json({
    result: vulnerable ? "vulnerable" : "not_vulnerable",
    scanType: "SQL Injection",
    target: url,
    payloadsTested: SQL_PAYLOADS.length,
    findings,
    timestamp: new Date().toISOString(),
  });
});

// ============================================================
// POST /scan/xss
// Tests target URL for Reflected XSS vulnerability indicators.
// ============================================================
app.post("/scan/xss", async (req, res) => {
  const { url } = req.body;

  // ── Input validation ──────────────────────────────────────
  if (!url || typeof url !== "string") {
    return res.status(400).json({
      result: "error",
      message: "A valid URL string is required.",
    });
  }

  if (!isValidUrl(url)) {
    return res.status(400).json({
      result: "error",
      message: "URL must start with http:// or https://",
    });
  }

  const findings = [];
  let vulnerable = false;

  // ── Test each XSS payload ─────────────────────────────────
  for (const payload of XSS_PAYLOADS) {
    const testUrl = buildTestUrl(url, payload);

    try {
      const response = await axios.get(testUrl, {
        timeout: 8000,
        validateStatus: null,
        headers: {
          "User-Agent": "VulnScannerEdu/1.0 (Academic Research)",
        },
        maxRedirects: 3,
      });

      const body = (response.data || "").toString();

      // XSS detection: check if the raw payload appears unescaped in the HTML response.
      // A properly secured site will HTML-encode <, >, ', " so the script won't appear literally.
      const payloadReflected = body.includes(payload);

      if (payloadReflected) {
        vulnerable = true;
        findings.push({
          payload,
          status: response.status,
          finding: "Payload was reflected unescaped in the response body.",
          verdict: "vulnerable",
        });
        break;
      } else {
        findings.push({
          payload,
          status: response.status,
          finding: "Payload was not reflected (or was escaped) in the response.",
          verdict: "safe",
        });
      }
    } catch (err) {
      findings.push({
        payload,
        finding: `Request failed: ${err.message}`,
        verdict: "error",
      });
    }
  }

  return res.json({
    result: vulnerable ? "vulnerable" : "not_vulnerable",
    scanType: "Cross-Site Scripting (XSS)",
    target: url,
    payloadsTested: XSS_PAYLOADS.length,
    findings,
    timestamp: new Date().toISOString(),
  });
});

// ── Health check endpoint ─────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// ── Start server ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡️  VulnScanner API running at http://localhost:${PORT}`);
  console.log(`   POST /scan/sql  — SQL Injection scanner`);
  console.log(`   POST /scan/xss  — XSS scanner`);
  console.log(`   GET  /health    — Health check\n`);
});
