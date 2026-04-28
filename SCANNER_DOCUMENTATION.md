# VulnScanner: Technical Documentation

## Overview
VulnScanner is an educational web application vulnerability scanner designed to detect common security flaws in web applications. It uses a **Black Box** testing approach to identify vulnerabilities without requiring access to the target's source code.

---

## 1. Supported Attack Types

### SQL Injection (SQLi)
*   **Goal:** To determine if the target application's database can be manipulated via input parameters.
*   **Method:** The scanner injects SQL-specific characters and commands into URL query parameters to trigger database errors.
*   **Detection:** It monitors the HTTP response body for "Error Signatures" from common databases (MySQL, PostgreSQL, SQLite, Oracle, etc.).

### Cross-Site Scripting (Reflected XSS)
*   **Goal:** To check if the application reflects unsanitized user input back into the browser.
*   **Method:** The scanner injects HTML and JavaScript snippets into URL parameters.
*   **Detection:** It checks if the injected payload appears exactly (unescaped) in the returned HTML. If the script is reflected without being HTML-encoded, the site is considered vulnerable.

---

## 2. The Scanning Process

The backend server (`server.js`) follows a systematic 4-step process:

1.  **URL Normalization:** The target URL is validated and prepared.
2.  **Payload Injection:** Each payload from the pre-defined lists is appended to the URL as a query parameter (e.g., `?q=payload`).
3.  **HTTP Request:** The scanner sends a GET request to the modified URL with a specific User-Agent (`VulnScannerEdu/1.0`).
4.  **Heuristic Analysis:**
    *   **SQLi:** Searches for strings like `"sql syntax"`, `"mysql_fetch"`, or `"unclosed quotation"`.
    *   **XSS:** Searches for the literal presence of the injected script tags.

---

## 3. Pre-defined Payloads

### SQL Injection Payloads
*   `' OR '1'='1`
*   `admin' --`
*   `' OR 1=1 --`
*   `1; DROP TABLE users--`
*   `' UNION SELECT null--`

### XSS Payloads
*   `<script>alert('xss')</script>`
*   `<img src=x onerror=alert(1)>`
*   `'\"><svg onload=alert(1)>`
*   `<body onload=alert('XSS')>`

---

## 4. Technical Architecture
*   **Frontend:** HTML5, Vanilla CSS3, and JavaScript (ES6+).
*   **Backend:** Node.js with Express.
*   **Communication:** Axios for HTTP requests, CORS enabled for cross-origin dashboard access.

---

## 5. Professor Presentation Guide

### Core Method: Black Box Testing
The system uses a **Black Box** methodology, meaning it interacts with the target website from the perspective of an external user. It does not need to see the server-side source code; instead, it analyzes how the server **responds** to "malicious" inputs.

### Execution Process (Step-by-Step)
1.  **Input Normalization:** The user provides a target URL. The system validates the protocol (HTTP/S) and prepares the connection.
2.  **Automated Injection:** The engine automatically appends pre-defined "attack payloads" (SQL commands or JavaScript snippets) to the URL's query parameters.
3.  **Response Analysis:** The backend sends an HTTP request and captures the full HTML response from the server.
4.  **Heuristic Matching:** The system runs the response through two detection filters:
    *   **Signature Matching:** Checking for database error strings.
    *   **Reflection Check:** Checking if raw script tags were echoed back without being sanitized.

### The "Why" (Reasoning for Logic)
*   **SQL Injection Detection Reason:** A secure application should never show raw database errors to a user. If a payload like `' OR '1'='1` causes the server to return a message like `"You have an error in your SQL syntax"`, it proves that the input reached the database un-sanitized.
*   **XSS Detection Reason:** Security best practices require that all user input be "HTML-Encoded" before being displayed. If the scanner sends `<script>` and the server returns that exact same `<script>` in the HTML, it means a browser would execute it, confirming the site is vulnerable to a session-hijacking attack.

---

> **Disclaimer:** This tool is for **educational and academic research purposes only**. Never scan a website that you do not own or have explicit permission to test.
