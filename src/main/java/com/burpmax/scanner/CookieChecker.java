package com.burpmax.scanner;

import com.burpmax.model.Finding;

import java.util.*;
import java.util.regex.*;

import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

public class CookieChecker {

    private static final Pattern RE_EMAIL = Pattern.compile(
            "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}");
    private static final Pattern RE_JWT = Pattern.compile(
            "ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");
    private static final Pattern RE_JSON = Pattern.compile(
            "\\{[\"'][^\"']{1,100}[\"']\\s*:\\s*[\"'\\d\\[{]");

    public static List<CheckResult> check(List<String> setCookieHeaders) {
        List<CheckResult> results = new ArrayList<>();
        if (setCookieHeaders == null || setCookieHeaders.isEmpty()) return results;

        boolean httponlyReported = false;
        boolean secureReported   = false;

        for (String cookie : setCookieHeaders) {
            String lower = cookie.toLowerCase();

            // HttpOnly
            if (!httponlyReported) {
                boolean hasHttpOnly = false;
                for (String part : lower.split(";")) {
                    if (part.trim().equals("httponly")) { hasHttpOnly = true; break; }
                }
                if (!hasHttpOnly) {
                    results.add(new CheckResult(
                        "Cookie HTTPOnly Flag Missing", SEV_LOW,
                        "The HttpOnly flag instructs browsers to prevent JavaScript from reading the cookie via document.cookie. Without it, any script executing on the page -- including code injected through Cross-Site Scripting (XSS) -- can read the cookie and exfiltrate it to an attacker's server. Session cookies, authentication tokens, and CSRF tokens are the primary targets.",
                        "Set-Cookie: " + trunc(cookie, 150),
                        "- Add the HttpOnly flag to all cookies not intentionally read by JavaScript: Set-Cookie: session=abc; HttpOnly\n- Session tokens, auth tokens, CSRF cookies, and remember-me tokens must all be HttpOnly\n- Configure HttpOnly as the default at the framework session management level, not per individual cookie\n- Express.js: res.cookie('session', value, { httpOnly: true })\n- Spring Boot: server.servlet.session.cookie.http-only=true",
                        "CWE-1004"));
                    httponlyReported = true;
                }
            }

            // Secure
            if (!secureReported) {
                boolean hasSecure = false;
                for (String part : lower.split(";")) {
                    if (part.trim().equals("secure")) { hasSecure = true; break; }
                }
                if (!hasSecure) {
                    results.add(new CheckResult(
                        "Cookie Secure Flag Missing", SEV_LOW,
                        "The Secure cookie attribute restricts the browser to transmitting the cookie only over encrypted HTTPS connections. Without it, the browser will also send the cookie over HTTP. An attacker positioned on the network can capture the cookie in plaintext from any unencrypted HTTP request to the domain.",
                        "Set-Cookie: " + trunc(cookie, 150),
                        "- Add the Secure flag to every cookie: Set-Cookie: session=abc; Secure\n- Combine with HttpOnly and SameSite for maximum hardening: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict\n- Deploy HSTS alongside the Secure flag to prevent the browser from making any unencrypted HTTP requests to the domain",
                        "CWE-614"));
                    secureReported = true;
                }
            }

            // Extract cookie value
            String value = "";
            int eq = cookie.indexOf('=');
            if (eq >= 0) {
                String rest = cookie.substring(eq + 1);
                int semi = rest.indexOf(';');
                value = semi >= 0 ? rest.substring(0, semi) : rest;
            }

            if (RE_EMAIL.matcher(value).find()) {
                results.add(new CheckResult(
                    "Sensitive PII Data Passed in Cookie", SEV_HIGH,
                    "This cookie's value contains personally identifiable information (PII) -- specifically an email address or similar user data. Cookies are transmitted in HTTP headers, stored in browser storage on disk, and often recorded in web server and proxy access logs.",
                    "Cookie contains email-like value: " + trunc(value, 100),
                    "- Replace the PII value with an opaque server-side session identifier (random UUID mapped to user data server-side)\n- Store user data in your session store (Redis, database) keyed by the session ID -- never in the cookie itself\n- Implement automated scanning of Set-Cookie headers in your CI pipeline to detect PII values before deployment",
                    "CWE-312"));
            }

            if (RE_JWT.matcher(value).find()) {
                results.add(new CheckResult(
                    "Data Exposure in Cookie (JWT)", SEV_MEDIUM,
                    "This cookie contains a JSON Web Token (JWT). JWT payloads are Base64URL-encoded, not encrypted -- anyone who obtains the token can decode the header and all payload claims without knowing the signing secret.",
                    "Cookie contains JWT: " + trunc(value, 100),
                    "- Remove PII from JWT payload claims; store only opaque identifiers (user UUID, session ID)\n- If sensitive data must be in the token, use JSON Web Encryption (JWE) instead of plain JWT\n- Always add the HttpOnly and Secure flags to JWT cookies to prevent JavaScript access",
                    "CWE-312"));
            } else if (RE_JSON.matcher(value).find()) {
                // Only flag if the JSON value contains keys that suggest sensitive data.
                // Plain JSON cookies like {"theme":"dark","lang":"en"} are not a security issue.
                String valueLower = value.toLowerCase();
                boolean hasSensitiveKey = valueLower.contains("token") || valueLower.contains("session")
                        || valueLower.contains("secret") || valueLower.contains("password")
                        || valueLower.contains("auth") || valueLower.contains("key")
                        || valueLower.contains("user_id") || valueLower.contains("userid")
                        || valueLower.contains("account");
                if (hasSensitiveKey) {
                    results.add(new CheckResult(
                        "Data Exposure in Cookie (JSON)", SEV_MEDIUM,
                        "This cookie contains serialized JSON with keys that suggest sensitive session or authentication data is stored client-side. If the JSON is not integrity-protected, users can modify their own cookie values to tamper with their session state.",
                        "Cookie contains sensitive JSON keys: " + trunc(value, 100),
                        "- Replace JSON cookie values with a random opaque session ID that references server-side state\n- Store structured session data in a server-side session store (Redis, Memcached, database) keyed by session ID",
                        "CWE-312"));
                }
            }

            // SameSite — differentiate between truly absent, and intentional None+Secure
            boolean hasSameSiteNone   = lower.contains("samesite=none");
            boolean hasSameSiteStrict = lower.contains("samesite=strict");
            boolean hasSameSiteLax    = lower.contains("samesite=lax");
            boolean hasSecureFlag     = lower.contains("; secure") || lower.endsWith(";secure")
                                        || lower.contains(";secure") || lower.matches(".*\bsecure\b.*");

            if (!hasSameSiteStrict && !hasSameSiteLax) {
                if (hasSameSiteNone && hasSecureFlag) {
                    // SameSite=None; Secure is a valid intentional config for third-party embedded
                    // contexts (OAuth, payment widgets). File as a separate lower-severity notice.
                    results.add(new CheckResult(
                        "Cookie SameSite=None Allows Cross-Site Transmission", SEV_LOW,
                        "This cookie is configured with SameSite=None, which instructs the browser to " +
                        "send it with all cross-site requests including those from third-party pages. " +
                        "While this is intentional for cookies used in embedded third-party contexts " +
                        "(OAuth flows, payment widgets, cross-origin APIs), it removes the CSRF " +
                        "mitigation that SameSite=Strict or Lax would provide. Verify this is required.",
                        "Set-Cookie: " + trunc(cookie, 150),
                        "- Verify that SameSite=None is genuinely required for cross-site usage\n" +
                        "- If the cookie is a session or auth cookie used only on your own domain, " +
                        "change to SameSite=Strict or SameSite=Lax\n" +
                        "- Combine SameSite=None with traditional CSRF tokens on state-changing endpoints",
                        "CWE-352"));
                } else {
                    // SameSite truly absent or set to an unrecognised value
                    results.add(new CheckResult(
                        "Cookie SameSite Attribute Missing or Weak", SEV_LOW,
                        "The SameSite attribute is absent from this cookie. Without it, the browser " +
                        "sends the cookie with cross-site requests triggered by third-party pages, " +
                        "enabling Cross-Site Request Forgery (CSRF) attacks. Modern browsers default " +
                        "to Lax for cookies without SameSite, but this is not universally enforced " +
                        "and should not be relied upon.",
                        "Set-Cookie: " + trunc(cookie, 150),
                        "- Add SameSite=Strict for session and auth cookies used only on your domain\n" +
                        "- Use SameSite=Lax when the cookie must be sent on top-level cross-site navigation\n" +
                        "- Only use SameSite=None for cookies explicitly required for third-party embeds " +
                        "(must be paired with Secure)\n" +
                        "- Combine SameSite with CSRF tokens for defence-in-depth",
                        "CWE-352"));
                }
            }
        }
        return results;
    }
}
