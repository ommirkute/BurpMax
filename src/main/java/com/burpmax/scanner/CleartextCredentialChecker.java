package com.burpmax.scanner;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

/**
 * Detects credentials being transmitted in cleartext in HTTP requests.
 *
 * Fires when:
 *  1. The URL scheme is http:// (not https) — cleartext channel confirmed
 *  2. AND the request contains credential-like parameters or headers
 *
 * Also fires (regardless of scheme) when credentials appear in the URL query string,
 * which is always a bad practice even over HTTPS (logged in server access logs,
 * browser history, Referer headers, etc.).
 *
 * Severity: LOW — as requested, since HTTPS misconfiguration is the root cause
 * and the endpoint may not be widely accessible.
 */
public class CleartextCredentialChecker {

    // Ordered list — order matters for regex alternation (longer/more specific first)
    private static final List<String> CREDENTIAL_PARAM_NAMES = List.of(
            "access_token", "refresh_token", "auth_token", "session_token",
            "bearer_token", "id_token", "two_factor_secret", "totp_secret",
            "mfa_secret", "recovery_code", "backup_code",
            "client_secret", "api_secret", "private_key", "secret_key",
            "password_hash", "hashed_password", "password_digest",
            "credit_card", "card_number", "social_security",
            "password", "passwd", "secret", "api_key", "apikey",
            "token", "cvv", "cvc", "ssn", "pass", "pwd"
    );

    // Form-encoded credential pattern: password=value or api_key=value in body
    private static final Pattern RE_FORM_CRED = Pattern.compile(
            "(?:^|&)(" +
            String.join("|", CREDENTIAL_PARAM_NAMES) +
            ")=([^&\\s]{1,200})",
            Pattern.CASE_INSENSITIVE);

    // URL query string credential
    private static final Pattern RE_QUERY_CRED = Pattern.compile(
            "[?&](" +
            String.join("|", CREDENTIAL_PARAM_NAMES) +
            ")=([^&\\s#]{1,200})",
            Pattern.CASE_INSENSITIVE);

    // JSON body credential pattern (static — not recompiled per call)
    private static final Pattern RE_JSON_CRED = Pattern.compile(
            "\"(?:password|passwd|secret|api_key|apikey|token|access_token|" +
            "auth_token|client_secret|private_key|password_hash|hashed_password)" +
            "\"\\s*:\\s*\"([^\"]{1,200})\"",
            Pattern.CASE_INSENSITIVE);

    // Basic auth header (Authorization: Basic <base64>)
    private static final Pattern RE_BASIC_AUTH = Pattern.compile(
            "^Basic\\s+([A-Za-z0-9+/=]{4,})",
            Pattern.CASE_INSENSITIVE);

    public static List<CheckResult> check(Map<String, String> reqHeaders,
                                           String reqBody,
                                           String url,
                                           String method) {
        List<CheckResult> results = new ArrayList<>();
        if (url == null) return results;

        boolean isHttp = url.toLowerCase().startsWith("http://");

        // ── 1. Credentials in URL query string (always bad, any scheme) ──────
        Matcher mqc = RE_QUERY_CRED.matcher(url);
        if (mqc.find()) {
            String paramName = mqc.group(1).toLowerCase();
            String paramVal  = mqc.group(2);
            if (!isPlaceholder(paramVal)) {
                String masked = mask(paramVal);

                // Classify by param name — single-use token patterns (verify, confirm, unsubscribe,
                // webhook, callback paths) are legitimately in URLs and less severe.
                boolean isPersistentCred = paramName.equals("password") || paramName.equals("passwd")
                        || paramName.equals("api_secret") || paramName.equals("client_secret")
                        || paramName.equals("access_token") || paramName.equals("refresh_token")
                        || paramName.equals("private_key") || paramName.equals("secret_key")
                        || paramName.equals("credit_card") || paramName.equals("cvv")
                        || paramName.equals("ssn");

                String urlLower = url.toLowerCase();
                boolean isSingleUseContext = urlLower.contains("verify") || urlLower.contains("confirm")
                        || urlLower.contains("unsubscribe") || urlLower.contains("webhook")
                        || urlLower.contains("callback") || urlLower.contains("activate")
                        || urlLower.contains("invite") || urlLower.contains("reset");

                String sev  = (isPersistentCred || !isSingleUseContext) ? SEV_MEDIUM : SEV_LOW;
                String note = isSingleUseContext && !isPersistentCred
                    ? " This may be an intentional single-use token (verify/reset link) - confirm " +
                      "whether the value is reusable before treating as high-risk."
                    : " Persistent credentials in query strings are always high-risk.";

                results.add(new CheckResult(
                    "Credentials Transmitted in URL Query String", sev,
                    "The request URL contains a credential parameter ('" + paramName + "') in the " +
                    "query string. Query parameters are recorded in web server access logs, browser " +
                    "history, proxy logs, and Referer headers sent to third-party resources. " +
                    "This exposes credentials even when the connection uses HTTPS." + note,
                    "URL parameter: " + paramName + "=" + masked + " in: " + trunc(url, 120),
                    "- Move persistent credentials from URL query parameters to the request body (POST) " +
                    "or Authorization header\n" +
                    "- For API keys: use the Authorization header: Authorization: Bearer <key>\n" +
                    "- For single-use tokens: ensure short expiry (≤15 min) and single-use invalidation\n" +
                    "- Rotate any persistent credentials that have been transmitted as query parameters\n" +
                    "- Review web server access logs for historical exposure",
                    "CWE-598"));
            }
        }

        // ── 2. Credentials over HTTP (not HTTPS) ─────────────────────────────
        if (!isHttp) return results;

        // Check form-encoded POST body
        String reqContentType = reqHeaders.getOrDefault("content-type", "").toLowerCase();
        boolean isFormEncoded = reqContentType.contains("application/x-www-form-urlencoded")
                             || reqContentType.contains("multipart/form-data");

        if (isFormEncoded && reqBody != null && !reqBody.isEmpty()) {
            Matcher mf = RE_FORM_CRED.matcher(reqBody);
            if (mf.find()) {
                String paramName = mf.group(1);
                String paramVal  = mf.group(2);
                if (!isPlaceholder(paramVal)) {
                    results.add(new CheckResult(
                        "Credentials Transmitted in Cleartext (HTTP)", SEV_LOW,
                        "A credential parameter ('" + paramName + "') was detected in an HTTP POST " +
                        "request body transmitted over an unencrypted connection. The full request " +
                        "body including the credential value is visible to any network intermediary " +
                        "(ISP, corporate proxy, Wi-Fi hotspot operator, ARP spoofing attacker).",
                        "HTTP POST to " + trunc(url, 100) + " contains form field: " + paramName,
                        "- Enforce HTTPS on all endpoints that accept credentials - redirect HTTP to HTTPS\n" +
                        "- Deploy HSTS to prevent SSL stripping: Strict-Transport-Security: max-age=31536000\n" +
                        "- Ensure TLS certificates are valid and properly configured\n" +
                        "- Consider HSTS preloading at hstspreload.org for maximum protection",
                        "CWE-319"));
                }
            }
        }

        // Check JSON body for credential fields
        boolean isJson = reqContentType.contains("application/json");
        if (isJson && reqBody != null && !reqBody.isEmpty()) {
            Matcher mj = RE_JSON_CRED.matcher(reqBody);
            if (mj.find()) {
                String val = mj.group(1);
                if (!isPlaceholder(val)) {
                    results.add(new CheckResult(
                        "Credentials Transmitted in Cleartext (HTTP)", SEV_LOW,
                        "A credential field was detected in a JSON request body transmitted over " +
                        "an unencrypted HTTP connection. The full payload including credential values " +
                        "is visible to network intermediaries.",
                        "HTTP " + method + " to " + trunc(url, 100) + " contains JSON credential field",
                        "- Enforce HTTPS: redirect all HTTP requests to HTTPS at the load balancer\n" +
                        "- Deploy HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains\n" +
                        "- Ensure all API clients use HTTPS endpoints only",
                        "CWE-319"));
                }
            }
        }

        // Check Basic Auth header over HTTP
        String authHeader = reqHeaders.getOrDefault("authorization", "");
        Matcher mb = RE_BASIC_AUTH.matcher(authHeader);
        if (mb.find()) {
            String encoded = mb.group(1);
            // Decode and check it's not empty
            try {
                String decoded = new String(Base64.getDecoder().decode(encoded));
                if (decoded.contains(":") && decoded.length() > 3) {
                    results.add(new CheckResult(
                        "HTTP Basic Authentication Over Cleartext (HTTP)", SEV_LOW,
                        "HTTP Basic Authentication credentials were transmitted over an unencrypted " +
                        "HTTP connection. Basic Auth credentials are Base64-encoded (not encrypted) " +
                        "and are trivially decoded by any network observer. The credentials in this " +
                        "request are fully visible in plaintext on the wire.",
                        "Authorization: Basic [credentials] sent over HTTP to: " + trunc(url, 100),
                        "- Enforce HTTPS for all endpoints using Basic Authentication\n" +
                        "- Prefer token-based authentication (Bearer tokens, OAuth) over Basic Auth\n" +
                        "- If Basic Auth must be used, ensure it is only ever transmitted over HTTPS\n" +
                        "- Deploy HSTS to prevent protocol downgrade attacks",
                        "CWE-319"));
                }
            } catch (Exception ignored) {}
        }

        return results;
    }

    private static boolean isPlaceholder(String v) {
        if (v == null || v.isEmpty()) return true;
        String lower = v.toLowerCase();
        return lower.equals("null") || lower.equals("undefined")
                || lower.equals("password") || lower.equals("secret")
                || lower.equals("changeme") || lower.equals("example")
                || lower.startsWith("****") || lower.equals("your_password");
    }

    private static String mask(String v) {
        if (v == null || v.length() < 4) return "****";
        return v.substring(0, 2) + "****";
    }
}
