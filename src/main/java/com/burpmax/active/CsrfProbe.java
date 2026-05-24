package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

class CsrfProbe {

    private static final Set<String> CSRF_TOKEN_NAMES = Set.of(
        "csrf", "csrf_token", "_csrf", "csrftoken", "csrf-token",
        "xsrf", "xsrf_token", "_xsrf", "xsrftoken",
        "authenticity_token", "_token", "form_token", "nonce",
        "__requestverificationtoken", "x-csrf-token", "x-xsrf-token"
    );

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Only check POST endpoints — CSRF only matters for state-changing requests
        if (!"POST".equalsIgnoreCase(ctx.method) && !"PUT".equalsIgnoreCase(ctx.method)
                && !"DELETE".equalsIgnoreCase(ctx.method)) return results;

        // Exclude authentication endpoints: login CSRF has near-zero real-world impact
        // (attacker logging victim into attacker's account is low severity and rarely
        // exploitable), and these endpoints return 401 without cookies by design —
        // which the probe misinterprets as "auth required, CSRF matters".
        String pathLower = ctx.url.toLowerCase();
        if (pathLower.contains("/login") || pathLower.contains("/signin")
                || pathLower.contains("/sign-in") || pathLower.contains("/auth")
                || pathLower.contains("/token") || pathLower.contains("/oauth")) return results;

        // Check if any CSRF token parameter exists in the request
        boolean hasToken = ctx.allParamNames().stream()
                .anyMatch(p -> CSRF_TOKEN_NAMES.contains(p.toLowerCase()));

        // Check for CSRF token in headers
        boolean hasHeaderToken = ctx.reqHeaders.keySet().stream()
                .anyMatch(h -> CSRF_TOKEN_NAMES.contains(h.toLowerCase()));

        // Check for SameSite=Strict/Lax cookies (modern CSRF protection)
        // We don't have cookie context here — this is purely parameter-based

        if (!hasToken && !hasHeaderToken) {
            // Try removing SameSite-equivalent: send request without Cookie header
            // and see if it still returns 200 (confirming no other CSRF protection)
            byte[] probeReq = removeCookieHeader(ctx.originalRequest);
            HttpSender.Response resp = sender.send(ctx.service, probeReq);

            // If 200 without cookies it means endpoint is public, not a CSRF issue
            // If 403/401 without cookies — auth required, so CSRF still matters
            // Real CSRF issue: authenticated endpoint with no token
            // Only fire when removing cookies triggers a proper auth challenge (401/403).
            // 400 (bad request for missing fields), 404, and 500 are not auth failures —
            // they indicate the endpoint is misconfigured or irrelevant, not CSRF-vulnerable.
            int noCookieStatus = resp != null ? resp.statusCode() : 0;
            if (noCookieStatus == 401 || noCookieStatus == 403) {
                // Endpoint requires auth but has no CSRF token
                results.add(new ActiveScanResult(
                    "CSRF: Missing Anti-CSRF Token on State-Changing Endpoint", SEV_MEDIUM,
                    "The " + ctx.method + " endpoint appears to require authentication " +
                    "(returning HTTP " + noCookieStatus + " without cookies) but does not " +
                    "include an anti-CSRF token in its parameters or headers. An attacker can " +
                    "craft a malicious page that triggers this request in the victim's browser " +
                    "using the victim's session cookies, performing actions on their behalf.",
                    ctx.method + " " + ctx.url + " has no CSRF token parameter or header. " +
                    "Without-cookie response: HTTP " + noCookieStatus,
                    "PRIMARY FIX - SameSite Cookies (modern):\n" +
                    "Set SameSite=Lax (minimum) or SameSite=Strict on all session cookies.\n" +
                    "SameSite=Lax blocks cross-site POST requests while allowing GET navigation.\n" +
                    "SameSite=Strict blocks all cross-site requests including navigation.\n" +
                    "ALTERNATIVE - Synchroniser Token Pattern:\n" +
                    "Generate a cryptographically random per-session CSRF token, embed it in\n" +
                    "every state-changing form and AJAX request, validate server-side.\n" +
                    "Spring Security, Django, and Rails implement this automatically when enabled.\n" +
                    "SECONDARY CONTROLS:\n" +
                    "- Verify Origin/Referer header on state-changing requests as additional check.\n" +
                    "- Double Submit Cookie pattern for stateless/API architectures.\n" +
                    "- Require re-authentication for high-value actions (password change, transfers).",
                    "CWE-352", ctx.url, "csrf_token", "(absent)",
                    trunc(new String(ctx.originalRequest), 300),
                    "HTTP " + noCookieStatus + " returned without Cookie header",
                    ctx.originalRequest, resp.raw(), -1L));
            }
        }
        return results;
    }

    private static byte[] removeCookieHeader(byte[] req) {
        String s = new String(req, java.nio.charset.StandardCharsets.ISO_8859_1);
        String cleaned = s.replaceAll("(?im)^Cookie:[^\r\n]*\r\n", "");
        return cleaned.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    }
    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Authentication Bypass (remove auth headers/cookies)
// ─────────────────────────────────────────────────────────────────────────────
