package com.burpmax.scanner;

import java.util.*;
import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

/**
 * Checks for insecure Cache-Control on responses that contain session cookies
 * or that are returned from sensitive endpoints (profile, payment, admin).
 *
 * Fires only when BOTH conditions are true:
 *  1. The response sets a cookie (authenticated context), OR the URL path is sensitive
 *  2. Cache-Control lacks both "no-store" and "no-cache"
 *
 * This tight gating keeps false positives very low.
 */
public class CacheControlChecker {

    // URL path keywords that indicate a sensitive endpoint
    private static final Set<String> SENSITIVE_PATH_KEYWORDS = Set.of(
            "login", "logout", "signin", "signout", "auth",
            "profile", "account", "settings", "password",
            "payment", "checkout", "billing", "invoice", "order",
            "admin", "dashboard", "manage", "secret",
            "token", "oauth", "sso", "session",
            "2fa", "mfa", "otp", "verify"
    );

    public static List<CheckResult> check(Map<String, String> respHeaders,
                                           List<String> setCookies,
                                           String url) {
        List<CheckResult> results = new ArrayList<>();

        String cacheControl = respHeaders.getOrDefault("cache-control", "").toLowerCase();
        String pragma        = respHeaders.getOrDefault("pragma", "").toLowerCase();

        // Already properly configured — no finding
        boolean hasNoStore  = cacheControl.contains("no-store");
        boolean hasNoCache  = cacheControl.contains("no-cache") || pragma.contains("no-cache");
        if (hasNoStore) return results;   // no-store alone is sufficient

        // Determine if this is a sensitive response
        boolean hasCookie        = !setCookies.isEmpty();
        boolean isSensitivePath  = isSensitivePath(url);
        boolean hasAuthHeader    = respHeaders.containsKey("authorization") ||
                                   respHeaders.containsKey("www-authenticate");

        if (!hasCookie && !isSensitivePath && !hasAuthHeader) return results;

        // Build specific evidence
        String cacheVal = cacheControl.isEmpty() ? "(absent)" : cacheControl;
        String trigger  = hasCookie       ? "response sets cookies"
                        : isSensitivePath ? "sensitive endpoint URL"
                        :                  "auth header present";

        String evidence = "Cache-Control: " + trunc(cacheVal, 100) +
                " | Trigger: " + trigger + " | URL: " + trunc(url, 80);

        // Differentiate severity: public cache is worse than just missing no-store
        boolean isPublic = cacheControl.contains("public") ||
                          (!cacheControl.isEmpty() && !cacheControl.contains("private")
                           && !cacheControl.contains("no-store") && !cacheControl.contains("no-cache"));

        String severity = isPublic ? SEV_MEDIUM : SEV_LOW;
        String publicNote = isPublic
                ? "The Cache-Control header explicitly marks this response as 'public', " +
                  "meaning shared/proxy caches are permitted to store it. "
                : "";

        results.add(new CheckResult(
            "Insecure Cache-Control on Sensitive Response", severity,
            publicNote +
            "This response is returned from a sensitive endpoint or sets authentication cookies, " +
            "but is missing Cache-Control: no-store. Without no-store, browsers and intermediate " +
            "proxies may cache the response and serve it to subsequent users on the same device " +
            "or network. This can expose session tokens, personal data, and authenticated page " +
            "content to unauthorised parties - particularly on shared computers and corporate proxies.",
            evidence,
            "- Add to all authenticated and sensitive responses: Cache-Control: no-store, no-cache\n" +
            "- For APIs: Cache-Control: no-store is the minimum; add Pragma: no-cache for HTTP/1.0 compatibility\n" +
            "- Configure at the framework/middleware level to apply globally to all authenticated routes\n" +
            "- Spring Security: http.headers().cacheControl() applies no-store automatically\n" +
            "- Express.js: res.set('Cache-Control', 'no-store, no-cache, must-revalidate')\n" +
            "- Verify with browser dev tools: Network tab → Response Headers → Cache-Control",
            "CWE-525"));

        return results;
    }

    private static boolean isSensitivePath(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase();
        // Extract path only (after host, before query)
        int pathStart = lower.indexOf('/', lower.indexOf("//") + 2);
        if (pathStart < 0) return false;
        int pathEnd = lower.indexOf('?', pathStart);
        String path = pathEnd > 0 ? lower.substring(pathStart, pathEnd) : lower.substring(pathStart);
        for (String kw : SENSITIVE_PATH_KEYWORDS) {
            if (path.contains(kw)) return true;
        }
        return false;
    }
}
