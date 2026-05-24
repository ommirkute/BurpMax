package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

class AuthBypassProbe {

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Only probe if the original request had auth
        boolean hasAuth = ctx.reqHeaders.containsKey("authorization")
                       || ctx.reqHeaders.containsKey("cookie");
        if (!hasAuth) return results;

        // Only probe authenticated endpoints (exclude login, public pages)
        String urlLower = ctx.url.toLowerCase();
        if (urlLower.contains("/login") || urlLower.contains("/signin")
                || urlLower.contains("/register") || urlLower.contains("/signup")) {
            return results;
        }

        // FALSE POSITIVE GUARD: require original response was 200 (authenticated success).
        // If the original returned 401/403, the endpoint is already blocking unauthenticated
        // access correctly — no bypass to test. If 404/5xx, irrelevant endpoint.
        if (ctx.originalResponse != null) {
            int origSc = extractStatus(ctx.originalResponse);
            if (origSc != 200) return results;
        }

        byte[] probeReq = removeAuthHeaders(ctx.originalRequest);
        HttpSender.Response resp = sender.send(ctx.service, probeReq);
        if (resp == null) return results;

        int originalStatus = ctx.originalResponse != null ? extractStatus(ctx.originalResponse) : 200;
        int probeStatus    = resp.statusCode();

        // Auth bypass: unauthenticated request returns same success status as authenticated
        if (probeStatus == 200 && originalStatus == 200) {
            String origBody  = ctx.originalResponse != null
                    ? new String(ctx.originalResponse) : "";
            String probeBody = resp.body();
            int origLen  = origBody.length();
            int probeLen = probeBody.length();

            // Use BOTH length AND content similarity to avoid false positives.
            // Length-only: two different 1000-byte pages both score 100% — misleading.
            double lengthRatio  = origLen > 0
                    ? (double) Math.min(probeLen, origLen) / Math.max(probeLen, origLen) : 0;
            double contentRatio = contentSimilarity(origBody, probeBody);

            // Both must agree — length similar AND content similar
            if (lengthRatio > 0.8 && contentRatio > 0.7 && probeBody.length() > 50) {
                results.add(new ActiveScanResult(
                    "Authentication Bypass - Endpoint Accessible Without Credentials", SEV_CRITICAL,
                    "The endpoint returned HTTP 200 with a similar response body when all " +
                    "authentication headers and cookies were removed. This indicates the endpoint " +
                    "is not enforcing authentication checks and is accessible without credentials.",
                    "With auth: HTTP " + originalStatus + " (" + origLen + " bytes) | " +
                    "Without auth: HTTP " + probeStatus + " (" + probeLen + " bytes) | " +
                    "Length similarity: " + String.format("%.0f%%", lengthRatio * 100) +
                    " | Content similarity: " + String.format("%.0f%%", contentRatio * 100),
                    "PRIMARY FIX - Centralised Authentication Enforcement:\n" +
                    "Apply authentication checks at the framework/middleware level, not per-route.\n" +
                    "  Spring Security: configure HttpSecurity.authorizeRequests() globally\n" +
                    "  Express.js: apply auth middleware before all route handlers\n" +
                    "  Django: use @login_required decorator or LoginRequiredMixin globally\n" +
                    "The default posture must be DENY; routes that are public must be\n" +
                    "explicitly opted-out, not the reverse.\n\n" +
                    "SECONDARY CONTROLS:\n" +
                    "- Automated regression tests: for every protected endpoint, assert that a\n" +
                    "  request without credentials returns 401/403, not 200.\n" +
                    "- API gateway: enforce authentication at the gateway layer before traffic\n" +
                    "  reaches the application server as a defence-in-depth control.\n" +
                    "- Remove or disable unused/debug endpoints in production deployments.",
                    "CWE-306", ctx.url, "Authorization/Cookie", "(removed)",
                    trunc(new String(probeReq), 300), trunc(probeBody, 200),
                    probeReq, resp.raw(), -1L));
            }
        }
        return results;
    }

    /**
     * Content similarity: computes word-set Jaccard index on the first 2000 chars.
     * Cheap heuristic — not a diff algorithm, but avoids the length-only false positive.
     */
    private static double contentSimilarity(String a, String b) {
        if (a == null || b == null) return 0;
        Set<String> wa = words(a.substring(0, Math.min(a.length(), 2000)));
        Set<String> wb = words(b.substring(0, Math.min(b.length(), 2000)));
        if (wa.isEmpty() && wb.isEmpty()) return 1.0;
        if (wa.isEmpty() || wb.isEmpty()) return 0;
        Set<String> intersection = new HashSet<>(wa);
        intersection.retainAll(wb);
        Set<String> union = new HashSet<>(wa);
        union.addAll(wb);
        return (double) intersection.size() / union.size();
    }

    private static Set<String> words(String s) {
        Set<String> set = new HashSet<>();
        for (String w : s.split("[^a-zA-Z0-9]+")) {
            if (w.length() > 3) set.add(w.toLowerCase());
        }
        return set;
    }

    private static byte[] removeAuthHeaders(byte[] req) {
        String s = new String(req, java.nio.charset.StandardCharsets.ISO_8859_1);
        s = s.replaceAll("(?im)^Authorization:[^\r\n]*\r\n", "");
        s = s.replaceAll("(?im)^Cookie:[^\r\n]*\r\n", "");
        return s.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    private static int extractStatus(byte[] resp) {
        try {
            String s = new String(resp, 0, Math.min(20, resp.length));
            String[] parts = s.split(" ", 3);
            return parts.length > 1 ? Integer.parseInt(parts[1].trim()) : 200;
        } catch (Exception e) { return 200; }
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IDOR Detection
// ─────────────────────────────────────────────────────────────────────────────
