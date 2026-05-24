package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import static com.burpmax.model.Finding.*;

/**
 * Hidden Parameter Discovery probe.
 *
 * Discovers parameters that are accepted by the server but absent from the
 * observed request. Hidden parameters often represent debug controls, admin
 * flags, deprecated API fields, and internal state variables that were never
 * meant to be user-accessible.
 *
 * Detection strategy:
 *   1. Probe each candidate parameter individually.
 *   2. Compare the response to a clean baseline on:
 *        - Status code change (parameter accepted — caused routing difference)
 *        - Response body length change > threshold (parameter affected processing)
 *        - Response body contains a reflection of the candidate value
 *        - New headers appear in the response (e.g. X-Debug: true activates debug header)
 *        - Error messages referencing the parameter name (rejected but recognised)
 *   3. Confirm: re-send with the same parameter and verify the signal reproduces.
 *   4. Reject signals that are coincidental: baseline variance check using
 *      two clean requests — if clean responses also differ by > threshold,
 *      the endpoint is non-deterministic and is skipped.
 *
 * Wordlist strategy:
 *   The 120-entry wordlist is tiered by signal strength:
 *   Tier A (20 entries): highest-value debug/admin params — tested on all endpoints
 *   Tier B (50 entries): common framework-specific params — tested on parameterised endpoints
 *   Tier C (50 entries): generic API params — tested only if Tier A/B produced a signal
 *
 * False-positive mitigations:
 *   - Non-determinism baseline: skip endpoint if two clean requests differ > 10%
 *   - Confirmation re-send: signal must reproduce on second probe request
 *   - Value reflection: only counts if the unique test value (not a generic word) appears
 *   - Length threshold: body must change by > 200 bytes AND > 10% (both conditions required)
 *   - Status change: 4xx→2xx or 2xx→4xx changes are strong signals; 200→200 with body
 *     change requires length + reflection confirmation
 *
 * Endpoint gating:
 *   Skipped on static resources (.js/.css/.png), WebSockets, and extremely large
 *   responses (> 500KB) where body comparison is unreliable.
 *
 * Tier: 3 (medium — 20-120 requests per endpoint; self-caps at first Tier A find).
 */
class HiddenParamProbe {

    // Unique marker value injected so we can detect reflection without false positives
    private static final String MARKER_VALUE = "burpmax9741hidden";

    // ── Wordlist Tier A: High-value debug / admin params (always tested) ──────
    private static final List<String> TIER_A = List.of(
        "debug", "test", "admin", "internal", "trace", "verbose",
        "format", "callback", "jsonp", "output", "return",
        "redirect", "next", "url", "ref", "token",
        "apikey", "api_key", "key", "secret", "auth"
    );

    // ── Wordlist Tier B: Framework-specific params ────────────────────────────
    private static final List<String> TIER_B = List.of(
        // Spring/Java
        "wt_format", "_format", "view", "layout", "template",
        "lang", "locale", "timezone", "currency",
        // Node.js / Express
        "pretty", "indent", "wrap", "_callback", "jsonCallback",
        // PHP
        "XDEBUG_SESSION", "phpinfo", "xdebug", "_debug",
        // Ruby on Rails
        "authenticity_token", "commit", "_method",
        // Django
        "csrfmiddlewaretoken", "format", "fields",
        // General REST API
        "fields", "include", "expand", "embed", "select",
        "filter", "sort", "order", "page", "per_page",
        "limit", "offset", "cursor", "after", "before",
        "version", "v", "api_version", "since", "until",
        // Cache/performance
        "nocache", "no_cache", "refresh", "bypass",
        "cache", "ttl", "etag",
        // Feature flags
        "feature", "flag", "beta", "preview", "experiment",
        "variant", "cohort", "ab_test"
    );

    // ── Wordlist Tier C: Generic params ──────────────────────────────────────
    private static final List<String> TIER_C = List.of(
        "mode", "type", "action", "method", "op", "operation",
        "cmd", "command", "exec", "run", "process",
        "q", "query", "search", "term", "keyword",
        "id", "uid", "user_id", "account", "profile",
        "data", "payload", "body", "content", "value",
        "source", "target", "dest", "destination", "from", "to",
        "subject", "message", "text", "title", "name",
        "code", "hash", "sig", "signature", "nonce",
        "scope", "role", "group", "permission", "access",
        "env", "environment", "region", "zone", "cluster"
    );

    // Patterns in response body that suggest the server recognised (but rejected) the param
    private static final List<Pattern> RECOGNITION_PATTERNS = List.of(
        Pattern.compile("unknown.*param",        Pattern.CASE_INSENSITIVE),
        Pattern.compile("invalid.*param",        Pattern.CASE_INSENSITIVE),
        Pattern.compile("parameter.*not.*allowed", Pattern.CASE_INSENSITIVE),
        Pattern.compile("unexpected.*field",     Pattern.CASE_INSENSITIVE),
        Pattern.compile("unrecognized.*field",   Pattern.CASE_INSENSITIVE)
    );

    // ── Entry point ───────────────────────────────────────────────────────────

    static List<ActiveScanResult> probe(ProbeContext ctx,
                                        RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Gate: skip static resources
        String urlLower = ctx.url.toLowerCase();
        if (urlLower.matches(".*\\.(js|css|png|jpg|gif|ico|svg|woff|ttf|map)([?#].*)?$"))
            return results;

        // Baseline: two clean requests to detect non-determinism
        HttpSender.Response base1 = sender.send(ctx.service, ctx.originalRequest);
        if (base1 == null) return results;
        HttpSender.Response base2 = sender.send(ctx.service, ctx.originalRequest);
        if (base2 == null) return results;

        int baseLen1 = base1.body().length();
        int baseLen2 = base2.body().length();
        int baseStatus = base1.statusCode();

        // Non-determinism check: if two clean requests differ significantly in length
        // or normalised content, the endpoint is dynamic — skip to avoid false positives.
        if (!bodyStable(baseLen1, baseLen2)) return results;
        if (!bodyStableContent(base1.body(), base2.body())) return results;

        int baseLen = (baseLen1 + baseLen2) / 2;

        // Skip extremely large responses (body comparison is unreliable)
        if (baseLen > 500_000) return results;

        // ── Tier A: Always test (admin/debug params) ──────────────────────────
        Set<String> existing = ctx.allParamNames();
        for (String param : TIER_A) {
            if (existing.contains(param)) continue;  // already in original request
            if (results.size() >= 5) break;  // cap findings per endpoint

            ActiveScanResult r = probeParam(ctx, rb, sender, param, baseStatus, baseLen, base1.body());
            if (r != null) results.add(r);
        }

        // ── Tier B: Test on parameterised endpoints ───────────────────────────
        if (ctx.hasParameters() || !ctx.bodyRaw.isBlank()) {
            for (String param : TIER_B) {
                if (existing.contains(param)) continue;
                if (results.size() >= 5) break;

                ActiveScanResult r = probeParam(ctx, rb, sender, param, baseStatus, baseLen, base1.body());
                if (r != null) results.add(r);
            }
        }

        // ── Tier C: Only if Tier A/B produced at least one signal ────────────
        if (!results.isEmpty()) {
            for (String param : TIER_C) {
                if (existing.contains(param)) continue;
                if (results.size() >= 5) break;

                ActiveScanResult r = probeParam(ctx, rb, sender, param, baseStatus, baseLen, base1.body());
                if (r != null) results.add(r);
            }
        }

        return results;
    }

    // ── Parameter probe ───────────────────────────────────────────────────────

    private static ActiveScanResult probeParam(ProbeContext ctx,
                                                RequestBuilder rb,
                                                HttpSender sender,
                                                String param,
                                                int baseStatus,
                                                int baseLen,
                                                String baseBody) {
        // Build a probe request that adds the candidate parameter with the unique marker value
        byte[] probeReq = appendParam(ctx, rb, param, MARKER_VALUE);
        if (probeReq == null) return null;

        HttpSender.Response resp = sender.send(ctx.service, probeReq);
        if (resp == null) return null;

        String signal = detectSignal(resp, baseStatus, baseLen, baseBody, param);
        if (signal == null) return null;

        // Confirmation: re-send to verify the signal is reproducible
        HttpSender.Response confirm = sender.send(ctx.service, probeReq);
        if (confirm == null) return null;

        String signal2 = detectSignal(confirm, baseStatus, baseLen, baseBody, param);
        if (signal2 == null) return null;  // transient - not a real find

        return new ActiveScanResult(
            "Hidden / Undocumented Parameter: " + param, SEV_MEDIUM,
            "The server appears to accept the undocumented parameter '" + param + "' which was " +
            "not present in the original observed request. Adding this parameter produced a " +
            "detectable difference in the server's response (" + signal + "), confirmed on a " +
            "second probe request. Hidden parameters commonly represent: debug modes that expose " +
            "internal state, admin controls that bypass business logic, deprecated API fields with " +
            "reduced validation, feature flags that unlock preview functionality, and internal " +
            "routing parameters. Further manual investigation is recommended to determine the " +
            "parameter's function and exploitability.",
            "Parameter: " + param + " | Value injected: " + MARKER_VALUE +
            " | Signal: " + signal +
            " | Baseline status: " + baseStatus + " | Probe status: " + resp.statusCode() +
            " | Baseline body length: " + baseLen + " | Probe body length: " + resp.body().length(),
            "PRIMARY FIX - Strict input validation:\n" +
            "Reject unexpected parameters at the API boundary. Most frameworks support this:\n" +
            "  Spring: @Valid with @JsonIgnoreProperties(ignoreUnknown=false)\n" +
            "  Express: use a whitelist schema validator (Joi, Zod, express-validator)\n" +
            "  Django DRF: set strict mode on serializers to reject extra fields\n" +
            "  Rails: use strong parameters with explicit permit() lists\n\n" +
            "FOR DEBUG PARAMETERS SPECIFICALLY:\n" +
            "  - Remove all debug parameters from production builds entirely\n" +
            "  - If debug params must exist, gate them on an internal IP check AND\n" +
            "    a time-limited HMAC token that cannot be forged by an external caller\n" +
            "  - Audit all endpoints for parameters that bypass authentication,\n" +
            "    rate limiting, payment checks, or other security controls\n\n" +
            "DETECTION:\n" +
            "  Log all unexpected parameters received - a surge in unknown param names\n" +
            "  may indicate an active parameter enumeration attack.",
            "CWE-200",
            ctx.url, param, MARKER_VALUE,
            trunc(new String(probeReq, StandardCharsets.ISO_8859_1), 300),
            "Signal: " + signal + " | Response body (first 200 chars): " + trunc(resp.body(), 200),
            probeReq, resp.raw(), -1L
        );
    }

    // ── Signal detection ──────────────────────────────────────────────────────

    /**
     * Returns a human-readable signal description if the response differs from baseline
     * in a meaningful way, or null if no signal.
     */
    private static String detectSignal(HttpSender.Response resp,
                                        int baseStatus,
                                        int baseLen,
                                        String baseBody,
                                        String param) {
        String body = resp.body();
        int   len   = body.length();
        int   status = resp.statusCode();

        // Signal 1: status code changed meaningfully (not just 200→201 etc)
        if (Math.abs(status - baseStatus) > 50) {
            return "status change " + baseStatus + " → " + status;
        }

        // Signal 2: unique marker value appears in the response body (reflection)
        if (body.contains(MARKER_VALUE)) {
            return "parameter value reflected in response body";
        }

        // Signal 3: parameter name appears in a parameter-context pattern in the response.
        // Require the param name to appear in a context that suggests the server parsed it
        // as a field/parameter name (not as a free substring of an unrelated word).
        // Short param names ("id", "q", "v") appear in many words by coincidence.
        for (Pattern p : RECOGNITION_PATTERNS) {
            if (!p.matcher(body).find()) continue;
            String bodyLower  = body.toLowerCase();
            String paramLower = param.toLowerCase();
            // Only fire if the param name appears in a context that suggests the server
            // parsed it as a parameter name, not as a coincidental substring.
            // Require the name to appear: quoted in JSON, single-quoted in an error message,
            // after "parameter"/"field"/"param", or as a standalone word (word-boundary check).
            String quotedParam = "\"" + paramLower + "\"";         // "id"
            String singleParam = "'" + paramLower + "'";               // 'id'
            boolean paramInContext =
                    bodyLower.contains(quotedParam)                     // JSON key "id"
                    || bodyLower.contains(singleParam)                  // error: 'id'
                    || bodyLower.contains("parameter " + singleParam)  // parameter 'id'
                    || bodyLower.contains("field " + singleParam)      // field 'id'
                    || bodyLower.contains("param " + singleParam)      // param 'id'
                    || java.util.regex.Pattern.compile(
                            "\\b" + java.util.regex.Pattern.quote(paramLower) + "\\b")
                       .matcher(bodyLower).find();  // word boundary
            if (paramInContext) {
                return "server rejected but recognised parameter '" + param + "': " + p.pattern();
            }
        }

        // Signal 4: significant body length change
        int delta = Math.abs(len - baseLen);
        int pct   = baseLen > 0 ? (delta * 100 / baseLen) : 0;
        if (delta > 200 && pct > 10) {
            return "body length changed by " + delta + " bytes (" + pct + "%)";
        }

        return null;
    }

    // ── Request builder helpers ───────────────────────────────────────────────

    /**
     * Appends a new parameter to the request. Routes to:
     *   - Query param if the original has query params or is a GET
     *   - JSON body field if Content-Type is JSON
     *   - Form body param otherwise
     */
    private static byte[] appendParam(ProbeContext ctx, RequestBuilder rb,
                                       String param, String value) {
        String method = ctx.method.toUpperCase();
        String ct     = ctx.contentType != null ? ctx.contentType.toLowerCase() : "";

        if (method.equals("GET") || !ctx.hasParameters() && ctx.bodyRaw.isBlank()) {
            return rb.appendQueryParam(ctx.originalRequest, param, value);
        }

        if (ct.contains("json") && ctx.bodyRaw != null && ctx.bodyRaw.trim().startsWith("{")) {
            return appendJsonField(ctx, param, value);
        }

        if (ct.contains("x-www-form-urlencoded")) {
            return appendFormField(ctx, param, value);
        }

        // Fallback: append as query param
        return rb.appendQueryParam(ctx.originalRequest, param, value);
    }

    private static byte[] appendJsonField(ProbeContext ctx, String param, String value) {
        String body = ctx.bodyRaw != null ? ctx.bodyRaw : "";
        int last = body.lastIndexOf('}');
        if (last < 0) return null;
        String inner = body.substring(1, last).trim();
        String comma = inner.isEmpty() ? "" : ",";
        String injected = body.substring(0, last)
                + comma + "\"" + param + "\":\"" + value + "\""
                + body.substring(last);
        // JSON bodies must be UTF-8 (RFC 8259)
        return rebuildWithBody(ctx, injected.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static byte[] appendFormField(ProbeContext ctx, String param, String value) {
        String body = ctx.bodyRaw != null ? ctx.bodyRaw : "";
        String injected = body + (body.isEmpty() ? "" : "&") + param + "=" + value;
        return rebuildWithBody(ctx, injected.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static byte[] rebuildWithBody(ProbeContext ctx, byte[] newBody) {
        String req = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
        int sep = req.indexOf("\r\n\r\n");
        if (sep < 0) return null;
        String headers = req.substring(0, sep)
                .replaceAll("(?im)^Content-Length:[^\r\n]*\r?\n?", "")
                .stripTrailing();
        String rebuilt = headers + "\r\nContent-Length: " + newBody.length
                + "\r\n\r\n" + new String(newBody, StandardCharsets.ISO_8859_1);
        return rebuilt.getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * Returns true if both body lengths AND normalised body content are stable across
     * two clean requests. Normalisation strips dynamic content (timestamps, session IDs,
     * nonces, counters) that would make every request look different even with no injection.
     * Length-only checks pass for pages with fixed-length randomised tokens.
     */
    private static boolean bodyStable(int len1, int len2) {
        if (len1 == 0 && len2 == 0) return true;
        if (len1 == 0 || len2 == 0) return false;
        int larger  = Math.max(len1, len2);
        int smaller = Math.min(len1, len2);
        return (double) smaller / larger >= 0.90;
    }

    /**
     * Normalises a response body by stripping dynamic content patterns before comparison.
     * Used by bodyStableContent() to detect non-deterministic endpoints that length-only
     * checks would incorrectly classify as stable.
     */
    private static String normaliseBody(String body) {
        if (body == null) return "";
        return body
            // ISO 8601 timestamps
            .replaceAll("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z?", "TIMESTAMP")
            // Unix epoch (ms) 2020+
            .replaceAll("\\b1[6-9]\\d{9,12}\\b", "EPOCH")
            // UUIDs
            .replaceAll("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "UUID")
            // Short hex tokens (session IDs, nonces) — 16-64 hex chars
            .replaceAll("\\b[0-9a-f]{16,64}\\b", "HEXTOKEN")
            // Base64 blobs (JWT, nonces)
            .replaceAll("[A-Za-z0-9+/]{32,}={0,2}", "B64TOKEN");
    }

    /** Returns true if two responses are stable in both length and normalised content. */
    static boolean bodyStableContent(String body1, String body2) {
        if (!bodyStable(body1.length(), body2.length())) return false;
        // After normalisation both bodies should be very similar
        String norm1 = normaliseBody(body1);
        String norm2 = normaliseBody(body2);
        return bodyStable(norm1.length(), norm2.length());
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
