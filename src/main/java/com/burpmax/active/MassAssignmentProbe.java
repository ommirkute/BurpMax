package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * Mass Assignment (parameter binding / over-posting) probe.
 *
 * Targets REST API endpoints that accept JSON or form bodies.
 * Injects extra fields that a backend ORM / binder might silently accept
 * (role escalation, privilege flags, internal state fields) and then confirms
 * the injection in two ways:
 *
 *  1. Response reflection - the injected field value appears in the response
 *     body of the same request (common on create/update endpoints that echo
 *     the saved resource).
 *
 *  2. Read-back confirmation - a follow-up GET to the same base URL returns
 *     the injected field value, indicating it was persisted to the backend.
 *
 * Only fires on state-changing methods (POST, PUT, PATCH, DELETE). GET/HEAD
 * requests cannot carry a meaningful body and are skipped.
 *
 * Tier: 2 (fast, 2-3 requests per endpoint, no sleep, no OOB).
 * Self-gates on Content-Type: only JSON bodies or form-encoded bodies get the
 * injected fields in the appropriate format.
 */
class MassAssignmentProbe {

    // ── Candidate fields to inject ────────────────────────────────────────────
    // Two categories:
    //  PRIV_FIELDS: high-sensitivity fields likely tied to access control.
    //               Confirmed if they appear in the response.
    //  STATE_FIELDS: internal lifecycle fields. Confirmed if they appear in response.
    //
    // Values are chosen to be distinctive enough to avoid false positives
    // from coincidental substring matches in HTML/JSON.
    private static final List<String[]> INJECT_FIELDS = List.of(
        // [fieldName, jsonValue, formValue, displayLabel]
        new String[]{"role",            "\"burpmax_admin_8741\"", "burpmax_admin_8741",    "role"},
        new String[]{"isAdmin",         "true",                  "true",                  "isAdmin"},
        new String[]{"is_admin",        "true",                  "true",                  "is_admin"},
        new String[]{"admin",           "true",                  "true",                  "admin"},
        new String[]{"verified",        "true",                  "true",                  "verified"},
        new String[]{"is_verified",     "true",                  "true",                  "is_verified"},
        new String[]{"status",          "\"burpmax_active_8741\"","burpmax_active_8741",   "status"},
        new String[]{"approved",        "true",                  "true",                  "approved"},
        new String[]{"active",          "true",                  "true",                  "active"},
        new String[]{"credits",         "99999",                 "99999",                 "credits"},
        new String[]{"balance",         "99999.99",              "99999.99",              "balance"},
        new String[]{"price",           "0.01",                  "0.01",                  "price"},
        new String[]{"discount",        "100",                   "100",                   "discount"},
        new String[]{"group",           "\"burpmax_admins_8741\"","burpmax_admins_8741",   "group"},
        new String[]{"permissions",     "[\"admin\",\"write\"]", "admin",                 "permissions"},
        new String[]{"account_type",    "\"burpmax_premium_8741\"","burpmax_premium_8741","account_type"},
        new String[]{"subscription",    "\"burpmax_paid_8741\"", "burpmax_paid_8741",     "subscription"},
        new String[]{"plan",            "\"burpmax_enterprise_8741\"","burpmax_enterprise_8741","plan"},
        new String[]{"user_id",         "0",                     "0",                     "user_id"},
        new String[]{"userId",          "0",                     "0",                     "userId"}
    );

    // Marker substring we can search for in responses (appears in every injected string value)
    private static final String MARKER = "burpmax";

    // ── Entry point ───────────────────────────────────────────────────────────

    static List<ActiveScanResult> probe(ProbeContext ctx,
                                        RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Only probe state-changing methods
        String method = ctx.method.toUpperCase();
        if (!method.equals("POST") && !method.equals("PUT")
                && !method.equals("PATCH") && !method.equals("DELETE")) {
            return results;
        }

        // Must have a body to inject into
        if (ctx.bodyRaw == null || ctx.bodyRaw.isEmpty()) return results;

        String ct = ctx.contentType != null ? ctx.contentType.toLowerCase() : "";
        boolean isJson = ct.contains("json");
        boolean isForm = ct.contains("x-www-form-urlencoded");

        if (!isJson && !isForm) return results;

        // Baseline response (needed for confirmation)
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        if (baseline == null) return results;

        // Try each candidate field
        for (String[] field : INJECT_FIELDS) {
            if (results.size() >= 3) break;  // cap findings per endpoint

            String fieldName  = field[0];
            String jsonVal    = field[1];
            String formVal    = field[2];
            String label      = field[3];

            // Skip if field already present in the original request (legitimate use)
            String bodyStr = ctx.bodyRaw;
            if (containsFieldName(bodyStr, fieldName)) continue;

            byte[] injectedReq = isJson
                    ? injectJsonField(ctx, fieldName, jsonVal)
                    : injectFormField(ctx, fieldName, formVal);
            if (injectedReq == null) continue;

            HttpSender.Response resp = sender.send(ctx.service, injectedReq);
            if (resp == null) continue;

            // ── Confirmation 1: response reflects the injected marker ────────
            boolean reflected = resp.body().contains(MARKER) && !baseline.body().contains(MARKER);

            // ── Confirmation 2: server didn't reject the field (2xx) ─────────
            // and response body changed (field was processed, not ignored)
            boolean accepted2xx = resp.statusCode() >= 200 && resp.statusCode() < 300;
            boolean bodyChanged = Math.abs(resp.body().length() - baseline.body().length()) > 5;

            if (reflected && accepted2xx) {
                results.add(buildFinding(ctx, label, fieldName,
                        isJson ? jsonVal : formVal, injectedReq, resp,
                        "injected field value reflected in response"));
                continue;
            }

            // ── Confirmation 3: read-back GET to base URL ─────────────────────
            // Only attempt if the method was POST (resource creation) and server
            // returned 2xx with a body that could contain an ID for follow-up GET.
            if (accepted2xx && bodyChanged && method.equals("POST")) {
                String locationOrBody = resp.header("location") != null
                        ? resp.header("location") : resp.body();
                String getUrl = extractResourceUrl(ctx.url, locationOrBody);
                if (getUrl != null) {
                    byte[] getReq = buildGetRequest(ctx, getUrl);
                    HttpSender.Response getResp = sender.send(ctx.service, getReq);
                    if (getResp != null && getResp.body().contains(MARKER)
                            && !baseline.body().contains(MARKER)) {
                        results.add(buildFinding(ctx, label, fieldName,
                                isJson ? jsonVal : formVal, injectedReq, getResp,
                                "injected field persisted - confirmed via GET read-back"));
                    }
                }
            }
        }

        return results;
    }

    // ── JSON field injection ──────────────────────────────────────────────────

    /**
     * Injects a new key-value pair into the first JSON object in the request body.
     * Handles nested objects by targeting the outermost level only.
     * Returns null if the body is not a parseable JSON object.
     */
    private static byte[] injectJsonField(ProbeContext ctx, String fieldName, String jsonValue) {
        try {
            String body = ctx.bodyRaw.trim();
            if (!body.startsWith("{")) return null;

            // Find last } to insert before it
            int lastBrace = body.lastIndexOf('}');
            if (lastBrace < 0) return null;

            // Determine if there are existing fields (to know whether to add a comma)
            String inner = body.substring(1, lastBrace).trim();
            String comma = inner.isEmpty() ? "" : ",";

            String injected = body.substring(0, lastBrace)
                    + comma + "\"" + fieldName + "\":" + jsonValue
                    + body.substring(lastBrace);

            return rebuildRequest(ctx, injected.getBytes(StandardCharsets.ISO_8859_1));
        } catch (Exception e) {
            return null;
        }
    }

    // ── Form field injection ──────────────────────────────────────────────────

    private static byte[] injectFormField(ProbeContext ctx, String fieldName, String formValue) {
        try {
            String body = ctx.bodyRaw;
            // URL-encode the value for safety (special chars in formValue are all ASCII here)
            String injected = body + (body.isEmpty() ? "" : "&") + fieldName + "=" + formValue;
            return rebuildRequest(ctx, injected.getBytes(StandardCharsets.ISO_8859_1));
        } catch (Exception e) {
            return null;
        }
    }

    // ── Request rebuild ───────────────────────────────────────────────────────

    /**
     * Rebuilds the original request bytes with a new body, updating Content-Length.
     * Follows the project convention: isolate header block at first CRLFCRLF,
     * strip Content-Length, append exactly one CRLFCRLF + new body.
     */
    private static byte[] rebuildRequest(ProbeContext ctx, byte[] newBody) {
        String req = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
        int sep = req.indexOf("\r\n\r\n");
        if (sep < 0) return null;

        String headerBlock = req.substring(0, sep);
        // Remove existing Content-Length (case-insensitive)
        headerBlock = headerBlock.replaceAll("(?im)^Content-Length:.*\r\n?", "");
        // Strip trailing CRLF from header block before we re-add CRLFCRLF
        headerBlock = headerBlock.stripTrailing();

        int newLen = newBody.length;
        String rebuilt = headerBlock
                + "\r\nContent-Length: " + newLen
                + "\r\n\r\n"
                + new String(newBody, StandardCharsets.ISO_8859_1);
        return rebuilt.getBytes(StandardCharsets.ISO_8859_1);
    }

    // ── Field presence check ──────────────────────────────────────────────────

    /** Returns true if fieldName is already present as a key in the body.
     *  Uses tight patterns to avoid false negatives from field names appearing
     *  inside JSON string values (e.g. {"error":"role: is required"}).
     */
    private static boolean containsFieldName(String body, String fieldName) {
        // JSON key pattern: "fieldName" followed by optional whitespace then colon
        // This anchors on the closing quote+colon to avoid matching inside values.
        if (body.contains("\"" + fieldName + "\":") ||
            body.contains("\"" + fieldName + "\" :")) return true;
        // Form-encoded: fieldName= at the start, after &, or at the start of the string
        // Use word-boundary approach: must be preceded by start or & and followed by =
        String formKey = fieldName + "=";
        int idx = body.indexOf(formKey);
        while (idx >= 0) {
            if (idx == 0 || body.charAt(idx - 1) == '&') return true;
            idx = body.indexOf(formKey, idx + 1);
        }
        return false;
    }

    // ── Read-back helpers ─────────────────────────────────────────────────────

    /**
     * Attempts to extract the URL of the newly created resource from a POST response.
     * Checks: Location header, "id" or "url" field in JSON body.
     */
    private static String extractResourceUrl(String baseUrl, String locationOrBody) {
        // Location header (201 Created pattern)
        if (locationOrBody.startsWith("http") || locationOrBody.startsWith("/")) {
            return locationOrBody.split("[\\s\"']")[0];
        }
        // JSON id field: extract numeric/uuid id and append to base URL
        Matcher m = Pattern.compile("\"(?:id|uuid|_id)\"\\s*:\\s*\"?([\\w-]{1,64})\"?")
                .matcher(locationOrBody);
        if (m.find()) {
            String id = m.group(1);
            String base = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
            return base + id;
        }
        return null;
    }

    /**
     * Builds a GET request for read-back confirmation, copying auth headers
     * (Authorization, Cookie, X-Api-Key, etc.) from the original request so
     * the read-back succeeds on protected endpoints.
     */
    private static byte[] buildGetRequest(ProbeContext ctx, String targetUrl) {
        // Extract auth headers from original request to include in the read-back GET
        String origReq = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
        String authHeaders = extractAuthHeaders(origReq);

        try {
            java.net.URL parsed = new java.net.URL(targetUrl);
            String pathQ = parsed.getFile();
            if (pathQ == null || pathQ.isEmpty()) pathQ = "/";
            String host = parsed.getHost();
            if (parsed.getPort() > 0) host += ":" + parsed.getPort();
            String raw = "GET " + pathQ + " HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "Accept: application/json\r\n"
                    + authHeaders
                    + "\r\n";
            return raw.getBytes(StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            // Fallback: convert original request to GET same path, preserving auth headers
            int crlf = origReq.indexOf("\r\n");
            String firstLine = crlf > 0 ? origReq.substring(0, crlf) : origReq;
            String[] parts = firstLine.split(" ", 3);
            if (parts.length < 2) return null;
            String path = parts[1];
            int sep = origReq.indexOf("\r\n\r\n");
            String headers = sep > 0 ? origReq.substring(0, sep) : origReq;
            headers = headers.replaceAll("(?im)^Content-(?:Length|Type):.*\r?\n?", "");
            headers = headers.replaceFirst("(?m)^\\w+ .+ HTTP/", "GET " + path + " HTTP/");
            return (headers.stripTrailing() + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        }
    }

    /**
     * Extracts auth-related headers from a raw HTTP request string,
     * formatted ready to append to a new request (each line ending with CRLF).
     */
    private static String extractAuthHeaders(String rawRequest) {
        StringBuilder sb = new StringBuilder();
        int headerEnd = rawRequest.indexOf("\r\n\r\n");
        String headerBlock = headerEnd > 0 ? rawRequest.substring(0, headerEnd) : rawRequest;
        for (String line : headerBlock.split("\r\n")) {
            String lower = line.toLowerCase();
            if (lower.startsWith("authorization:")
                    || lower.startsWith("cookie:")
                    || lower.startsWith("x-api-key:")
                    || lower.startsWith("x-auth-token:")
                    || lower.startsWith("x-access-token:")
                    || lower.startsWith("bearer:")) {
                sb.append(line).append("\r\n");
            }
        }
        return sb.toString();
    }

    // ── Finding builder ───────────────────────────────────────────────────────

    private static ActiveScanResult buildFinding(ProbeContext ctx,
                                                  String label, String fieldName,
                                                  String value,
                                                  byte[] probeReq, HttpSender.Response resp,
                                                  String confirmation) {
        return new ActiveScanResult(
            "Mass Assignment (Over-Posting)", SEV_HIGH,
            "A mass assignment vulnerability was confirmed on this endpoint. Injecting the " +
            "extra field '\"" + fieldName + "\"' (value: " + value + ") into the request body " +
            "was accepted by the server without rejection. The backend ORM or model binder " +
            "processed the field, allowing an attacker to set internal model attributes that " +
            "should not be user-controllable - including role, privilege flags, pricing, and " +
            "account lifecycle fields. Depending on the field, this can lead to privilege " +
            "escalation, authentication bypass, financial manipulation, or account takeover.",
            "Injected field: " + fieldName + " | Value: " + value
                + " | Confirmation: " + confirmation
                + " | Method: " + ctx.method + " | Endpoint: " + ctx.url,
            "PRIMARY FIX - Explicit allow-list binding:\\n" +
            "Never bind request body fields directly to domain model objects. Instead:\\n" +
            "  Spring:    use @JsonIgnore / @JsonProperty(access = READ_ONLY) on sensitive fields\\n" +
            "             or use DTOs with only the fields the endpoint should accept.\\n" +
            "  Rails:     params.require(:user).permit(:name, :email) - never permit(:all)\\n" +
            "  Django:    use serializer fields with read_only=True on sensitive attributes\\n" +
            "  Laravel:   use $fillable on models (never use $guarded = [])\\n" +
            "  Node/Mongoose: use .select() projection and schema validation\\n\\n" +
            "SECONDARY CONTROLS:\\n" +
            "- Validate input against a strict schema before binding to any model\\n" +
            "- Log and alert on unexpected fields in request bodies\\n" +
            "- Separate DTOs (Data Transfer Objects) from domain models in all layers\\n" +
            "- Apply field-level authorization: verify the caller has permission to set\\n" +
            "  each field they supply, not just permission to call the endpoint",
            "CWE-915",
            ctx.url, fieldName, value,
            trunc(new String(probeReq, StandardCharsets.ISO_8859_1), 400),
            trunc(resp.body(), 200),
            probeReq, resp.raw(), -1L
        );
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
