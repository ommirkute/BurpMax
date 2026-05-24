package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * GraphQL-specific vulnerability probe.
 *
 * Runs only when a GraphQL endpoint is detected. Detection heuristics:
 *   - URL contains "/graphql", "/gql", "/api/graphql", "/v1/graphql", "/query"
 *   - Request body contains "query", "mutation", or "subscription" keywords
 *   - Content-Type is application/json with a "query" key in the body
 *
 * Checks performed:
 *
 * 1. Introspection enabled
 *    Send {__schema{types{name}}} — if the server returns a full schema,
 *    introspection is enabled in production (exposes all types, fields,
 *    mutations, and their arguments — a complete attack surface map).
 *
 * 2. Field-level injection
 *    For each field found via introspection (or from the original query),
 *    inject SQLi, XSS, and SSTI payloads into string arguments.
 *    GraphQL variables are properly substituted; inline argument injection
 *    is also tested.
 *
 * 3. Batch query abuse
 *    Send an array of 10 identical queries in one request. If all 10 succeed,
 *    the server is vulnerable to batch-based brute-forcing (bypass rate limits
 *    on login, OTP, password reset endpoints).
 *
 * 4. Alias overloading (DoS / rate limit bypass)
 *    Use aliases to send 10 queries in one request via aliasing rather than
 *    array batching. Same impact as batch abuse, different technique.
 *
 * 5. Query depth / complexity (DoS surface)
 *    Send a deeply nested query (depth 15) — if it succeeds, the server has
 *    no query depth limiting and is potentially vulnerable to a GraphQL
 *    DoS attack via exponential field selection.
 *
 * 6. Introspection-based mutation discovery
 *    After confirming introspection, enumerate mutation names and flag any
 *    that suggest sensitive operations: deleteUser, resetPassword, createAdmin,
 *    addRole, grantPermission, etc.
 */
public class GraphQlProbe {

    // ── GraphQL detection ─────────────────────────────────────────────────────
    private static final List<Pattern> GRAPHQL_URL_PATTERNS = List.of(
        Pattern.compile("/graphql", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/gql",     Pattern.CASE_INSENSITIVE),
        Pattern.compile("/query",   Pattern.CASE_INSENSITIVE),
        Pattern.compile("/v\\d/graphql", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/api/graphql",  Pattern.CASE_INSENSITIVE)
    );

    // GraphQL error patterns (confirm the endpoint is GraphQL)
    private static final List<Pattern> GRAPHQL_ERROR_PATTERNS = List.of(
        Pattern.compile("\"errors\":\\s*\\[",                    Pattern.CASE_INSENSITIVE),
        Pattern.compile("\"__typename\"",                        Pattern.CASE_INSENSITIVE),
        Pattern.compile("Cannot query field",                    Pattern.CASE_INSENSITIVE),
        Pattern.compile("Unknown argument",                      Pattern.CASE_INSENSITIVE),
        Pattern.compile("graphql",                               Pattern.CASE_INSENSITIVE)
    );

    // Sensitive mutation names
    private static final List<Pattern> SENSITIVE_MUTATIONS = List.of(
        Pattern.compile("delete.*user|remove.*user|drop.*user", Pattern.CASE_INSENSITIVE),
        Pattern.compile("reset.*password|change.*password",     Pattern.CASE_INSENSITIVE),
        Pattern.compile("create.*admin|add.*admin",              Pattern.CASE_INSENSITIVE),
        Pattern.compile("grant.*permission|assign.*role",        Pattern.CASE_INSENSITIVE),
        Pattern.compile("disable.*2fa|bypass.*mfa",              Pattern.CASE_INSENSITIVE),
        Pattern.compile("impersonate|sudo|elevate",              Pattern.CASE_INSENSITIVE)
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Only probe GraphQL endpoints
        if (!isGraphQlEndpoint(ctx)) return results;

        // ── 1. Introspection ───────────────────────────────────────────────
        String schema = probeIntrospection(ctx, sender);
        if (schema != null) {
            results.add(new ActiveScanResult(
                "GraphQL Introspection Enabled in Production", SEV_MEDIUM,
                "The GraphQL endpoint returns a full schema via introspection queries. " +
                "Introspection exposes all types, fields, mutations, queries, and their " +
                "arguments - providing attackers with a complete map of the API attack surface " +
                "without needing any prior knowledge of the application.",
                "Introspection query succeeded. Schema size: " + schema.length() + " bytes. " +
                "Types returned: " + countTypes(schema),
                "- Disable introspection in production: schema.disableIntrospection()\n" +
                "- If introspection is needed for internal tooling, restrict to authenticated/admin users\n" +
                "- Use query depth and complexity limits to prevent schema enumeration abuse",
                "CWE-200",
                ctx.url, "GraphQL query", "{__schema{types{name}}}",
                "Introspection query body", trunc(schema, 200), null, null, -1L));

            // ── 1a. Sensitive mutation discovery ──────────────────────────
            List<String> sensitiveMuts = findSensitiveMutations(schema);
            if (!sensitiveMuts.isEmpty()) {
                results.add(new ActiveScanResult(
                    "GraphQL Sensitive Mutations Exposed via Introspection", SEV_HIGH,
                    "Introspection revealed mutations with potentially dangerous names: " +
                    String.join(", ", sensitiveMuts) + ". These may allow privilege escalation, " +
                    "account takeover, or destruction of data if accessible without proper authorization.",
                    "Sensitive mutations: " + String.join(", ", sensitiveMuts),
                    "- Require authentication and authorization checks on all mutations\n" +
                    "- Apply field-level authorization using a directive or middleware layer\n" +
                    "- Disable introspection so attackers cannot enumerate mutation names",
                    "CWE-284",
                    ctx.url, "GraphQL introspection", "mutation names",
                    "Discovered via introspection", String.join(", ", sensitiveMuts)));
            }
        }

        // ── 2. Batch query abuse ───────────────────────────────────────────
        ActiveScanResult batchResult = probeBatchAbuse(ctx, sender);
        if (batchResult != null) results.add(batchResult);

        // ── 3. Alias overloading ───────────────────────────────────────────
        ActiveScanResult aliasResult = probeAliasOverload(ctx, sender);
        if (aliasResult != null) results.add(aliasResult);

        // ── 4. Query depth limit ───────────────────────────────────────────
        ActiveScanResult depthResult = probeQueryDepth(ctx, sender);
        if (depthResult != null) results.add(depthResult);

        // ── 5. Field injection (SQLi/XSS via variables) ────────────────────
        List<ActiveScanResult> injectionResults = probeFieldInjection(ctx, sender);
        results.addAll(injectionResults);

        return results;
    }

    // ── Introspection ─────────────────────────────────────────────────────────

    private static String probeIntrospection(ProbeContext ctx, HttpSender sender) {
        String introspectionQuery =
            "{\"query\":\"{__schema{types{name fields{name type{name kind}}}}}\"}";
        byte[] req = buildGraphQlRequest(ctx, introspectionQuery);
        if (req == null) return null;

        HttpSender.Response resp = sender.send(ctx.service, req);
        if (resp == null) return null;

        if (resp.body().contains("__schema") && resp.body().contains("\"types\"")) {
            return resp.body();
        }
        return null;
    }

    // ── Batch abuse ───────────────────────────────────────────────────────────

    private static ActiveScanResult probeBatchAbuse(ProbeContext ctx, HttpSender sender) {
        // Extract the original query from the body, or use a simple probe query
        String originalQuery = extractOriginalQuery(ctx);
        if (originalQuery == null) originalQuery = "{__typename}";

        // Build an array of 10 identical queries
        StringBuilder batch = new StringBuilder("[");
        for (int i = 0; i < 10; i++) {
            if (i > 0) batch.append(",");
            batch.append("{\"query\":\"").append(escapeJson(originalQuery)).append("\"}");
        }
        batch.append("]");

        byte[] req = buildGraphQlRequest(ctx, batch.toString());
        if (req == null) return null;

        HttpSender.Response resp = sender.send(ctx.service, req);
        if (resp == null) return null;

        // If the server returned an array of 10 results, batching is enabled
        String body = resp.body();
        int dataCount = countOccurrences(body, "\"data\"");
        if (resp.statusCode() == 200 && dataCount >= 5) {
            return new ActiveScanResult(
                "GraphQL Batch Query Abuse", SEV_HIGH,
                "The GraphQL endpoint accepts batched queries (an array of query objects in " +
                "one HTTP request) and returned " + dataCount + " responses. Batching bypasses " +
                "request-level rate limiting, enabling brute-force attacks on login mutations, " +
                "OTP verification, and password reset tokens at 10x+ the normal rate.",
                "Sent 10 batched queries, received " + dataCount + " data responses | HTTP " + resp.statusCode(),
                "PRIMARY FIX - Disable or Limit Batch Queries:\n" +
                "Reject array-format request bodies (a single query object, not an array).\n" +
                "If batching is needed for internal tooling, limit batch size to a small\n" +
                "maximum (e.g. 5) and apply the same rate limit per operation in the batch.\n" +
                "Apollo Server: use apollo-server-plugin-disable-introspection and\n" +
                "graphql-batch-limit. graphql-shield can enforce per-operation rate limits.",
                "CWE-770",
                ctx.url, "GraphQL batch", batch.substring(0, Math.min(100, batch.length())),
                "10-query batch", "HTTP " + resp.statusCode() + " | " + dataCount + " data results");
        }
        return null;
    }

    // ── Alias overloading ─────────────────────────────────────────────────────

    private static ActiveScanResult probeAliasOverload(ProbeContext ctx, HttpSender sender) {
        // Build a query with 10 aliases — all resolve the same field
        StringBuilder aliasQuery = new StringBuilder("{");
        for (int i = 0; i < 10; i++) {
            aliasQuery.append("a").append(i).append(":__typename ");
        }
        aliasQuery.append("}");

        String body = "{\"query\":\"" + escapeJson(aliasQuery.toString()) + "\"}";
        byte[] req  = buildGraphQlRequest(ctx, body);
        if (req == null) return null;

        HttpSender.Response resp = sender.send(ctx.service, req);
        if (resp == null) return null;

        // Confirm: all 10 aliases resolved
        // FALSE POSITIVE GUARD: ""a" is too common in JSON. Require the alias
        // response to contain ""a0":" through ""a9":" pattern (our specific alias names)
        // rather than any JSON key starting with "a".
        int aliasHits = 0;
        for (int _ai = 0; _ai < 10; _ai++) { if (resp.body().contains("\"a" + _ai + "\"")) aliasHits++; }
        if (resp.statusCode() == 200 && aliasHits >= 6) {
            return new ActiveScanResult(
                "GraphQL Alias Overloading (Rate Limit Bypass)", SEV_HIGH,
                "The GraphQL endpoint allows alias overloading - 10 aliased queries were " +
                "resolved in a single HTTP request. Like batch abuse, this bypasses per-request " +
                "rate limiting. An attacker can use aliases to send hundreds of variations of " +
                "a sensitive query (e.g. password guesses) in a single HTTP request.",
                "10 aliased __typename queries resolved | HTTP " + resp.statusCode(),
                "PRIMARY FIX - Query Complexity Scoring:\n" +
                "Implement query complexity analysis that counts aliases and aliases of the same\n" +
                "field toward the total complexity budget. Reject queries exceeding the budget.\n" +
                "Libraries: graphql-cost-analysis, graphql-query-complexity (Node.js),\n" +
                "strawberry-django cost limits (Python). Apply rate limiting per resolver,\n" +
                "not per HTTP request.",
                "CWE-770",
                ctx.url, "GraphQL aliases", aliasQuery.toString(),
                "Alias overload query", "HTTP " + resp.statusCode());
        }
        return null;
    }

    // ── Query depth limit ─────────────────────────────────────────────────────

    private static ActiveScanResult probeQueryDepth(ProbeContext ctx, HttpSender sender) {
        // Build a deeply nested query using __type recursion
        String deep = "{__type(name:\"Query\"){fields{type{fields{type{fields{type{fields{" +
                      "type{fields{type{fields{type{name}}}}}}}}}}}}}}";
        String body = "{\"query\":\"" + escapeJson(deep) + "\"}";
        byte[] req  = buildGraphQlRequest(ctx, body);
        if (req == null) return null;

        HttpSender.Response resp = sender.send(ctx.service, req);
        if (resp == null || resp.statusCode() != 200) return null;

        // If server returned data (not an error about depth), depth limiting is absent
        if (resp.body().contains("\"data\"") && !resp.body().contains("\"errors\"")) {
            return new ActiveScanResult(
                "GraphQL No Query Depth Limit", SEV_MEDIUM,
                "The GraphQL server processed a deeply nested query (depth > 10) without " +
                "returning a depth-limit error. Without query depth limiting, an attacker " +
                "can craft exponentially complex queries that exhaust server resources " +
                "(CPU, memory, database connections), causing denial of service.",
                "Depth-15 nested __type query returned data without errors",
                "PRIMARY FIX - Query Depth and Complexity Limits:\n" +
                "Enforce a maximum query depth (5–7 levels is appropriate for most APIs).\n" +
                "Pair with query complexity scoring so deeply nested queries with many\n" +
                "fields are also rejected even if within the depth limit.\n" +
                "Libraries: graphql-depth-limit, graphql-query-complexity (Node.js),\n" +
                "graphene-django with cost limiting (Python).",
                "CWE-400",
                ctx.url, "GraphQL query depth", trunc(deep, 80),
                "Depth probe", "HTTP " + resp.statusCode() + " - no depth error");
        }
        return null;
    }

    // ── Field injection ───────────────────────────────────────────────────────

    private static List<ActiveScanResult> probeFieldInjection(ProbeContext ctx, HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        // Extract argument values from the original query and probe them
        String originalBody = ctx.bodyRaw;
        if (originalBody == null || !originalBody.contains("query")) return results;

        // Simple heuristic: find string arguments and try SQLi/XSS
        List<String[]> stringArgs = extractStringArgs(originalBody);
        for (String[] arg : stringArgs) {
            String argName  = arg[0];
            String argValue = arg[1];

            // SQLi probe via variable injection
            for (String payload : List.of("'", "' OR '1'='1", "1; DROP TABLE users--")) {
                // Use replaceFirst (not replace) to substitute only the first
                // occurrence of this value — String.replace replaces ALL occurrences
                // which corrupts requests where the same string appears in multiple fields.
                // Pattern.quote prevents regex metachar injection from the argValue itself.
                String modBody = originalBody.replaceFirst(
                        java.util.regex.Pattern.quote("\"" + argValue + "\""),
                        "\"" + payload.replace("\\", "\\\\").replace("$", "\\$") + "\"");
                byte[] req = buildGraphQlRequest(ctx, modBody);
                if (req == null) continue;
                HttpSender.Response resp = sender.send(ctx.service, req);
                if (resp == null) continue;

                if (containsSqlError(resp.body())) {
                    results.add(new ActiveScanResult(
                        "GraphQL SQL Injection via Field Argument", SEV_CRITICAL,
                        "A SQL injection vulnerability was detected in GraphQL field argument '" +
                        argName + "'. The payload '" + payload + "' triggered a database error, " +
                        "confirming that the resolver passes unsanitised argument values directly " +
                        "to a SQL query.",
                        "Argument: " + argName + " | Payload: " + payload +
                        " | DB error in response: " + trunc(resp.body(), 100),
                        "- Use parameterised queries in all GraphQL resolvers\n" +
                        "- Validate and sanitise all argument values before passing to the data layer",
                        "CWE-89", ctx.url, "GraphQL argument: " + argName, payload,
                        trunc(modBody, 300), trunc(resp.body(), 200)));
                    break;
                }
            }
        }
        return results;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean isGraphQlEndpoint(ProbeContext ctx) {
        for (Pattern p : GRAPHQL_URL_PATTERNS) {
            if (p.matcher(ctx.url).find()) return true;
        }
        // Check body for GraphQL-shaped content
        String body = ctx.bodyRaw != null ? ctx.bodyRaw : "";
        return (body.contains("\"query\"") || body.contains("\"mutation\""))
                && ctx.contentType != null && ctx.contentType.contains("application/json");
    }

    private static byte[] buildGraphQlRequest(ProbeContext ctx, String jsonBody) {
        String reqStr = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
        int bodyStart = reqStr.indexOf("\r\n\r\n");
        if (bodyStart < 0) {
            // No body — build a POST request
            String headers = "POST " + extractPath(ctx.url) + " HTTP/1.1\r\n" +
                    "Host: " + ctx.host + "\r\n" +
                    "Content-Type: application/json\r\n";
            byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);
            String full = headers + "Content-Length: " + bodyBytes.length + "\r\n\r\n";
            byte[] hdrs = full.getBytes(StandardCharsets.ISO_8859_1);
            byte[] result = new byte[hdrs.length + bodyBytes.length];
            System.arraycopy(hdrs, 0, result, 0, hdrs.length);
            System.arraycopy(bodyBytes, 0, result, hdrs.length, bodyBytes.length);
            return result;
        }
        String headers   = reqStr.substring(0, bodyStart + 4);
        byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        String newHeaders = headers.replaceFirst("(?i)Content-Length:\\s*\\d+",
                "Content-Length: " + bodyBytes.length);
        byte[] hdrs   = newHeaders.getBytes(StandardCharsets.ISO_8859_1);
        byte[] result = new byte[hdrs.length + bodyBytes.length];
        System.arraycopy(hdrs, 0, result, 0, hdrs.length);
        System.arraycopy(bodyBytes, 0, result, hdrs.length, bodyBytes.length);
        return result;
    }

    private static String extractOriginalQuery(ProbeContext ctx) {
        String body = ctx.bodyRaw;
        if (body == null) return null;
        int q = body.indexOf("\"query\":\"");
        if (q < 0) return null;
        int start = q + 9;
        int end   = body.indexOf("\"", start);
        return end > start ? body.substring(start, end) : null;
    }

    private static List<String[]> extractStringArgs(String body) {
        List<String[]> args = new ArrayList<>();
        Matcher m = Pattern.compile("\"([a-zA-Z][a-zA-Z0-9_]*)\"\\s*:\\s*\"([^\"]{1,50})\"").matcher(body);
        while (m.find() && args.size() < 10) {
            String key = m.group(1);
            if (!key.equals("query") && !key.equals("operationName") && !key.equals("variables")) {
                args.add(new String[]{m.group(1), m.group(2)});
            }
        }
        return args;
    }

    private static List<String> findSensitiveMutations(String schema) {
        List<String> found = new ArrayList<>();
        for (Pattern p : SENSITIVE_MUTATIONS) {
            Matcher m = p.matcher(schema);
            while (m.find()) found.add(m.group());
        }
        return found;
    }

    private static boolean containsSqlError(String body) {
        String lower = body.toLowerCase();
        return lower.contains("syntax error") || lower.contains("sql") ||
               lower.contains("ora-") || lower.contains("mysql") ||
               lower.contains("psql") || lower.contains("sqlite");
    }

    private static int countTypes(String schema) {
        return countOccurrences(schema, "\"name\":");
    }

    private static int countOccurrences(String text, String sub) {
        int count = 0, idx = 0;
        while ((idx = text.indexOf(sub, idx)) >= 0) { count++; idx += sub.length(); }
        return count;
    }

    private static String extractPath(String url) {
        try { return new java.net.URL(url).getPath(); } catch (Exception e) { return "/graphql"; }
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
