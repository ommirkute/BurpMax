package com.burpmax.active;


import java.util.*;
import com.burpmax.active.ConfirmationEngine;
import static com.burpmax.model.Finding.*;

/**
 * NoSQL Injection probe — targets MongoDB operator injection patterns.
 *
 * Detection strategies:
 *  1. JSON body parameter replacement with operator objects ($gt, $ne, $where)
 *  2. Form parameter pollution with array-style operators (param[$gt]=)
 *  3. URL parameter operator injection
 *
 * Confirmation: compares response body length between true-condition and
 * false-condition payloads to confirm differential behavior.
 */
public class NoSqlInjectionProbe {

    // ── Operator payloads for JSON body injection ────────────────────────────
    // Replace "param":"value" with "param":{"$gt":""} which matches any string
    private static final List<String[]> JSON_OP_PAYLOADS = List.of(
        // [true-condition payload, false-condition payload, operator name]
        new String[]{"{\"$gt\": \"\"}",        "{\"$lt\": \"~\"}",  "$gt/$lt"},
        new String[]{"{\"$ne\": null}",         "{\"$eq\": null}",   "$ne/$eq"},
        new String[]{"{\"$regex\": \".*\"}",    "{\"$regex\": \"a^\"}", "$regex"}
    );

    // ── Form/URL parameter pollution payloads ─────────────────────────────────
    // These work when the server converts ?param[$gt]= to {"param":{"$gt":""}}
    private static final List<String[]> PARAM_POLLUTION = List.of(
        new String[]{"[$gt]=",    "[$lt]=~",   "$gt pollution"},
        new String[]{"[$ne]=1",   "[$eq]=1",   "$ne pollution"},
        new String[]{"[$exists]=true", "[$exists]=false", "$exists pollution"}
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        if (ctx == null) return results;

        String ctLower = ctx.contentType != null ? ctx.contentType.toLowerCase() : "";
        // Dedup keys include probe type so different NoSQL techniques can each fire
        // on the same parameter. Old param-only key blocked $ne/$eq from running
        // after $gt/$lt even though they use different queries and confirmation logic.
        Set<String> firedJson  = new HashSet<>();
        Set<String> firedPoll  = new HashSet<>();

        // ── JSON body injection ────────────────────────────────────────────
        if (ctLower.contains("application/json")) {
            for (String param : ctx.allParamNames()) {
                if (firedJson.contains(param)) continue;
                ActiveScanResult r = probeJsonOperator(ctx, rb, sender, param);
                if (r != null) { results.add(r); firedJson.add(param); }
            }
        }

        // ── Parameter pollution (query string and form body) ───────────────
        for (String param : ctx.allParamNames()) {
            if (firedPoll.contains(param)) continue;
            ActiveScanResult r = probeParamPollution(ctx, rb, sender, param);
            if (r != null) { results.add(r); firedPoll.add(param); }
        }

        return results;
    }

    // ── JSON operator injection ───────────────────────────────────────────────
    private static ActiveScanResult probeJsonOperator(ProbeContext ctx, RequestBuilder rb,
                                                       HttpSender sender, String param) {
        // Get baseline for comparison
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        if (baseline == null) return null;
        int baseLen = baseline.body().length();

        for (String[] op : JSON_OP_PAYLOADS) {
            String truePayload  = op[0];
            String falsePayload = op[1];
            String opName       = op[2];

            byte[] trueReq  = rb.buildProbeRequest(ctx, param, truePayload);
            byte[] falseReq = rb.buildProbeRequest(ctx, param, falsePayload);
            if (trueReq == null || falseReq == null) continue;

            HttpSender.Response trueResp  = sender.send(ctx.service, trueReq);
            HttpSender.Response falseResp = sender.send(ctx.service, falseReq);
            if (trueResp == null || falseResp == null) continue;

            int trueLen  = trueResp.body().length();
            int falseLen = falseResp.body().length();

            // True condition should return data (similar or more than baseline)
            // False condition should return less data or different status
            boolean truePassed  = trueResp.statusCode() == 200 && trueLen >= baseLen * 0.8;
            boolean falseDiffers = falseResp.statusCode() != 200
                                || similarity(trueLen, falseLen) < 0.7;

            if (truePassed && falseDiffers) {
                // Confirm: run differential probes a second time to rule out A/B testing
                if (!ConfirmationEngine.confirmDifferential(sender, ctx.service,
                        trueReq, falseReq, trueLen, falseLen, baseLen, 0.30)) continue;

                return new ActiveScanResult(
                    "NoSQL Injection (MongoDB Operator)", SEV_CRITICAL,
                    "NoSQL injection was detected on JSON parameter '" + param + "' using MongoDB " +
                    "operator '" + opName + "'. The true-condition operator returned " + trueLen +
                    " bytes (HTTP " + trueResp.statusCode() + ") while the false-condition returned " +
                    falseLen + " bytes (HTTP " + falseResp.statusCode() + "). This indicates the " +
                    "operator was interpreted by the database, allowing authentication bypass and " +
                    "unauthorised data access.",
                    "Parameter: '" + param + "' | True op: " + truePayload +
                    " (" + trueLen + "b, HTTP " + trueResp.statusCode() + ") | " +
                    "False op: " + falsePayload + " (" + falseLen + "b, HTTP " + falseResp.statusCode() + ")",
                    NOSQL_REMEDIATION, "CWE-943",
                    ctx.url, param, truePayload,
                    trunc(new String(trueReq), 300),
                    "True=" + trueLen + "b HTTP" + trueResp.statusCode() +
                    ", False=" + falseLen + "b HTTP" + falseResp.statusCode());
            }
        }
        return null;
    }

    // ── Parameter pollution ───────────────────────────────────────────────────
    private static ActiveScanResult probeParamPollution(ProbeContext ctx, RequestBuilder rb,
                                                         HttpSender sender, String param) {
        // Get baseline
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        if (baseline == null) return null;
        int baseLen = baseline.body().length();

        for (String[] pp : PARAM_POLLUTION) {
            // pp[0] = "[$gt]=" — strip trailing "=" to get the key suffix, value is empty
            // e.g. param="username", pp[0]="[$gt]=" → new param "username[$gt]" with value ""
            String keySuffix = pp[0].endsWith("=") ? pp[0].substring(0, pp[0].length() - 1) : pp[0];
            String falSuffix = pp[1].endsWith("=") ? pp[1].substring(0, pp[1].length() - 1) : pp[1];

            // For value-bearing entries like "[$ne]=1", split on "=" inside
            String trueParamName  = param + keySuffix;
            String trueParamValue = "";
            String falseParamName = param + falSuffix;
            String falseParamValue = "";

            // Extract value if pp[0] contains "=" in the middle (e.g. "[$ne]=1")
            int eqIdx = pp[0].indexOf('=');
            if (eqIdx >= 0 && eqIdx < pp[0].length() - 1) {
                trueParamName  = param + pp[0].substring(0, eqIdx);
                trueParamValue = pp[0].substring(eqIdx + 1);
            }
            int eqIdx2 = pp[1].indexOf('=');
            if (eqIdx2 >= 0 && eqIdx2 < pp[1].length() - 1) {
                falseParamName  = param + pp[1].substring(0, eqIdx2);
                falseParamValue = pp[1].substring(eqIdx2 + 1);
            }

            String opName = pp[2];

            // Append the polluted parameter as a NEW query param alongside the original
            byte[] trueReq  = rb.appendQueryParam(ctx.originalRequest, trueParamName,  trueParamValue);
            byte[] falseReq = rb.appendQueryParam(ctx.originalRequest, falseParamName, falseParamValue);
            if (trueReq == null || falseReq == null) continue;
            // Guard: if appendQueryParam returned the original (no-op), skip
            if (trueReq == ctx.originalRequest || falseReq == ctx.originalRequest) continue;

            HttpSender.Response trueResp  = sender.send(ctx.service, trueReq);
            HttpSender.Response falseResp = sender.send(ctx.service, falseReq);
            if (trueResp == null || falseResp == null) continue;

            int trueLen  = trueResp.body().length();
            int falseLen = falseResp.body().length();

            boolean truePassed   = trueResp.statusCode() == 200 && trueLen >= baseLen * 0.8;
            boolean falseDiffers = similarity(trueLen, falseLen) < 0.7
                                || falseResp.statusCode() != 200;

            if (truePassed && falseDiffers) {
                if (!ConfirmationEngine.confirmDifferential(sender, ctx.service,
                        trueReq, falseReq, trueLen, falseLen, baseLen, 0.30)) continue;

                return new ActiveScanResult(
                    "NoSQL Injection (Parameter Pollution)", SEV_HIGH,
                    "NoSQL injection via parameter pollution was detected on parameter '" + param +
                    "' using '" + opName + "'. The server appears to interpret array-style query " +
                    "parameters as MongoDB operators. This is common in Node.js/Express applications " +
                    "using body-parser, where ?" + trueParamName + "= is parsed as {" + param + ":{$gt:\"\"}}.",
                    "Parameter pollution: " + trueParamName + "=" + trueParamValue +
                    " → " + trueLen + "b HTTP" + trueResp.statusCode() +
                    " vs " + falseParamName + "=" + falseParamValue +
                    " → " + falseLen + "b HTTP" + falseResp.statusCode(),
                    NOSQL_REMEDIATION, "CWE-943",
                    ctx.url, param, trueParamName + "=" + trueParamValue,
                    trunc(new String(trueReq), 300),
                    opName + ": true=" + trueLen + "b, false=" + falseLen + "b",
                    trueReq, trueResp.raw(), -1L);
            }
        }
        return null;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private static double similarity(int a, int b) {
        if (a == 0 && b == 0) return 1.0;
        if (a == 0 || b == 0) return 0.0;
        return (double) Math.min(a, b) / Math.max(a, b);
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String NOSQL_REMEDIATION =
        "PRIMARY FIX - Type Validation Before Querying:\n" +
        "Validate that every field passed to a query is the expected primitive type before\n" +
        "it reaches the database driver. If a field should be a string, reject objects.\n" +
        "  BAD:  db.users.find({ password: req.body.password })  // can be {$gt: \"\"}\n" +
        "  GOOD: if (typeof req.body.password !== \"string\") return 400;\n\n" +
        "SCHEMA VALIDATION LIBRARIES:\n" +
        "- Node.js: Joi, Zod, or Yup - define schema with .string() not .any()\n" +
        "- Python: Pydantic with strict type annotations\n" +
        "- Java: Bean Validation (@Pattern, @Size) with explicit type checking\n\n" +
        "SECONDARY CONTROLS:\n" +
        "- Mongoose: enable strict mode (default) and use typed schema definitions.\n" +
        "- Least privilege: the MongoDB user should only have read/write on required collections.\n" +
        "- Disable JavaScript execution in MongoDB: --noscripting flag in production.\n" +
        "- Input sanitisation: strip or reject $-prefixed keys from user-supplied JSON.";
}
