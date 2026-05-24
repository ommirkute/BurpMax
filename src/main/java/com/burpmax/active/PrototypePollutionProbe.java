package com.burpmax.active;

import java.util.*;
import static com.burpmax.model.Finding.*;

/**
 * Server-Side Prototype Pollution probe.
 *
 * Injects prototype pollution payloads via JSON body and URL query parameters.
 * Detection: inject a canary property (__proto__[avppKey]=avppValue) and then
 * check if a subsequent request returns the canary value in the response
 * (indicating the prototype was polluted and the property leaked into output).
 *
 * This targets Node.js/Express applications using vulnerable lodash, defaults,
 * merge, or extend functions.
 *
 * Note: This probe sends TWO requests per test — injection then verification.
 */
public class PrototypePollutionProbe {

    private static final String CANARY_KEY   = "avppKey";
    private static final String CANARY_VALUE = "avppValue-" + Long.toHexString(System.nanoTime());

    // ── JSON body pollution payloads ──────────────────────────────────────────
    private static final List<String[]> JSON_POLLUTION_PATHS = List.of(
        // [param to inject, JSON value — wraps in the pollution object]
        // These are appended to the existing JSON body or replace a param value
        new String[]{"__proto__",          "{\"" + CANARY_KEY + "\": \"" + CANARY_VALUE + "\"}"},
        new String[]{"constructor",        "{\"prototype\": {\"" + CANARY_KEY + "\": \"" + CANARY_VALUE + "\"}}"},
        new String[]{"__proto__." + CANARY_KEY, CANARY_VALUE}
    );

    // ── URL query pollution payloads ──────────────────────────────────────────
    // Appended to the URL: ?__proto__[avppKey]=avppValue
    private static final List<String> URL_POLLUTION_PARAMS = List.of(
        "__proto__[" + CANARY_KEY + "]",
        "constructor[prototype][" + CANARY_KEY + "]",
        "__proto__." + CANARY_KEY
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        String ctLower = ctx.contentType != null ? ctx.contentType.toLowerCase() : "";

        // ── 1. JSON body pollution ────────────────────────────────────────
        if (ctLower.contains("application/json")) {
            for (String[] pp : JSON_POLLUTION_PATHS) {
                if (results.isEmpty()) {
                    ActiveScanResult r = probeJsonPollution(ctx, rb, sender, pp[0], pp[1]);
                    if (r != null) results.add(r);
                }
            }
        }

        // ── 2. URL parameter pollution ────────────────────────────────────
        if (results.isEmpty()) {
            for (String pollutedParam : URL_POLLUTION_PARAMS) {
                ActiveScanResult r = probeUrlPollution(ctx, rb, sender, pollutedParam);
                if (r != null) { results.add(r); break; }
            }
        }

        return results;
    }

    // ── JSON body pollution ───────────────────────────────────────────────────
    private static ActiveScanResult probeJsonPollution(ProbeContext ctx, RequestBuilder rb,
                                                        HttpSender sender,
                                                        String paramPath, String pollutionValue) {
        // Step 1: Inject pollution payload
        byte[] injectReq = rb.buildProbeRequest(ctx, paramPath, pollutionValue);
        if (injectReq == null) return null;
        HttpSender.Response injectResp = sender.send(ctx.service, injectReq);
        if (injectResp == null) return null;

        // Step 2: Send a clean follow-up request and check if canary is reflected
        HttpSender.Response verifyResp = sender.send(ctx.service, ctx.originalRequest);
        if (verifyResp == null) return null;

        // FALSE POSITIVE GUARD: verify canary was not already present in an earlier
        // baseline request. Should not happen with a randomised canary but guards
        // against any edge case where the app echoes arbitrary JSON keys.
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        if (baseline != null && baseline.body().contains(CANARY_VALUE)) return null;

        // Check if canary appears in either response (immediate or persistent pollution)
        boolean foundImmediate  = injectResp.body().contains(CANARY_VALUE);
        boolean foundPersistent = verifyResp.body().contains(CANARY_VALUE);

        if (foundImmediate || foundPersistent) {
            String when = foundPersistent ? "persistent (found in follow-up request)"
                                          : "immediate (found in injection response)";
            return new ActiveScanResult(
                "Server-Side Prototype Pollution", SEV_HIGH,
                "Prototype pollution was detected via JSON parameter '" + paramPath + "'. " +
                "The canary value '" + CANARY_VALUE + "' was reflected in the " + when + ". " +
                "Prototype pollution can lead to Remote Code Execution, authentication bypass, " +
                "DoS, and property injection depending on how polluted properties are used.",
                "Injection param: " + paramPath + " | Canary: " + CANARY_VALUE +
                " | Detection: " + when,
                PP_REMEDIATION, "CWE-1321",
                ctx.url, paramPath, pollutionValue,
                trunc(new String(injectReq), 300), trunc(injectResp.body(), 200),
                injectReq, injectResp.raw(), -1L);
        }
        return null;
    }

    // ── URL parameter pollution ───────────────────────────────────────────────
    private static ActiveScanResult probeUrlPollution(ProbeContext ctx, RequestBuilder rb,
                                                       HttpSender sender, String pollutedParam) {
        // Inject pollution as an additional URL parameter
        byte[] injectReq = rb.buildProbeRequest(ctx, pollutedParam, CANARY_VALUE);
        if (injectReq == null) return null;
        HttpSender.Response injectResp = sender.send(ctx.service, injectReq);
        if (injectResp == null) return null;

        HttpSender.Response verifyResp = sender.send(ctx.service, ctx.originalRequest);
        if (verifyResp == null) return null;

        boolean found = injectResp.body().contains(CANARY_VALUE)
                     || verifyResp.body().contains(CANARY_VALUE);
        if (!found) return null;

        return new ActiveScanResult(
            "Server-Side Prototype Pollution (URL Parameter)", SEV_HIGH,
            "Prototype pollution was detected via URL parameter '" + pollutedParam + "'. " +
            "The server appears to parse and merge query parameters directly into JavaScript " +
            "objects without filtering prototype-modifying keys. This can lead to property " +
            "injection affecting all object instances in the application process.",
            "URL param: " + pollutedParam + "=" + CANARY_VALUE + " | Canary reflected in response",
            PP_REMEDIATION, "CWE-1321",
            ctx.url, pollutedParam, CANARY_VALUE,
            trunc(new String(injectReq), 300), trunc(injectResp.body(), 200),
                injectReq, injectResp.raw(), -1L);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String PP_REMEDIATION =
        "PRIMARY FIX - Block Dangerous Keys + Freeze Prototype:\n" +
        "1. Reject __proto__, constructor, and prototype keys before any merge/assign operation.\n" +
        "2. Use Object.create(null) for all objects used as hash maps / key-value stores.\n" +
        "3. Freeze Object.prototype early in application startup: Object.freeze(Object.prototype)\n" +
        "   This prevents prototype modification even if pollution reaches the merge function.\n\n" +
        "DEPENDENCY UPDATES (mandatory):\n" +
        "- lodash: upgrade to >= 4.17.21 (CVE-2019-10744, CVE-2020-8203)\n" +
        "- defaults: >= 1.0.4, merge: >= 2.1.1, deep-assign: >= 3.0.0\n" +
        "- ejs: >= 3.1.7 (CVE-2022-29078 - RCE via prototype pollution)\n\n" +
        "NODE.JS RUNTIME FLAGS:\n" +
        "- --disable-proto=delete: removes __proto__ setter/getter entirely (Node 12.17+)\n" +
        "- --disable-proto=throw: throws on any __proto__ access\n" +
        "Run: npm audit and address all prototype pollution advisories.";
}
