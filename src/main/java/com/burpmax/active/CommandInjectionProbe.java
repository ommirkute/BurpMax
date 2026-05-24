package com.burpmax.active;


import java.util.*;
import com.burpmax.active.ConfirmationEngine;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * Command Injection probe — two detection strategies:
 *
 *  1. Output-based : inject commands whose output appears in the response
 *     (e.g. /etc/passwd content, hostname, id output)
 *
 *  2. Time-based blind : inject sleep commands and measure response time delta
 *     (detects blind OS command injection where output is not returned)
 *
 * Tests both URL parameters and injectable HTTP headers.
 */
public class CommandInjectionProbe {

    // ── Output-based payloads ─────────────────────────────────────────────────
    // Each entry: [unix payload, windows payload, detection pattern]
    private static final List<String[]> OUTPUT_PAYLOADS = List.of(
        new String[]{"; echo avci$(echo inject)avci", "& echo avciinjectavci",  "avciinjectavci"},
        new String[]{"; echo avci-cmdi-canary",        "& echo avci-cmdi-canary", "avci-cmdi-canary"},
        new String[]{"`echo avci-cmdi-bt`",             null,                      "avci-cmdi-bt"},
        new String[]{"$(echo avci-cmdi-sub)",           null,                      "avci-cmdi-sub"}
    );

    // ── Time-based blind payloads ────────────────────────────────────────────
    private static final int    SLEEP_SECS      = 4;   // distinctive duration
    private static final long   TIME_THRESHOLD  = (SLEEP_SECS - 1) * 1000L;
    private static final long   MAX_BASELINE_MS = 2000L;

    private static final List<String[]> TIME_PAYLOADS = List.of(
        // [payload, OS type]
        new String[]{"& sleep " + SLEEP_SECS,                        "Unix"},
        new String[]{"; sleep " + SLEEP_SECS,                        "Unix"},
        new String[]{"| sleep " + SLEEP_SECS,                        "Unix"},
        new String[]{"` sleep " + SLEEP_SECS + "`",                  "Unix"},
        new String[]{"$( sleep " + SLEEP_SECS + ")",                  "Unix"},
        new String[]{"& ping -c " + SLEEP_SECS + " 127.0.0.1",       "Unix"},
        new String[]{"& timeout /t " + SLEEP_SECS,                   "Windows"},
        new String[]{"| timeout /t " + SLEEP_SECS,                   "Windows"},
        new String[]{"& ping -n " + (SLEEP_SECS + 1) + " 127.0.0.1", "Windows"}
    );

    // Headers that are commonly passed to OS commands (e.g. shell scripts, CGI)
    private static final List<String> INJECTABLE_HEADERS = List.of(
        "User-Agent", "Referer", "X-Forwarded-For", "Cookie"
    );

    // Response patterns confirming command execution (Unix)
    private static final Pattern RE_PASSWD = Pattern.compile(
        "root:[x*]?:\\d+:\\d+:", Pattern.CASE_INSENSITIVE);
    private static final Pattern RE_HOSTNAME = Pattern.compile(
        "avci-cmdi-(?:canary|bt|sub|inject)", Pattern.CASE_INSENSITIVE);

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> firedParams = new HashSet<>();

        // ── 1. Output-based (parameters) ──────────────────────────────────
        for (String param : ctx.allParamNames()) {
            if (firedParams.contains(param)) continue;
            ActiveScanResult r = probeOutputBased(ctx, rb, sender, param, null);
            if (r != null) { results.add(r); firedParams.add(param); }
        }

        // ── 2. Output-based (headers) ──────────────────────────────────────
        for (String header : INJECTABLE_HEADERS) {
            String key = "hdr:" + header;
            if (firedParams.contains(key)) continue;
            ActiveScanResult r = probeOutputBased(ctx, rb, sender, null, header);
            if (r != null) { results.add(r); firedParams.add(key); }
        }

        // ── 3. Time-based blind (parameters not yet fired) ─────────────────
        long baselineMs = measureBaseline(ctx, sender);
        if (baselineMs >= 0 && baselineMs < MAX_BASELINE_MS) {
            for (String param : ctx.allParamNames()) {
                if (firedParams.contains(param)) continue;
                ActiveScanResult r = probeTimeBased(ctx, rb, sender, param, null, baselineMs);
                if (r != null) { results.add(r); firedParams.add(param); }
            }
            for (String header : INJECTABLE_HEADERS) {
                String key = "hdr:" + header;
                if (firedParams.contains(key)) continue;
                ActiveScanResult r = probeTimeBased(ctx, rb, sender, null, header, baselineMs);
                if (r != null) { results.add(r); firedParams.add(key); }
            }
        }

        return results;
    }

    // ── Public tier-split entry points ────────────────────────────────────────

    /** Tier 3: output-based (command output in response) — medium speed, no sleep. */
    public static List<ActiveScanResult> probeOutputBased(ProbeContext ctx,
                                                           RequestBuilder rb,
                                                           HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> firedParams = new HashSet<>();
        for (String param : ctx.allParamNames()) {
            if (firedParams.contains(param)) continue;
            ActiveScanResult r = probeOutputBased(ctx, rb, sender, param, null);
            if (r != null) { results.add(r); firedParams.add(param); }
        }
        for (String header : INJECTABLE_HEADERS) {
            String key = "hdr:" + header;
            if (firedParams.contains(key)) continue;
            ActiveScanResult r = probeOutputBased(ctx, rb, sender, null, header);
            if (r != null) { results.add(r); firedParams.add(key); }
        }
        return results;
    }

    /** Tier 4: time-based blind only — always slow, runs last. */
    public static List<ActiveScanResult> probeTimeBased(ProbeContext ctx,
                                                         RequestBuilder rb,
                                                         HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> firedParams = new HashSet<>();
        long baselineMs = measureBaseline(ctx, sender);
        if (baselineMs < 0 || baselineMs >= MAX_BASELINE_MS) return results;
        for (String param : ctx.allParamNames()) {
            if (firedParams.contains(param)) continue;
            ActiveScanResult r = probeTimeBased(ctx, rb, sender, param, null, baselineMs);
            if (r != null) { results.add(r); firedParams.add(param); }
        }
        for (String header : INJECTABLE_HEADERS) {
            String key = "hdr:" + header;
            if (firedParams.contains(key)) continue;
            ActiveScanResult r = probeTimeBased(ctx, rb, sender, null, header, baselineMs);
            if (r != null) { results.add(r); firedParams.add(key); }
        }
        return results;
    }

    // ── Output-based (private) ────────────────────────────────────────────────
    private static ActiveScanResult probeOutputBased(ProbeContext ctx, RequestBuilder rb,
                                                      HttpSender sender,
                                                      String param, String header) {
        for (String[] entry : OUTPUT_PAYLOADS) {
            // Try Unix payload
            if (entry[0] != null) {
                ActiveScanResult r = tryPayload(ctx, rb, sender, param, header,
                        entry[0], entry[2], "Unix");
                if (r != null) return r;
            }
            // Try Windows payload
            if (entry[1] != null) {
                ActiveScanResult r = tryPayload(ctx, rb, sender, param, header,
                        entry[1], entry[2], "Windows");
                if (r != null) return r;
            }
        }
        return null;
    }

    private static ActiveScanResult tryPayload(ProbeContext ctx, RequestBuilder rb,
                                                HttpSender sender,
                                                String param, String header,
                                                String payload, String marker, String os) {
        byte[] req = buildRequest(ctx, rb, param, header, payload);
        if (req == null) return null;
        HttpSender.Response resp = sender.send(ctx.service, req);
        if (resp == null) return null;

        boolean found = resp.body().contains(marker)
                     || RE_PASSWD.matcher(resp.body()).find()
                     || RE_HOSTNAME.matcher(resp.body()).find();
        if (!found) return null;

        // FALSE POSITIVE GUARD: verify the match did NOT already appear in the
        // baseline response. Documentation pages or error messages can contain
        // "root:x:0:0:" or hostname-like strings without any command injection.
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        if (baseline != null) {
            String baseBody = baseline.body();
            if (baseBody.contains(marker)
                    || RE_PASSWD.matcher(baseBody).find()
                    || RE_HOSTNAME.matcher(baseBody).find()) return null;
        }

        // Confirm: marker must reappear AND not be in the clean baseline
        boolean confirmed = ConfirmationEngine.confirmSingleMarker(
                sender, ctx.service, req, ctx.originalRequest, marker);
        if (!confirmed) return null;

        String where = param != null ? "parameter '" + param + "'" : "header '" + header + "'";
        return new ActiveScanResult(
            "OS Command Injection (Output-Based)", SEV_CRITICAL,
            "OS command injection was confirmed on " + where + " against a " + os +
            " system. The command output marker '" + marker + "' was observed in the response, " +
            "confirming that user input is passed to a system shell without sanitisation. " +
            "Full remote code execution with web server privileges is possible.",
            "Injection point: " + where + " | Payload: " + trunc(payload, 80) +
            " | Output marker: " + marker,
            CMDI_REMEDIATION, "CWE-78",
            ctx.url, param != null ? param : header, payload,
            trunc(new String(req), 300), trunc(resp.body(), 200),
                req, resp.raw(), -1L);
    }

    // ── Time-based blind ──────────────────────────────────────────────────────
    private static ActiveScanResult probeTimeBased(ProbeContext ctx, RequestBuilder rb,
                                                    HttpSender sender,
                                                    String param, String header,
                                                    long baselineMs) {
        for (String[] tp : TIME_PAYLOADS) {
            String payload = tp[0];
            String os      = tp[1];

            byte[] req = buildRequest(ctx, rb, param, header, payload);
            if (req == null) continue;

            long start   = System.currentTimeMillis();
            HttpSender.Response resp = sender.send(ctx.service, req);
            long elapsed = System.currentTimeMillis() - start;

            if (resp == null) continue;
            long delta = elapsed - baselineMs;
            if (delta < TIME_THRESHOLD) continue;

            // Confirm: sleep must be reproducible, clean request must be fast
            if (!ConfirmationEngine.confirmTimeBased(sender, ctx.service,
                    req, ctx.originalRequest, TIME_THRESHOLD, baselineMs)) continue;

            String where = param != null ? "parameter '" + param + "'" : "header '" + header + "'";
            return new ActiveScanResult(
                "OS Command Injection (Time-Based Blind)", SEV_CRITICAL,
                "Blind OS command injection was confirmed on " + where + " against a " + os +
                " system. The sleep payload caused a " + (elapsed/1000) + "s delay (baseline: " +
                (baselineMs/1000) + "s). The delay was reproducible and the clean request " +
                "returned within the expected baseline. An attacker can exfiltrate " +
                "data via DNS or timing channels, and achieve full remote code execution.",
                "Injection point: " + where + " | Payload: " + trunc(payload, 80) +
                " | Response: " + elapsed + "ms | Baseline: " + baselineMs + "ms | OS: " + os,
                CMDI_REMEDIATION, "CWE-78",
                ctx.url, param != null ? param : header, payload,
                trunc(new String(req), 300),
                "Response delayed " + elapsed + "ms (baseline: " + baselineMs + "ms)",
                req, resp.raw(), elapsed);
        }
        return null;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private static byte[] buildRequest(ProbeContext ctx, RequestBuilder rb,
                                        String param, String header, String payload) {
        if (param != null) return rb.buildProbeRequest(ctx, param, payload);
        if (header != null) return rb.injectHeader(ctx.originalRequest, header, payload);
        return null;
    }

    private static long measureBaseline(ProbeContext ctx, HttpSender sender) {
        long start = System.currentTimeMillis();
        HttpSender.Response r = sender.send(ctx.service, ctx.originalRequest);
        return r != null ? System.currentTimeMillis() - start : -1;
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String CMDI_REMEDIATION =
        "PRIMARY FIX - Avoid Shell Invocation:\n" +
        "Replace shell calls with language-native APIs that do not involve a shell interpreter:\n" +
        "  File ops: java.nio.Files, Python pathlib, Node.js fs\n" +
        "  Images:   ImageMagick Java binding, Pillow - not exec(convert ...)\n" +
        "  Network:  HTTP client libraries - not exec(curl ...)\n\n" +
        "IF SHELL EXECUTION IS UNAVOIDABLE:\n" +
        "- Pass arguments as an array to bypass shell interpretation:\n" +
        "    BAD:  Runtime.exec(\"convert \" + userFile)\n" +
        "    GOOD: Runtime.exec(new String[]{\"convert\", userFile})\n" +
        "- Validate arguments against a strict allowlist of permitted values.\n" +
        "- Run the process as a dedicated low-privilege OS user.\n" +
        "- Apply seccomp/AppArmor profiles restricting which syscalls the process can make.\n" +
        "- Block outbound DNS/HTTP from the app tier to prevent OOB data exfiltration.";
}
