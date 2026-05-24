package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import static com.burpmax.model.Finding.*;

/**
 * Stored (Persistent) XSS probe.
 *
 * Distinct from reflected XSS: the payload is submitted once, then the probe
 * checks whether the canary persists and is rendered unescaped on a LATER,
 * SEPARATE request — either a GET of the same endpoint, or any other endpoint
 * already known from the Burp site map (comments, profiles, dashboards).
 *
 * Detection strategy (false-positive resistant):
 *   1. Submit a unique HTML-breaking canary into each writable parameter of a
 *      state-changing request (POST/PUT/PATCH). Each canary is globally unique
 *      so a match anywhere can only have come from this exact injection.
 *   2. Re-fetch the SAME endpoint with a clean GET. If the raw canary tag
 *      appears unescaped in an HTML response → stored XSS on the same page.
 *   3. If not found there, fetch a small set of "sink" endpoints harvested
 *      from the site map (same host, GET, HTML responses) and look for the
 *      canary there → stored XSS surfacing on a different page.
 *   4. Confirm by requesting the sink URL a SECOND time — a genuine stored
 *      value persists; a transient echo does not.
 *
 * Guards against false positives:
 *   - Canary is unique per injection; collision is statistically impossible.
 *   - The response Content-Type must be HTML/XHTML for the canary to execute.
 *   - The HTML-encoded form of the canary is checked: if only the encoded
 *     form is present, the value is stored but correctly escaped → NOT a
 *     finding (reported as informational-free; simply skipped).
 *   - Re-request confirmation rules out a one-off reflection masquerading as
 *     stored.
 *
 * Cost control:
 *   - Only runs on state-changing methods (POST/PUT/PATCH) — GET endpoints
 *     are covered by the reflected XSS probe.
 *   - At most MAX_SINKS sink endpoints are checked per finding attempt.
 */
public class StoredXssProbe {

    private static final String PREFIX = "avsxss";

    // Globally unique marker sequence — see XssProbe for the rationale on using
    // AtomicLong instead of nanoTime (low-res clocks can repeat nanoTime()).
    private static final java.util.concurrent.atomic.AtomicLong SEQ =
            new java.util.concurrent.atomic.AtomicLong(0);

    // Cap on how many site-map sink endpoints to inspect per injection attempt.
    private static final int MAX_SINKS = 12;

    /** Optional supplier of candidate sink URLs (same host, GET, HTML).
     *  Wired by ActiveScanner from the Burp site map. May be null. */
    public interface SinkProvider {
        /** @return absolute URLs on {@code host} worth checking for persistence. */
        List<byte[]> sinkRequests(String host);
    }

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        return probe(ctx, rb, sender, null);
    }

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender, SinkProvider sinks) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Only state-changing requests store data. GET reflection is the
        // reflected-XSS probe's job; running here would just duplicate it.
        String method = ctx.method == null ? "" : ctx.method.toUpperCase();
        if (!method.equals("POST") && !method.equals("PUT") && !method.equals("PATCH")) {
            return results;
        }

        // Nothing writable → nothing to store.
        if (ctx.allParamNames().isEmpty()) return results;

        Set<String> firedParams = new HashSet<>();

        for (String param : ctx.allParamNames()) {
            if (firedParams.contains(param)) continue;

            long uid = SEQ.incrementAndGet();
            // Canary is a self-identifying custom tag. Unique token embedded so
            // a hit is unambiguously ours. Example: <avsxss1a2b3c>...</avsxss1a2b3c>
            String token  = PREFIX + Long.toHexString(uid)
                          + Integer.toHexString(
                              java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000));
            String canary = "<" + token + ">stored</" + token + ">";
            String encoded = canary.replace("<", "&lt;").replace(">", "&gt;");

            // ── Step 1: submit the canary via the state-changing request ──────
            byte[] writeReq = rb.buildProbeRequest(ctx, param, canary);
            if (writeReq == null) continue;
            HttpSender.Response writeResp = sender.send(ctx.service, writeReq);
            if (writeResp == null) continue;

            // A 4xx/5xx on the write means the value was rejected — not stored.
            int wc = writeResp.statusCode();
            if (wc >= 400) continue;

            // ── Step 2: re-fetch the SAME endpoint with a clean GET ──────────
            byte[] sameGet = buildSelfGet(ctx);
            if (sameGet != null) {
                HttpSender.Response g = sender.send(ctx.service, sameGet);
                ActiveScanResult r = evaluate(ctx, sender, g, sameGet,
                        ctx.url, param, canary, token, encoded, "same endpoint (GET)");
                if (r != null) { results.add(r); firedParams.add(param); continue; }
            }

            // ── Step 3: check site-map sink endpoints ────────────────────────
            if (sinks != null) {
                List<byte[]> sinkReqs;
                try {
                    sinkReqs = sinks.sinkRequests(ctx.host);
                } catch (Exception e) {
                    sinkReqs = Collections.emptyList();
                }
                int checked = 0;
                for (byte[] sinkReq : sinkReqs) {
                    if (sinkReq == null) continue;
                    if (checked >= MAX_SINKS) break;
                    checked++;
                    HttpSender.Response sr = sender.send(ctx.service, sinkReq);
                    ActiveScanResult r = evaluate(ctx, sender, sr, sinkReq,
                            sinkUrl(sinkReq, ctx), param, canary, token, encoded,
                            "different endpoint (stored and surfaced elsewhere)");
                    if (r != null) { results.add(r); firedParams.add(param); break; }
                }
            }
        }
        return results;
    }

    /**
     * Decide whether {@code resp} confirms stored XSS for this canary.
     * Returns a finding on confirmed unescaped persistence, else null.
     */
    private static ActiveScanResult evaluate(ProbeContext ctx, HttpSender sender,
                                              HttpSender.Response resp, byte[] reqUsed,
                                              String sinkUrl, String param,
                                              String canary, String token, String encoded,
                                              String where) {
        if (resp == null) return null;

        String body = resp.body();
        if (body == null || body.isEmpty()) return null;

        boolean rawPresent     = body.contains(canary);
        boolean encodedPresent = body.contains(encoded);

        // If only the encoded form is present, the input was stored but
        // correctly escaped on output → secure, not a finding.
        if (!rawPresent) return null;
        // Raw present but the page also escaped it elsewhere is still a finding
        // as long as the raw, executable form appears at least once.

        // Content-Type must be browser-renderable as HTML for execution.
        String ct = resp.header("content-type");
        ct = ct == null ? "" : ct.toLowerCase();
        boolean isHtml = ct.contains("text/html") || ct.contains("application/xhtml")
                       || ct.contains("text/xhtml");
        if (!isHtml) return null;

        // ── Confirmation: request the same sink again. A genuine stored value
        // is durable; a coincidental/transient echo usually is not. ───────────
        HttpSender.Response again = sender.send(ctx.service, reqUsed);
        if (again == null || again.body() == null || !again.body().contains(canary)) {
            return null;
        }

        String sev = SEV_HIGH;   // stored XSS affects every visitor of the sink page
        return new ActiveScanResult(
            "Stored XSS (" + where + ")", sev,
            "Stored (persistent) Cross-Site Scripting was confirmed. A unique HTML "
            + "payload submitted via parameter '" + param + "' on " + ctx.url
            + " was later returned UNESCAPED in an HTML response retrieved on a "
            + "separate request (" + where + "). Because the payload is persisted "
            + "server-side, it executes in the browser of every user who views the "
            + "affected page - no per-victim social engineering is required. This "
            + "enables session hijacking, account takeover, and worm-style propagation. "
            + "The canary was confirmed present on a second independent request, ruling "
            + "out a transient reflection.",
            "Injected via: parameter '" + param + "' on " + ctx.method + " " + ctx.url
            + " | Surfaced at: " + sinkUrl + " | Canary: " + trunc(canary, 60),
            STORED_XSS_REMEDIATION, "CWE-79",
            sinkUrl, param, canary,
            trunc(new String(reqUsed, StandardCharsets.ISO_8859_1), 300),
            trunc(body, 200),
            reqUsed, resp.raw(), -1L);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /** Build a clean GET of the probe endpoint's own URL (no body, no payload). */
    private static byte[] buildSelfGet(ProbeContext ctx) {
        try {
            String reqStr = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
            int firstSpace  = reqStr.indexOf(' ');
            int secondSpace = reqStr.indexOf(' ', firstSpace + 1);
            if (firstSpace < 0 || secondSpace < 0) return null;
            // Preserve the exact request path + "HTTP/x.y\r\n..." tail, force GET.
            String rebuilt = "GET " + reqStr.substring(firstSpace + 1, secondSpace)
                    + reqStr.substring(secondSpace);

            int hdrEnd = rebuilt.indexOf("\r\n\r\n");
            String headerBlock = hdrEnd >= 0 ? rebuilt.substring(0, hdrEnd) : rebuilt;

            StringBuilder clean = new StringBuilder();
            String[] lines = headerBlock.split("\r\n", -1);
            for (int i = 0; i < lines.length; i++) {
                String lower = lines[i].toLowerCase();
                if (lower.startsWith("content-length:")
                        || lower.startsWith("transfer-encoding:")
                        || lower.startsWith("content-type:")) continue;
                if (clean.length() > 0) clean.append("\r\n");
                clean.append(lines[i]);
            }
            clean.append("\r\n\r\n");
            return clean.toString().getBytes(StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return null;
        }
    }

    /** Best-effort extraction of the request-line path for evidence display. */
    private static String sinkUrl(byte[] req, ProbeContext ctx) {
        try {
            String s = new String(req, StandardCharsets.ISO_8859_1);
            int sp1 = s.indexOf(' ');
            int sp2 = s.indexOf(' ', sp1 + 1);
            if (sp1 < 0 || sp2 < 0) return ctx.url;
            String path = s.substring(sp1 + 1, sp2);
            // Reconstruct scheme://host + path from the probe context origin.
            java.net.URL u = new java.net.URL(ctx.url);
            int port = u.getPort();
            String portPart = (port > 0
                    && !(port == 80  && "http".equalsIgnoreCase(u.getProtocol()))
                    && !(port == 443 && "https".equalsIgnoreCase(u.getProtocol())))
                    ? ":" + port : "";
            return u.getProtocol() + "://" + u.getHost() + portPart + path;
        } catch (Exception e) {
            return ctx.url;
        }
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String STORED_XSS_REMEDIATION =
        "PRIMARY FIX - Encode on Output, Every Time:\n"
        + "Stored XSS is fixed the same way as reflected XSS: HTML-encode user data at\n"
        + "the point it is written into the page, using context-aware encoding\n"
        + "(htmlEncode for body/attribute, \\uXXXX for JS, encodeURIComponent for URLs).\n"
        + "Encoding on INPUT is fragile - the same value may be rendered in multiple\n"
        + "contexts; always encode at output.\n\n"
        + "SECONDARY CONTROLS:\n"
        + "- Sanitise rich-text/HTML input server-side with an allowlist sanitiser\n"
        + "  (OWASP Java HTML Sanitizer, DOMPurify server build) - never a denylist.\n"
        + "- Content-Security-Policy with nonces blocks execution even if a payload is\n"
        + "  persisted and rendered.\n"
        + "- Re-scan all locations where stored data is displayed - the sink may be a\n"
        + "  different page, an admin panel, a log viewer, or an email template.\n"
        + "- HttpOnly cookies limit session theft impact if a payload does execute.\n"
        + "- Treat already-stored data as tainted: a fix must also remediate or re-encode\n"
        + "  existing persisted values, not just new submissions.";
}
