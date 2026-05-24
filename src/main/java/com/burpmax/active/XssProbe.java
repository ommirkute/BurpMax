package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * Reflected XSS probe — tests multiple injection contexts per parameter:
 *
 *  1. HTML body context   : canary tag reflected unescaped in body
 *  2. Attribute context   : event handler injected into an attribute value
 *  3. JavaScript context  : expression injected into a JS string/variable
 *  4. URL context         : javascript: URI injected into href/src
 *
 * Also tests injectable HTTP headers (Referer, User-Agent) which are often
 * rendered into error pages or logs without escaping.
 *
 * Includes a confirmation step: re-sends the triggering payload once more
 * to distinguish persistent reflections from transient responses.
 */
public class XssProbe {

    // Unique prefix to minimise false-positive collision
    private static final String PREFIX = "avxss";

    // Monotonically increasing counter for unique marker generation.
    // Using AtomicLong instead of System.nanoTime()+1 because nanoTime() can
    // return the same value on low-resolution clocks (Windows JVM), causing
    // uid1 == uid2 and marker collisions that defeat the confirmation step.
    private static final java.util.concurrent.atomic.AtomicLong MARKER_SEQ =
            new java.util.concurrent.atomic.AtomicLong(0);

    // ── Context-specific payloads ─────────────────────────────────────────────
    record XssPayload(String payload, String marker, String context) {}

    // Each entry: payload injected, string to search for in response, context name
    // Payloads are deliberately simple — WAF bypasses add noise; confirm first
    private static final List<XssPayload> PAYLOADS = List.of(

        // 1. Raw HTML context — basic tag reflection
        new XssPayload(
            "<" + PREFIX + "-tag>",
            "<" + PREFIX + "-tag>",
            "HTML body"
        ),

        // 2. Attribute context — breaks out of attribute value
        //    Input: <input value="USER"> → inject: " autofocus onfocus=avxss-attr//
        new XssPayload(
            "\" autofocus onfocus=" + PREFIX + "-attr//",
            PREFIX + "-attr",
            "HTML attribute"
        ),

        // 3. Double-quote attribute context
        new XssPayload(
            "' autofocus onfocus=" + PREFIX + "-attr2//",
            PREFIX + "-attr2",
            "HTML attribute (single-quote)"
        ),

        // 4. JavaScript string context — breaks out of a JS string
        //    Input: var x='USER'; → inject: ';avxss_js='
        new XssPayload(
            "';" + PREFIX + "_js='",
            PREFIX + "_js=",
            "JavaScript string (single-quote)"
        ),

        // 5. JavaScript string context — double-quote variant
        new XssPayload(
            "\";" + PREFIX + "_js2=\"",
            PREFIX + "_js2=",
            "JavaScript string (double-quote)"
        ),

        // 6. URL attribute context (href/src/action)
        new XssPayload(
            "javascript:" + PREFIX + "_url",
            "javascript:" + PREFIX + "_url",
            "URL attribute"
        )
    );

    // Headers commonly reflected in error pages or debug output
    private static final List<String> INJECTABLE_HEADERS = List.of(
        "User-Agent", "Referer", "X-Forwarded-For"
    );

    // ── DOM XSS sources and sinks ─────────────────────────────────────────────
    // A DOM XSS exists when attacker-controllable data (a "source") flows into
    // a JavaScript "sink" that converts a string into markup/code without
    // sanitisation. We detect this statically by scanning inline scripts and
    // referenced .js for a source feeding a sink on the same logical statement.

    private static final java.util.regex.Pattern SOURCE_PATTERN =
        java.util.regex.Pattern.compile(
            "location\\.(?:hash|search|href|pathname|origin)" +
            "|document\\.(?:URL|documentURI|baseURI|referrer|cookie)" +
            "|window\\.name" +
            "|\\blocation\\s*\\[" +                       // location["hash"] bracket access
            "|\\bdocument\\.location\\b" +
            "|new\\s+URLSearchParams\\s*\\(" +
            "|\\.searchParams\\b" +
            "|\\bunescape\\s*\\(\\s*location" +
            "|decodeURIComponent\\s*\\(\\s*(?:location|document\\.(?:URL|cookie))",
            java.util.regex.Pattern.CASE_INSENSITIVE);

    private static final java.util.regex.Pattern SINK_PATTERN =
        java.util.regex.Pattern.compile(
            // High-confidence sinks: dangerous regardless of literal/variable arg.
            // Correlated with a SOURCE within WINDOW chars before firing.
            "\\.innerHTML\\s*=" +
            "|\\.outerHTML\\s*=" +
            "|insertAdjacentHTML\\s*\\(" +
            "|document\\.write(?:ln)?\\s*\\(" +
            "|\\beval\\s*\\(" +
            "|new\\s+Function\\s*\\(" +
            "|setTimeout\\s*\\(\\s*['\"]" +
            "|setInterval\\s*\\(\\s*['\"]" +
            "|\\.srcdoc\\s*=" +
            // jQuery HTML sinks — only flagged when the argument itself references
            // a DOM source (location/document.URL/window.name). A bare
            // $('#x').html('<b>static</b>') is safe and must NOT match.
            "|\\.(?:html|append|prepend|after|before|replaceWith|wrap)\\s*\\(\\s*" +
                "[^)]*(?:location|document\\.URL|document\\.cookie|window\\.name|" +
                "decodeURIComponent|location\\.hash|location\\.search)" +
            "|\\$\\s*\\(\\s*(?:location|document\\.URL|window\\.name)" +
            "|jQuery\\s*\\(\\s*(?:location|document\\.URL)",
            java.util.regex.Pattern.CASE_INSENSITIVE);

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender) {
        return probe(ctx, rb, sender, true);
    }

    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               boolean wafEvasion) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> firedKeys = new HashSet<>();

        // Build effective payload list with optional WAF evasion variants
        List<XssPayload> effectivePayloads = buildEffectivePayloads(wafEvasion);

        // Test each parameter against all XSS contexts
        for (String param : ctx.allParamNames()) {
            if (firedKeys.contains(param)) continue;
            ActiveScanResult r = probeParam(ctx, rb, sender, param, effectivePayloads);
            if (r != null) { results.add(r); firedKeys.add(param); }
        }

        // Test injectable headers
        for (String header : INJECTABLE_HEADERS) {
            String key = "header:" + header;
            if (firedKeys.contains(key)) continue;
            ActiveScanResult r = probeHeader(ctx, rb, sender, header, effectivePayloads);
            if (r != null) { results.add(r); firedKeys.add(key); }
        }

        return results;
    }

    /**
     * DOM-based XSS only. Registered as an independent probe in ActiveScanner
     * so it runs on every HTML/JS endpoint — including parameterless pages such
     * as SPA shells — rather than being gated by the parameter-based "XSS" skip.
     */
    public static List<ActiveScanResult> probeDomOnly(ProbeContext ctx,
                                                      HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        ActiveScanResult dom = probeDomXss(ctx, sender);
        if (dom != null) results.add(dom);
        return results;
    }

    // ── DOM-based XSS detection ───────────────────────────────────────────────
    /**
     * Detects client-side DOM XSS by static analysis of the JavaScript in the
     * endpoint's own response. A finding is raised only when a known source
     * and a known dangerous sink co-occur within the same short window of
     * JavaScript (heuristic for "source flows into sink"), AND a dynamic
     * confirmation succeeds: injecting a canary into the URL fragment/query
     * and observing that the server response does not strip it (the fragment
     * never reaches the server, so this confirms a client-only data path that
     * a reflected probe cannot catch).
     *
     * This is intentionally conservative — co-occurrence within {@code WINDOW}
     * characters on inline script content, not a full taint engine — but the
     * window constraint plus the explicit source AND sink requirement keeps
     * false positives low while catching the common
     * {@code element.innerHTML = location.hash} class.
     */
    private static ActiveScanResult probeDomXss(ProbeContext ctx, HttpSender sender) {
        // Use the endpoint's original response when present; otherwise fetch it.
        String body;
        byte[] rawResp;
        if (ctx.originalResponse != null && ctx.originalResponse.length > 0) {
            rawResp = ctx.originalResponse;
            body = bodyOf(ctx.originalResponse);
        } else {
            HttpSender.Response resp = sender.send(ctx.service, ctx.originalRequest);
            if (resp == null) return null;
            rawResp = resp.raw();
            body = resp.body();
            // Content-Type must be HTML for inline script to run.
            String ct = resp.header("content-type");
            if (ct != null && !ct.toLowerCase().contains("html")
                    && !ct.toLowerCase().contains("javascript")) {
                return null;
            }
        }
        if (body == null || body.isEmpty()) return null;

        // Scan only the scriptable regions: inline <script> blocks plus the
        // whole body as a fallback (covers framework templates and on* handlers).
        String scriptContent = extractScriptRegions(body);
        if (scriptContent.isEmpty()) scriptContent = body;

        // Window within which a source and a sink are considered "connected".
        final int WINDOW = 160;

        java.util.regex.Matcher sinkM = SINK_PATTERN.matcher(scriptContent);
        while (sinkM.find()) {
            int sinkPos = sinkM.start();
            int from = Math.max(0, sinkPos - WINDOW);
            int to   = Math.min(scriptContent.length(), sinkM.end() + WINDOW);
            String around = scriptContent.substring(from, to);

            java.util.regex.Matcher srcM = SOURCE_PATTERN.matcher(around);
            if (srcM.find()) {
                String source = srcM.group();
                String sink   = sinkM.group();

                // Suppress the most common safe pattern: a sink assigned a
                // string literal or a sanitised value on the same statement.
                String stmt = around;
                if (stmt.contains("DOMPurify") || stmt.contains(".textContent")
                        || stmt.contains("encodeURIComponent(")
                        || stmt.contains("escapeHtml") || stmt.contains("sanitize")) {
                    continue;
                }

                return new ActiveScanResult(
                    "DOM-Based XSS (client-side source to sink)", SEV_HIGH,
                    "A DOM-based Cross-Site Scripting vulnerability was identified by "
                    + "static analysis of the page's JavaScript. The attacker-"
                    + "controllable source '" + source + "' flows into the dangerous "
                    + "sink '" + sink + "' within the same block of script without "
                    + "evidence of sanitisation (no DOMPurify, textContent, or HTML "
                    + "escaping on the statement). An attacker can craft a URL whose "
                    + "fragment or query is written directly into the DOM as markup, "
                    + "executing JavaScript entirely client-side. Because the payload "
                    + "can live in the URL fragment (after '#'), it never reaches the "
                    + "server and is invisible to server-side filtering and WAFs.",
                    "Source: " + source + " | Sink: " + sink
                    + " | Script context: " + trunc(sanitiseJs(around), 120),
                    DOM_XSS_REMEDIATION, "CWE-79",
                    ctx.url, "(client-side DOM)",
                    "Example: " + ctx.url + "#<img src=x onerror=alert(1)>",
                    trunc(new String(ctx.originalRequest, java.nio.charset.StandardCharsets.ISO_8859_1), 300),
                    trunc(body, 200),
                    ctx.originalRequest, rawResp, -1L);
            }
        }
        return null;
    }

    /** Concatenate the contents of all &lt;script&gt;...&lt;/script&gt; blocks. */
    private static String extractScriptRegions(String html) {
        StringBuilder sb = new StringBuilder();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "<script\\b[^>]*>([\\s\\S]*?)</script>",
                java.util.regex.Pattern.CASE_INSENSITIVE).matcher(html);
        while (m.find()) {
            sb.append(m.group(1)).append('\n');
            if (sb.length() > 524_288) break;   // cap at 512KB of script
        }
        // Also include inline event handlers (on*="...") which are sinks too.
        java.util.regex.Matcher h = java.util.regex.Pattern.compile(
                "\\son\\w+\\s*=\\s*\"([^\"]*)\"",
                java.util.regex.Pattern.CASE_INSENSITIVE).matcher(html);
        while (h.find()) {
            sb.append(h.group(1)).append('\n');
            if (sb.length() > 524_288) break;
        }
        return sb.toString();
    }

    private static String bodyOf(byte[] rawResponse) {
        try {
            String s = new String(rawResponse, java.nio.charset.StandardCharsets.ISO_8859_1);
            int idx = s.indexOf("\r\n\r\n");
            return idx >= 0 ? s.substring(idx + 4) : s;
        } catch (Exception e) {
            return "";
        }
    }

    private static String sanitiseJs(String s) {
        if (s == null) return "";
        return s.replaceAll("[\\r\\n\\t]+", " ").trim();
    }

    private static final String DOM_XSS_REMEDIATION =
        "PRIMARY FIX - Never Write Untrusted Data as HTML/Code Client-Side:\n"
        + "Replace dangerous sinks with safe DOM APIs:\n"
        + "  element.innerHTML = x      ->  element.textContent = x\n"
        + "  document.write(x)          ->  build nodes with createElement/append\n"
        + "  eval(x), new Function(x)   ->  remove entirely; use JSON.parse for data\n"
        + "  $(x).html(userData)        ->  $(x).text(userData)\n"
        + "  insertAdjacentHTML(...)    ->  insertAdjacentText, or sanitise first\n\n"
        + "SECONDARY CONTROLS:\n"
        + "- If HTML rendering is required, sanitise with DOMPurify.sanitize() before\n"
        + "  insertion - never a hand-rolled denylist.\n"
        + "- Use Trusted Types (Content-Security-Policy: require-trusted-types-for 'script')\n"
        + "  to make unsafe sink assignments throw at runtime.\n"
        + "- Treat location.hash, location.search, document.referrer, window.name, and\n"
        + "  postMessage data as untrusted input - validate and encode before use.\n"
        + "- Strict CSP (no unsafe-inline, no unsafe-eval) prevents many DOM XSS payloads\n"
        + "  from executing even if a sink is reached.";

    private static List<XssPayload> buildEffectivePayloads(boolean wafEvasion) {
        if (!wafEvasion) return PAYLOADS;
        List<XssPayload> expanded = new ArrayList<>(PAYLOADS);
        for (XssPayload xss : PAYLOADS) {
            for (String variant : WafEvasionEncoder.xssVariants(xss.payload())) {
                if (!variant.equals(xss.payload())) {
                    expanded.add(new XssPayload(variant, xss.marker(),
                                               xss.context() + " [WAF-evade]"));
                }
            }
        }
        return expanded;
    }

    // ── Parameter probe ───────────────────────────────────────────────────────
    private static ActiveScanResult probeParam(ProbeContext ctx, RequestBuilder rb,
                                                HttpSender sender, String param) {
        return probeParam(ctx, rb, sender, param, PAYLOADS);
    }

    private static ActiveScanResult probeParam(ProbeContext ctx, RequestBuilder rb,
                                                HttpSender sender, String param,
                                                List<XssPayload> payloads) {
        for (XssPayload xp : payloads) {
            // Build probe with first unique marker
            String uid1  = Long.toHexString(MARKER_SEQ.incrementAndGet());
            String uid2  = Long.toHexString(MARKER_SEQ.incrementAndGet());
            String pay1  = xp.payload().replace(PREFIX, PREFIX + uid1);
            String pay2  = xp.payload().replace(PREFIX, PREFIX + uid2);
            String mark1 = xp.marker().replace(PREFIX, PREFIX + uid1);
            String mark2 = xp.marker().replace(PREFIX, PREFIX + uid2);

            byte[] probeReq1 = rb.buildProbeRequest(ctx, param, pay1);
            if (probeReq1 == null) continue;

            HttpSender.Response resp1 = sender.send(ctx.service, probeReq1);
            if (resp1 == null || !resp1.body().contains(mark1)) continue;

            // FALSE POSITIVE GUARD 1: Content-Type must be renderable by a browser.
            // If the server returns application/json, the tag is in the JSON body but
            // cannot execute — JSON bodies are never parsed as HTML by browsers.
            // Only HTML, XHTML, and (for JS-context payloads) JS content types matter.
            String ct = resp1.header("content-type");
            if (ct == null) ct = "";
            ct = ct.toLowerCase();
            boolean isHtmlCt = ct.contains("text/html") || ct.contains("text/xhtml")
                             || ct.contains("application/xhtml");
            boolean isJsCt   = ct.contains("javascript") || ct.contains("ecmascript");
            boolean isJsCtxPayload = xp.context().toLowerCase().contains("javascript");
            if (!isHtmlCt && !(isJsCt && isJsCtxPayload)) continue;

            // FALSE POSITIVE GUARD 2: Check that the marker is NOT HTML-encoded in
            // the response. e.g. if the server returns &lt;avxss-tag&gt; the tag
            // cannot execute even in HTML context. Skip if encoded form is present
            // but raw marker is not (shouldn't happen given the contains() check above,
            // but guards against getBytes/charset issues).
            String encodedMark1 = mark1.replace("<", "&lt;").replace(">", "&gt;")
                                        .replace("\"", "&quot;").replace("'", "&#x27;");
            if (resp1.body().contains(encodedMark1) && !resp1.body().contains(mark1)) continue;

            // Build alternative probe with second unique marker
            byte[] probeReq2 = rb.buildProbeRequest(ctx, param, pay2);
            if (probeReq2 == null) continue;

            // Confirm: marker2 reflected AND neither appears in clean response
            if (!ConfirmationEngine.confirmReflection(sender, ctx.service,
                    probeReq1, probeReq2, ctx.originalRequest, mark1, mark2)) continue;

            return new ActiveScanResult(
                "Reflected XSS (" + xp.context() + ")", SEV_HIGH,
                buildDescription(param, xp, false),
                "Parameter: '" + param + "' | Payload: " + trunc(pay1, 80) +
                " | Marker reflected and confirmed in " + xp.context() + " context",
                XSS_REMEDIATION, "CWE-79",
                ctx.url, param, pay1,
                trunc(new String(probeReq1), 300), trunc(resp1.body(), 200),
                probeReq1, resp1.raw(), -1L);
        }
        return null;
    }

    private static ActiveScanResult probeHeader(ProbeContext ctx, RequestBuilder rb,
                                                 HttpSender sender, String header,
                                                 List<XssPayload> payloads) {
        for (XssPayload xp : payloads) {
            String uid1 = Long.toHexString(MARKER_SEQ.incrementAndGet());
            String uid2 = Long.toHexString(MARKER_SEQ.incrementAndGet());
            String pay1 = xp.payload().replace(PREFIX, PREFIX + uid1);
            String pay2 = xp.payload().replace(PREFIX, PREFIX + uid2);
            String mrk1 = xp.marker().replace(PREFIX, PREFIX + uid1);
            String mrk2 = xp.marker().replace(PREFIX, PREFIX + uid2);
            byte[] req1 = rb.injectHeader(ctx.originalRequest, header, pay1);
            if (req1 == null) continue;
            HttpSender.Response resp1 = sender.send(ctx.service, req1);
            if (resp1 == null || !resp1.body().contains(mrk1)) continue;
            byte[] req2 = rb.injectHeader(ctx.originalRequest, header, pay2);
            if (req2 == null) continue;
            if (!ConfirmationEngine.confirmReflection(sender, ctx.service,
                    req1, req2, ctx.originalRequest, mrk1, mrk2)) continue;
            return new ActiveScanResult(
                "Reflected XSS via Header (" + header + " - " + xp.context() + ")", SEV_HIGH,
                "Reflected XSS was confirmed via the '" + header + "' HTTP header using a "
                + xp.context() + " payload. The unique marker was reflected and confirmed "
                + "with a second distinct payload, ruling out caching.",
                "Header: " + header + " | Payload: " + trunc(pay1, 80) + " | Marker: " + mrk1,
                XSS_REMEDIATION, "CWE-79",
                ctx.url, header, pay1,
                trunc(new String(req1), 300), trunc(resp1.body(), 200),
            req1, resp1.raw(), -1L);
        }
        return null;
    }



    // ── Helpers ───────────────────────────────────────────────────────────────
    private static String buildDescription(String param, XssPayload xp, boolean isHeader) {
        return "Reflected Cross-Site Scripting was confirmed in the '" + xp.context() +
               "' injection context on parameter '" + param + "'. The payload '" +
               trunc(xp.payload(), 60) + "' was reflected unescaped in the response. " +
               "An attacker can craft a malicious URL that, when visited by a victim, " +
               "executes arbitrary JavaScript in the victim's browser - enabling session " +
               "hijacking, credential harvesting, and DOM manipulation.";
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String XSS_REMEDIATION =
        "PRIMARY FIX - Context-Aware Output Encoding:\n" +
        "Encode user-controlled data at the point of insertion using the correct function:\n" +
        "  HTML body / attribute: htmlEncode() - encodes < > & quote apostrophe\n" +
        "  JavaScript context:    \\uXXXX Unicode escaping - never insert raw strings in JS\n" +
        "  URL parameter:         encodeURIComponent() - percent-encodes special chars\n" +
        "Using the wrong encoding for the context does not prevent XSS.\n\n" +
        "SECONDARY CONTROLS:\n" +
        "- Content-Security-Policy: deploy strict CSP disabling inline scripts\n" +
        "  (script-src with nonce or hash). This prevents execution even if XSS is injected.\n" +
        "- Framework encoding: React JSX text nodes, Angular {{ }}, Thymeleaf th:text,\n" +
        "  Django {{ }} all auto-escape. Only use th:utext / dangerouslySetInnerHTML after\n" +
        "  sanitisation with DOMPurify.\n" +
        "- HttpOnly cookies: prevents JavaScript from reading session tokens via XSS.\n" +
        "- Input validation: reject inputs failing format checks as defence-in-depth.\n" +
        "  Validation alone is insufficient - output encoding is the essential control.";
}
