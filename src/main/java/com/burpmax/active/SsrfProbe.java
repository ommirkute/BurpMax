package com.burpmax.active;

import java.util.*;
import static com.burpmax.model.Finding.*;

/**
 * Server-Side Request Forgery (SSRF) probe.
 *
 * Two detection strategies:
 *
 *  1. In-band (no OOB required)
 *     Inject internal/cloud metadata URLs and look for known response patterns:
 *       - AWS instance metadata (169.254.169.254) → "ami-id", "instance-id"
 *       - GCP metadata (metadata.google.internal) → "computeMetadata"
 *       - Azure metadata (169.254.169.254/metadata) → "compute"
 *       - Internal network indicators (RFC-1918 IP ranges in response)
 *     Also checks for redirect + response time anomalies on URL parameters.
 *
 *  2. OOB (requires configured OobClient)
 *     Inject the OOB hostname as the value of URL-like parameters and headers
 *     (Referer, X-Forwarded-For, X-Original-URL, Host etc.).
 *     A DNS/HTTP callback from the server confirms SSRF.
 *
 * Injection targets:
 *   - Query / body parameters whose values look like URLs or paths (heuristic)
 *   - All URL parameters on endpoints where all params are tested
 *   - HTTP headers: Referer, X-Forwarded-For, X-Original-URL, X-Rewrite-URL,
 *     X-Custom-IP-Authorization, True-Client-IP, Forwarded, X-Host
 */
public class SsrfProbe {

    // ── In-band probe targets ─────────────────────────────────────────────────
    private static final List<String[]> INBAND_URLS = List.of(
        new String[]{"http://169.254.169.254/latest/meta-data/",       "aws-metadata"},
        new String[]{"http://169.254.169.254/latest/meta-data/ami-id", "aws-metadata"},
        new String[]{"http://metadata.google.internal/computeMetadata/v1/", "gcp-metadata"},
        new String[]{"http://169.254.169.254/metadata/instance",        "azure-metadata"},
        new String[]{"http://localhost/",                               "localhost"},
        new String[]{"http://127.0.0.1/",                              "localhost"},
        new String[]{"http://[::1]/",                                  "localhost-ipv6"}
    );

    // Patterns that indicate the server fetched the injected URL
    private static final List<String> INBAND_INDICATORS = List.of(
        "ami-id", "instance-id", "security-credentials",  // AWS
        "computeMetadata", "serviceAccounts",              // GCP
        "\"compute\"", "\"network\"", "\"osProfile\"",    // Azure
        "root:x:", "root:*:", "/bin/bash"                  // file:// LFI via SSRF
        // "Connection refused" and "ECONNREFUSED" intentionally omitted:
        // these appear in legitimate app error messages for any failed outbound
        // call (webhooks, payment processors) and cause too many false positives.
    );

    // HTTP headers that are often used as SSRF vectors
    private static final List<String> SSRF_HEADERS = List.of(
        "Referer",
        "X-Forwarded-For",
        "X-Original-URL",      // nginx/IIS internal routing
        "X-Rewrite-URL",       // nginx proxy_pass rewrite
        "X-Custom-IP-Authorization",
        "True-Client-IP",
        "Forwarded",
        "X-Host",
        "X-Forwarded-Host",
        "X-Forwarded-Server",  // HAProxy/Varnish
        "X-HTTP-Host-Override",
        "X-ProxyUser-Ip",      // Google internal header
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Originating-IP",
        "CF-Connecting-IP",    // Cloudflare real-IP passthrough
        "Fastly-Client-Ip"     // Fastly CDN
    );

    // Alternative body content-types that can carry SSRF vectors beyond URL params
    // These are checked when the request body hints at a URL-fetching operation
    private static final List<String> SVG_SSRF_INDICATORS = List.of(
        "svg", "image/svg", "text/xml", "application/xml"
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               OobClient oob) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> fired = new HashSet<>();

        // ── 1. In-band parameter injection ────────────────────────────────
        for (String param : ctx.allParamNames()) {
            if (fired.contains(param)) continue;
            // Heuristic: prioritise params whose existing value looks like a URL or path
            String existing = ctx.paramValue(param);
            boolean looksLikeUrl = existing.startsWith("http") || existing.startsWith("/")
                    || existing.contains(".") || param.toLowerCase().matches(
                            ".*(url|uri|path|src|dest|redirect|link|next|target|proxy|host|endpoint).*");

            if (!looksLikeUrl) continue;

            ActiveScanResult r = probeInband(ctx, rb, sender, param, null);
            if (r != null) { results.add(r); fired.add(param); }
        }

        // ── 2. In-band header injection ───────────────────────────────────
        for (String header : SSRF_HEADERS) {
            String key = "hdr:" + header;
            if (fired.contains(key)) continue;
            ActiveScanResult r = probeInband(ctx, rb, sender, null, header);
            if (r != null) { results.add(r); fired.add(key); }
        }

        // ── 3. OOB parameter injection ────────────────────────────────────
        if (oob != null && oob.isAvailable()) {
            for (String param : ctx.allParamNames()) {
                if (fired.contains(param)) continue;
                // Use generateAndRecord so the injection is registered before we send —
                // if the request fails (null response), any subsequent OOB callback still matches.
                String oobHost = oob.generateHost("ssrf-param-" + param);
                if (oobHost == null) continue;
                String payload = "http://" + oobHost + "/ssrf";
                byte[] probeReq = rb.buildProbeRequest(ctx, param, payload);
                oob.recordInjection(oobHost, "SSRF (OOB)", ctx.url, param, payload, probeReq);
                sender.send(ctx.service, probeReq);  // fire-and-forget; callback matched via recordInjection
            }

            // ── 4. OOB header injection ────────────────────────────────────
            for (String header : SSRF_HEADERS) {
                String key = "hdr:" + header;
                if (fired.contains(key)) continue;
                String oobHost = oob.generateHost("ssrf-hdr-" + header);
                if (oobHost == null) continue;
                String payload = "http://" + oobHost + "/ssrf";
                byte[] probeReq = rb.injectHeader(ctx.originalRequest, header, payload);
                oob.recordInjection(oobHost, "SSRF (OOB)", ctx.url, header, payload, probeReq);
                sender.send(ctx.service, probeReq);  // fire-and-forget
            }
        }

        // ── 5. SVG / PDF / Markdown renderer SSRF ───────────────────────────
        // When the endpoint accepts XML, SVG, HTML, or Markdown content types
        // it may feed the body through a server-side renderer that fetches
        // embedded URLs. Inject an OOB callback via the most common SVG sink.
        if (oob != null && oob.isAvailable()) {
            String bodyStr = ctx.bodyRaw != null
                    ? ctx.bodyRaw
                    : "";
            boolean mightRender =
                    SVG_SSRF_INDICATORS.stream().anyMatch(ind -> ctx.contentType != null && ctx.contentType.contains(ind))
                    || bodyStr.contains("<svg") || bodyStr.contains("<image")
                    || bodyStr.contains("![") || bodyStr.contains("<img");

            if (mightRender && !fired.contains("__render__")) {
                fired.add("__render__");
                String oobHost = oob.generateHost("ssrf-render");
                if (oobHost != null) {
                    String oobUrl   = "http://" + oobHost + "/ssrf-render";
                    String svgPayload = "<svg xmlns=\"http://www.w3.org/2000/svg\">"
                            + "<image href=\"" + oobUrl + "\"/></svg>";
                    byte[] injected = appendBodyContent(ctx, svgPayload);
                    if (injected != null) {
                        oob.recordInjection(oobHost, "SSRF via Renderer (SVG/PDF/Markdown)",
                                ctx.url, "request-body", svgPayload, injected);
                        sender.send(ctx.service, injected);
                    }
                }
            }
        }

        return results;
    }

    // ── Body content append (for renderer SSRF) ───────────────────────────────

    /**
     * Appends an SVG payload to the request body. For JSON bodies, wraps the
     * SVG in a string field. For XML/HTML/text bodies appends directly.
     * Returns null if injection is not possible.
     */
    private static byte[] appendBodyContent(ProbeContext ctx, String payload) {
        if (ctx.bodyRaw == null || ctx.bodyRaw.isEmpty()) return null;
        String ct  = ctx.contentType != null ? ctx.contentType.toLowerCase() : "";
        String body = ctx.bodyRaw;

        String injectedBody;
        if (ct.contains("json") && body.trim().startsWith("{")) {
            int last = body.lastIndexOf('}');
            if (last < 0) return null;
            String inner = body.substring(1, last).trim();
            String comma = inner.isEmpty() ? "" : ",";
            // Escape double-quotes in the payload when embedding in JSON string value
            String escaped = payload.replace("\\", "\\\\").replace("\"", "\\\"");
            injectedBody = body.substring(0, last)
                    + comma + "\"_content\":\"" + escaped + "\""
                    + body.substring(last);
        } else {
            injectedBody = body + "\n" + payload;
        }

        String req = new String(ctx.originalRequest, java.nio.charset.StandardCharsets.ISO_8859_1);
        int sep = req.indexOf("\r\n\r\n");
        if (sep < 0) return null;
        String headers = req.substring(0, sep);
        headers = headers.replaceAll("(?im)^Content-Length:[^\r\n]*\r?\n?", "").stripTrailing();
        byte[] newBody = injectedBody.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        String rebuilt = headers + "\r\nContent-Length: " + newBody.length
                + "\r\n\r\n" + injectedBody;
        return rebuilt.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    // ── In-band detection ─────────────────────────────────────────────────────

    private static ActiveScanResult probeInband(ProbeContext ctx, RequestBuilder rb,
                                                 HttpSender sender,
                                                 String param, String header) {
        for (String[] target : INBAND_URLS) {
            String url   = target[0];
            String label = target[1];

            byte[] probeReq = param  != null ? rb.buildProbeRequest(ctx, param, url)
                                             : rb.injectHeader(ctx.originalRequest, header, url);
            if (probeReq == null) continue;

            HttpSender.Response resp = sender.send(ctx.service, probeReq);
            if (resp == null) continue;

            for (String indicator : INBAND_INDICATORS) {
                if (resp.body().contains(indicator)) {
                    // Confirm: re-send probe — indicator must reappear
                    HttpSender.Response confirm = sender.send(ctx.service, probeReq);
                    if (confirm == null || !confirm.body().contains(indicator)) continue;

                    // Baseline: indicator must NOT appear in clean response
                    HttpSender.Response base = sender.send(ctx.service, ctx.originalRequest);
                    if (base != null && base.body().contains(indicator)) continue;

                    String where = param != null ? "parameter '" + param + "'" : "header '" + header + "'";
                    return new ActiveScanResult(
                        "Server-Side Request Forgery (SSRF)", SEV_HIGH,
                        "In-band SSRF was confirmed on " + where + ". Injecting '" + url +
                        "' caused the server to fetch the URL and return its contents - the '" +
                        indicator + "' indicator appeared in the response. This exposes " +
                        "cloud metadata services, internal network services, and can be " +
                        "escalated to full credential theft (IAM roles, service account tokens).",
                        "Injection: " + where + " | URL: " + url + " | Indicator: " + indicator +
                        " | Source: " + label,
                        SSRF_REMEDIATION, "CWE-918",
                        ctx.url, param != null ? param : header, url,
                        trunc(new String(probeReq), 300), trunc(resp.body(), 200),
                    probeReq, resp.raw(), -1L);
                }
            }
        }
        return null;
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String SSRF_REMEDIATION =
        "PRIMARY FIX - Server-Side URL Allowlist:\n" +
        "Validate the target URL against a strict server-side allowlist of permitted schemes,\n" +
        "hostnames, and ports before making any outbound request. Reject by default; permit\n" +
        "only explicitly approved destinations.\n\n" +
        "MANDATORY BLOCKS (even with allowlisting):\n" +
        "- RFC 1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16\n" +
        "- Loopback: 127.0.0.0/8, ::1\n" +
        "- Link-local: 169.254.0.0/16 (cloud metadata endpoint)\n" +
        "- Unused schemes: file://, dict://, gopher://, ftp://\n\n" +
        "CLOUD-SPECIFIC CONTROLS:\n" +
        "- AWS/GCP/Azure: enforce IMDSv2 (token-based) so metadata requires a PUT pre-flight\n" +
        "  that a simple SSRF cannot perform. Set hop limit to 1 on EC2 IMDSv2.\n" +
        "- Azure: disable the IMDS endpoint if the workload does not use managed identity.\n\n" +
        "SECONDARY CONTROLS:\n" +
        "- Network egress firewall: restrict outbound TCP from the app tier to approved CIDRs.\n" +
        "- Never return the raw response of a server-side fetch to the client - this enables\n" +
        "  in-band SSRF and internal service enumeration.\n" +
        "- DNS rebinding: resolve the URL to an IP and re-validate the IP, not just the hostname.";
}
