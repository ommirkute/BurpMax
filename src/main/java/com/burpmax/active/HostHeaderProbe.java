package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

class HostHeaderProbe {

    private static final String CANARY_HOST = "burpmax-host-canary.test";

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        byte[] probeReq = rb.buildHostHeaderRequest(ctx, CANARY_HOST);
        HttpSender.Response resp = sender.send(ctx.service, probeReq);
        if (resp == null) return results;

        String body     = resp.body();
        String location = resp.header("location");
        String combined = body + " " + (location != null ? location : "");

        if (combined.contains(CANARY_HOST)) {
            // FALSE POSITIVE GUARD: single-request reflection could be a search/echo
            // feature, not genuine host header injection. Re-send to confirm, then
            // verify the canary is NOT in the clean baseline response.
            HttpSender.Response confirm = sender.send(ctx.service, probeReq);
            if (confirm == null || !(confirm.body() + " " + (confirm.header("location") != null ? confirm.header("location") : "")).contains(CANARY_HOST)) return results;
            HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
            if (baseline != null && (baseline.body() + " " + (baseline.header("location") != null ? baseline.header("location") : "")).contains(CANARY_HOST)) return results;
            String evidence = body.contains(CANARY_HOST)
                    ? "Canary host reflected in response body"
                    : "Canary host reflected in Location header: " + location;
            results.add(new ActiveScanResult(
                "Host Header Injection", SEV_MEDIUM,
                "The application reflects the Host header value into the response body or " +
                "a redirect. An attacker can manipulate the Host header to poison password " +
                "reset links (sending victims to an attacker-controlled domain), cache poison " +
                "legitimate pages, or conduct server-side request forgery.",
                evidence + " | Injected Host: " + CANARY_HOST,
                "PRIMARY FIX - Pin the Application URL:\n" +
                "Configure the absolute base URL in server-side settings; never derive it from the Host header.\n" +
                "  Django: ALLOWED_HOSTS list + settings.SITE_URL\n" +
                "  Spring: server.servlet.context-path + application.base-url property\n" +
                "  Rails:  config.action_mailer.default_url_options\n" +
                "SECONDARY CONTROLS:\n" +
                "- Validate the Host header at the ingress/load balancer against an allowlist of\n" +
                "  permitted hostnames; reject requests with unexpected Host values with 400.\n" +
                "- Password reset emails: generate reset links using the configured base URL,\n" +
                "  not request.getHeader(Host). This is the most critical exploitation path.\n" +
                "- Cache poisoning: ensure CDN/proxy normalises the Host header before caching.",
                "CWE-601", ctx.url, "Host", CANARY_HOST,
                trunc(new String(probeReq), 300), trunc(combined, 200),
                    probeReq, resp.raw(), -1L));
        }
        return results;
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Path Traversal
// ─────────────────────────────────────────────────────────────────────────────
