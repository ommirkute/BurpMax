package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

class OpenRedirectProbe {

    private static final String CANARY_HOST = "burpmax-scan-canary.test";
    private static final List<String> REDIRECT_PARAMS = List.of(
        "redirect", "redirect_uri", "redirect_url", "return", "return_url",
        "returnto", "next", "goto", "url", "target", "dest", "destination",
        "redir", "forward", "continue", "callback", "location", "link",
        "ref", "referer", "checkout_url", "success_url", "cancel_url"
    );

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Only test known redirect parameter names + any existing query params
        Set<String> toTest = new LinkedHashSet<>(REDIRECT_PARAMS);
        toTest.retainAll(ctx.allParamNames()); // only test params that exist in request

        for (String param : toTest) {
            String payload = "https://" + CANARY_HOST + "/";
            byte[] probeReq = rb.buildProbeRequest(ctx, param, payload);
            if (probeReq == null) continue;

            HttpSender.Response resp = sender.send(ctx.service, probeReq);
            if (resp == null) continue;

            // Fire if response is a redirect and Location header contains our canary
            int status = resp.statusCode();
            String location = resp.header("location");
            if (status >= 300 && status < 400 && location != null
                    && location.contains(CANARY_HOST)) {
                results.add(new ActiveScanResult(
                    "Open Redirect", SEV_MEDIUM,
                    "An open redirect vulnerability was confirmed on parameter '" + param + "'. " +
                    "The application accepted an external URL as a redirect destination and issued " +
                    "a " + status + " redirect to the attacker-controlled domain. This enables " +
                    "phishing attacks where URLs appear to originate from a trusted domain.",
                    "Parameter: " + param + " | Payload: " + payload +
                    " | Location: " + location,
                    "PRIMARY FIX - Indirect Redirect Map:\n" +
                    "Replace user-supplied redirect URLs with server-side opaque tokens:\n" +
                    "  BAD:  /login?next=https://evil.com/phish\n" +
                    "  GOOD: /login?next_id=42  (server maps 42 to /dashboard)\n" +
                    "This eliminates the redirect parameter as an attack surface entirely.\n\n" +
                    "IF EXTERNAL REDIRECTS ARE REQUIRED:\n" +
                    "- Validate against a strict allowlist of permitted domains.\n" +
                    "- Reject values containing ://, starting with //, or beginning with\n" +
                    "  an unexpected scheme (javascript:, data:).\n" +
                    "- Show an interstitial warning page for external redirects so users\n" +
                    "  can see they are leaving the application.",
                    "CWE-601", ctx.url, param, payload,
                    trunc(new String(probeReq), 300), "HTTP " + status + " Location: " + location,
                    probeReq, resp.raw(), -1L));
                break;
            }
        }
        return results;
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CORS Misconfiguration (active)
// ─────────────────────────────────────────────────────────────────────────────
