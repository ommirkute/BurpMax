package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

class CorsMisconfigProbe {

    private static final String EVIL_ORIGIN = "https://evil.burpmax-canary.test";

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        byte[] probeReq = rb.buildOriginRequest(ctx, EVIL_ORIGIN);
        HttpSender.Response resp = sender.send(ctx.service, probeReq);
        if (resp == null) return results;

        String acao = resp.header("access-control-allow-origin");
        String acac = resp.header("access-control-allow-credentials");

        if (acao == null) return results;

        // FALSE POSITIVE GUARD: CORS misconfigurations are only exploitable when
        // the server returns actual content (2xx). A CORS header on a 401/403/404
        // error response is the server's global CORS middleware firing — it does
        // not expose any protected data because the response body is an error, not
        // sensitive content. Only fire on 2xx responses.
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) return results;

        boolean reflectsEvil = acao.equals(EVIL_ORIGIN) || acao.equals("*");
        boolean allowsCreds  = "true".equalsIgnoreCase(acac);

        if (reflectsEvil && allowsCreds) {
            results.add(new ActiveScanResult(
                "CORS: Arbitrary Origin Reflected with Credentials", SEV_HIGH,
                "The server reflected the attacker-controlled Origin '" + EVIL_ORIGIN +
                "' in the Access-Control-Allow-Origin header alongside " +
                "Access-Control-Allow-Credentials: true. Any website can make fully " +
                "credentialed cross-origin requests to this endpoint and read the response.",
                "ACAO: " + acao + " | ACAC: " + acac + " | Probe Origin: " + EVIL_ORIGIN,
                "PRIMARY FIX - Origin Allowlist:\n" +
                "Maintain an explicit server-side allowlist of trusted origins. Check the\n" +
                "incoming Origin header against the list and only reflect it if it matches.\n" +
                "  BAD:  Access-Control-Allow-Origin: {request.Origin}  (always reflected)\n" +
                "  GOOD: if allowlist.contains(origin) { ACAO: origin } else { 403 }\n\n" +
                "SECONDARY CONTROLS:\n" +
                "- Never combine ACAO: * with ACAC: true - browsers block this, but some\n" +
                "  misconfigurations dynamically set ACAO based on Origin instead.\n" +
                "- Apply ACAC: true only to endpoints that genuinely require credentialed\n" +
                "  cross-origin access (e.g. authenticated API calls from a SPA).\n" +
                "- Expose only the minimum required headers via Access-Control-Expose-Headers.\n" +
                "- SameSite cookies: set SameSite=Lax or Strict on session cookies as\n" +
                "  complementary defence against cross-origin credential theft.",
                "CWE-942", ctx.url, "Origin", EVIL_ORIGIN,
                trunc(new String(probeReq), 300),
                "ACAO: " + acao + " | ACAC: " + acac));
        } else if (reflectsEvil) {
            results.add(new ActiveScanResult(
                "CORS: Arbitrary Origin Reflected (No Credentials)", SEV_MEDIUM,
                "The server reflected the attacker-controlled Origin '" + EVIL_ORIGIN +
                "' in the Access-Control-Allow-Origin header. Without ACAC:true this " +
                "only allows reading public (unauthenticated) responses cross-origin.",
                "ACAO: " + acao + " | Probe Origin: " + EVIL_ORIGIN,
                "PRIMARY FIX: validate Origin against a server-side allowlist before\n" +
                "reflecting it in ACAO. Never dynamically reflect arbitrary origins.",
                "CWE-942", ctx.url, "Origin", EVIL_ORIGIN,
                trunc(new String(probeReq), 300), "ACAO: " + acao));
        }
        return results;
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host Header Injection
// ─────────────────────────────────────────────────────────────────────────────
