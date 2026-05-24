package com.burpmax.active;

import java.util.*;
import static com.burpmax.model.Finding.*;

public class SstiProbe {

    // Payloads and their expected outputs — use math that won't occur in normal content
    record SstiPayload(String payload, String expected, String engine) {}

    private static final List<SstiPayload> PAYLOADS = List.of(
        new SstiPayload("{{7*'7'}}",       "7777777",  "Jinja2/Twig"),
        new SstiPayload("{{7*7}}",          "49",       "Jinja2/Twig/Angular"),
        new SstiPayload("${7*7}",           "49",       "Freemarker/Spring EL"),
        new SstiPayload("#{7*7}",           "49",       "Thymeleaf"),
        new SstiPayload("<%= 7*7 %>",       "49",       "ERB/EJS"),
        new SstiPayload("*{7*7}",           "49",       "Thymeleaf"),
        new SstiPayload("${{7*7}}",         "49",       "Pebble/Jinjava"),
        new SstiPayload("[[${ 7 * 7 }]]",   "49",       "Angular")
    );

    public static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                                HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> fired = new HashSet<>();

        // Fetch baseline response for the original request first
        // so we can skip SSTI payloads whose expected output already appears in normal responses
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        String baselineBody = baseline != null ? baseline.body() : "";

        for (String param : ctx.allParamNames()) {
            if (fired.contains(param)) continue;
            for (SstiPayload ssti : PAYLOADS) {
                // Skip if the expected output already appears in the baseline response
                // (avoids false positives on pages that naturally contain "49" etc.)
                if (!baselineBody.isEmpty() && baselineBody.contains(ssti.expected())) continue;

                byte[] probeReq = rb.buildProbeRequest(ctx, param, ssti.payload());
                if (probeReq == null) continue;

                HttpSender.Response resp = sender.send(ctx.service, probeReq);
                if (resp == null) continue;

                if (resp.body().contains(ssti.expected())) {
                    // FALSE POSITIVE GUARD: SSTI math results like "49" can appear
                    // naturally in JSON API responses (prices, counts, IDs). Only
                    // fire on text/html, text/xhtml, or text/plain responses where
                    // the expression is actually being evaluated in a template engine.
                    String ct = resp.header("content-type");
                    if (ct == null) ct = "";
                    ct = ct.toLowerCase();
                    if (!ct.contains("text/html") && !ct.contains("text/xhtml")
                            && !ct.contains("text/plain") && !ct.contains("text/template")
                            && !ct.contains("application/xhtml")) continue;
                    // Confirm with a second payload that has a DIFFERENT expected output
                    // to rule out caching. The old "next in list" approach was wrong:
                    // if both payloads return "49", confirmReflection passes trivially
                    // on any engine that evaluates either expression, causing false positives.
                    // We must find an alt whose expected value differs from ssti.expected().
                    SstiPayload alt = null;
                    for (SstiPayload candidate : PAYLOADS) {
                        if (candidate != ssti
                                && !candidate.expected().equals(ssti.expected())
                                && !baselineBody.contains(candidate.expected())) {
                            alt = candidate;
                            break;
                        }
                    }
                    if (alt == null) continue;  // no suitable alt found - skip
                    byte[] altReq = rb.buildProbeRequest(ctx, param, alt.payload());

                    // Skip if baseline already contained the alt expected value
                    if (altReq != null && !baselineBody.contains(alt.expected())
                            && ConfirmationEngine.confirmReflection(
                                    sender, ctx.service,
                                    probeReq, altReq, ctx.originalRequest,
                                    ssti.expected(), alt.expected())) {
                        fired.add(param);
                        results.add(new ActiveScanResult(
                            "Server-Side Template Injection (SSTI)", SEV_CRITICAL,
                            "A Server-Side Template Injection vulnerability was detected on parameter '" +
                            param + "' using a " + ssti.engine() + " payload. The expression '" +
                            ssti.payload() + "' was evaluated server-side and returned '" +
                            ssti.expected() + "'. Two distinct payloads confirmed the vulnerability, " +
                            "ruling out cached responses. SSTI can lead to full Remote Code Execution " +
                            "by escalating the template expression to execute OS commands.",
                            "Payload: " + ssti.payload() + " | Response: " + ssti.expected() +
                            " | Engine: " + ssti.engine() + " | Parameter: " + param +
                            " | Confirmed with second payload: " + alt.payload(),
                            "PRIMARY FIX - Separate Code from Data:\n" +
                            "Never pass user input as the template string. Pass it as a variable inside a\n" +
                            "fixed template. BAD: engine.render(userInput, ctx). GOOD: engine.render(fixedTpl, {param: userInput}).\n\n" +
                            "SECONDARY CONTROLS:\n" +
                            "- Sandbox the engine: Jinja2 SandboxedEnvironment, Freemarker ClassResolver\n" +
                            "  restrictions. Sandboxing reduces but does not eliminate risk.\n" +
                            "- Use logic-less templates (Mustache, Handlebars) where user content is displayed.\n" +
                            "- Allowlist permitted template syntax; reject inputs containing {{ }} ${ } #{ }.\n" +
                            "- Rotate all credentials immediately - SSTI grants full server access and exposes\n" +
                            "  environment variables, config files, and cloud metadata.",
                            "CWE-94",
                            ctx.url, param, ssti.payload(),
                            trunc(new String(probeReq), 300), trunc(resp.body(), 200),
                            probeReq, resp.raw(), -1L));
                        break;
                    }
                }   // end if resp.body contains expected
            }       // end for PAYLOADS
        }           // end for allParamNames
        return results;
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
