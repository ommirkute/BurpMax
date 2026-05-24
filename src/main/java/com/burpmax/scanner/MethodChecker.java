package com.burpmax.scanner;

import java.util.*;
import static com.burpmax.model.Finding.*;

public class MethodChecker {
    // TRACE and CONNECT have no legitimate use in production — always flag
    private static final Set<String> ALWAYS_DANGEROUS = Set.of("TRACE", "CONNECT");
    // PUT and DELETE are legitimate in REST APIs — only flag when combined with TRACE/CONNECT
    // or when the endpoint doesn't look like a REST API
    private static final Set<String> REST_METHODS     = Set.of("PUT", "DELETE");

    public static List<CheckResult> check(Map<String, String> respHeaders) {
        List<CheckResult> results = new ArrayList<>();
        Map<String, String> h = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : respHeaders.entrySet())
            h.put(e.getKey().toLowerCase(), e.getValue());

        String allow = h.getOrDefault("allow",
                       h.getOrDefault("access-control-allow-methods", ""));
        if (allow.isEmpty()) return results;
        String upper = allow.toUpperCase();

        // TRACE / CONNECT: never legitimate in production — flag always
        List<String> alwaysBad = new ArrayList<>();
        for (String d : ALWAYS_DANGEROUS) if (upper.contains(d)) alwaysBad.add(d);
        if (!alwaysBad.isEmpty()) {
            results.add(new CheckResult("Dangerous HTTP Methods Enabled", SEV_MEDIUM,
                "The server explicitly allows " + String.join(", ", alwaysBad) + " on this endpoint. " +
                "TRACE enables Cross-Site Tracing (XST) attacks that can steal HttpOnly cookies by " +
                "reflecting request headers back to a malicious script. CONNECT allows establishment " +
                "of arbitrary TCP tunnels through the server, enabling proxy abuse.",
                "Allow: " + allow,
                "- Disable TRACE globally - there is no legitimate production use case\n" +
                "- Apache: Set TraceEnable Off in httpd.conf\n" +
                "- Nginx: Return 405 for TRACE in server block: if ($request_method = TRACE) { return 405; }\n" +
                "- Disable CONNECT unless the server is intentionally operating as a forward proxy",
                "CWE-650"));
        }

        // PUT / DELETE without TRACE/CONNECT: note only if both are present
        // (single PUT or DELETE alone is normal REST — both together on a generic endpoint is suspicious)
        boolean hasPut    = upper.contains("PUT");
        boolean hasDelete = upper.contains("DELETE");
        if (hasPut && hasDelete && alwaysBad.isEmpty()) {
            results.add(new CheckResult("HTTP Write Methods Exposed (PUT, DELETE)", SEV_LOW,
                "This endpoint explicitly advertises both PUT and DELETE methods. While these are normal in authenticated REST APIs, their presence on unauthenticated or broadly-scoped endpoints may allow unauthorised file upload, resource modification, or deletion.",
                "Allow: " + allow,
                "- Verify that PUT and DELETE are protected by authentication and authorisation checks\n" +
                "- Restrict these methods to specific authenticated API routes via API gateway policy\n" +
                "- If not needed, disable them at the web server level",
                "CWE-650"));
        }

        return results;
    }
}
