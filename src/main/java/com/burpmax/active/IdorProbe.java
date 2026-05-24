package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

class IdorProbe {

    private static final Pattern RE_NUMERIC_ID = Pattern.compile(
        "(?:^|[/?&])(?:id|user_id|account_id|profile_id|order_id|item_id|" +
        "record_id|doc_id|file_id|customer_id|member_id|uid)=(\\d{1,10})(?:&|$)",
        Pattern.CASE_INSENSITIVE);

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Look for numeric ID parameters in the URL
        Matcher m = RE_NUMERIC_ID.matcher(ctx.url);
        if (!m.find()) {
            // Also check query params
            for (Map.Entry<String, String> entry : ctx.queryParams.entrySet()) {
                String k = entry.getKey().toLowerCase();
                String v = entry.getValue();
                if ((k.contains("id") || k.equals("uid") || k.equals("user"))
                        && v.matches("\\d{1,10}")) {
                    return probeIdorParam(ctx, rb, sender, entry.getKey(), entry.getValue());
                }
            }
            return results;
        }

        return probeIdorParam(ctx, rb, sender,
                m.group().split("=")[0].replaceAll("^[/?&]", ""), m.group(1));
    }

    private static List<ActiveScanResult> probeIdorParam(ProbeContext ctx, RequestBuilder rb,
                                                          HttpSender sender, String param, String idStr) {
        List<ActiveScanResult> results = new ArrayList<>();
        // FALSE POSITIVE GUARD: IDOR only matters on authenticated endpoints.
        // A public endpoint where id+1 returns different content is not a vulnerability.
        boolean hasAuth = ctx.reqHeaders.containsKey("authorization")
                       || ctx.reqHeaders.containsKey("cookie");
        if (!hasAuth) return results;
        try {
            long id         = Long.parseLong(idStr);
            long adjacentId = id + 1;

            byte[] probeReq = rb.buildProbeRequest(ctx, param, String.valueOf(adjacentId));
            HttpSender.Response resp = sender.send(ctx.service, probeReq);
            if (resp == null) return results;

            // IDOR indicator: 200 with different data (not same as original)
            int status = resp.statusCode();
            if (status == 200) {
                String origBody  = ctx.originalResponse != null ? new String(ctx.originalResponse) : "";
                String probeBody = resp.body();

                // Bodies should be DIFFERENT (different user's data) but both successful
                double similarity = computeSimilarity(origBody, probeBody);

                // Require meaningful content (>100 bytes) and strong dissimilarity
                // to avoid false positives from minor dynamic content differences.
                if (similarity < 0.85 && probeBody.length() > 100) {
                    results.add(new ActiveScanResult(
                        "IDOR - Insecure Direct Object Reference", SEV_HIGH,
                        "Incrementing the '" + param + "' parameter from " + idStr + " to " +
                        adjacentId + " returned HTTP 200 with different response content. " +
                        "This indicates the endpoint may not validate that the requesting user " +
                        "has permission to access the requested resource, allowing horizontal " +
                        "privilege escalation to access other users' data.",
                        "Parameter: " + param + " | Original ID: " + idStr +
                        " | Adjacent ID: " + adjacentId +
                        " | Original len: " + origBody.length() +
                        " | Probe len: " + probeBody.length() +
                        " | Similarity: " + String.format("%.0f%%", similarity * 100),
                        "PRIMARY FIX - Object-Level Authorisation:\n" +
                        "Every data access must verify that the authenticated user has permission\n" +
                        "to access the specific object, not just that they are authenticated.\n" +
                        "  BAD:  SELECT * FROM orders WHERE id = {id}\n" +
                        "  GOOD: SELECT * FROM orders WHERE id = {id} AND user_id = {session.userId}\n\n" +
                        "SECONDARY CONTROLS:\n" +
                        "- Opaque identifiers: use UUIDs or random tokens instead of sequential\n" +
                        "  integers. This raises the bar but does not replace authorisation checks.\n" +
                        "- Centralised authorisation: use a policy engine (OPA, CASL, Spring\n" +
                        "  Method Security) so ownership checks cannot be accidentally omitted.\n" +
                        "- Automated cross-user tests: include tests that log in as User A and\n" +
                        "  attempt to access User B resources - expect 403, not 200.\n" +
                        "- Audit logs: log all resource access so IDOR exploitation is detectable.",
                        "CWE-639", ctx.url, param, String.valueOf(adjacentId),
                        trunc(new String(probeReq), 300), trunc(probeBody, 200),
                    probeReq, resp.raw(), -1L));
                }
            }
        } catch (NumberFormatException ignored) {}
        return results;
    }

    private static double computeSimilarity(String a, String b) {
        if (a == null || b == null) return 0;
        int la = a.length(), lb = b.length();
        if (la == 0 && lb == 0) return 1.0;
        if (la == 0 || lb == 0) return 0;
        return (double) Math.min(la, lb) / Math.max(la, lb);
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XXE Detection
// ─────────────────────────────────────────────────────────────────────────────
