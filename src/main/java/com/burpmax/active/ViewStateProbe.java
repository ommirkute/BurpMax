package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * .NET ViewState Deserialization / Tampering probe.
 *
 * ASP.NET WebForms stores page state in a hidden form field called __VIEWSTATE.
 * It is Base64-encoded binary data, optionally encrypted and/or MAC-signed.
 * Three vulnerability classes are tested:
 *
 *  1. MAC validation disabled (CRITICAL - RCE via deserialization)
 *     When EnableViewStateMac=false (or machineKey is not configured),
 *     the server does not verify the HMAC before deserializing ViewState.
 *     An attacker can craft a malicious ViewState containing a .NET
 *     deserialization gadget chain (using ysoserial.net) to achieve RCE.
 *
 *     Detection: inject a tampered __VIEWSTATE value and check the response.
 *     If the server:
 *       (a) Returns 200 with no "ViewState is invalid" / "MAC failed" error, AND
 *       (b) The injected marker value appears in the response (confirming deserialization),
 *     then MAC validation is disabled.
 *
 *     For OOB confirmation: inject a URLDNS-equivalent payload via __VIEWSTATE
 *     and detect the DNS callback (requires OobClient).
 *
 *  2. ViewState encryption disabled (MEDIUM - information disclosure)
 *     If the __VIEWSTATE field does not start with the encryption prefix,
 *     it may expose sensitive server-side state in plaintext (user roles,
 *     query data, internal object graphs). Detected passively from the
 *     original request/response pair without sending additional requests.
 *
 *  3. ViewState in URL / GET request (LOW - CSRF + replay)
 *     ViewState in the URL query string leaks state via Referer headers and
 *     enables trivial replay attacks. Detected passively.
 *
 * Endpoint gating:
 *   Only fires when __VIEWSTATE (or __VIEWSTATEFIELDCOUNT, __EVENTTARGET,
 *   __EVENTARGUMENT — classic WebForms hidden fields) is present in the
 *   request parameters. This prevents wasted probes on non-.NET endpoints.
 *
 * Tier: 2 for MAC check (2 requests), 3 for OOB deserialization (fire-and-forget).
 */
class ViewStateProbe {

    // WebForms field names that identify a .NET WebForms endpoint
    private static final Set<String> VIEWSTATE_FIELDS = Set.of(
        "__viewstate", "__viewstatefieldcount", "__eventtarget",
        "__eventargument", "__eventvalidation", "__viewstategenerator"
    );

    // Patterns in the response that indicate MAC/signature validation failure
    // (server IS validating — a good sign, but the error tells us we tampered)
    private static final List<Pattern> MAC_ERROR_PATTERNS = List.of(
        Pattern.compile("viewstate.*invalid",          Pattern.CASE_INSENSITIVE),
        Pattern.compile("mac.*validation.*failed",     Pattern.CASE_INSENSITIVE),
        Pattern.compile("invalid.*viewstate",          Pattern.CASE_INSENSITIVE),
        Pattern.compile("viewstate.*tamper",           Pattern.CASE_INSENSITIVE),
        Pattern.compile("validation.*of.*viewstate",   Pattern.CASE_INSENSITIVE),
        Pattern.compile("state.*information.*invalid", Pattern.CASE_INSENSITIVE),
        Pattern.compile("System\\.Web\\.UI\\.ViewState", Pattern.CASE_INSENSITIVE),
        Pattern.compile("EnableViewStateMac",          Pattern.CASE_INSENSITIVE)
    );

    // Patterns in the response that indicate a .NET deserialization error
    // (server tried to deserialize but the payload was invalid format)
    private static final List<Pattern> DESER_ERROR_PATTERNS = List.of(
        Pattern.compile("BinaryFormatter",             Pattern.CASE_INSENSITIVE),
        Pattern.compile("SerializationException",      Pattern.CASE_INSENSITIVE),
        Pattern.compile("ObjectStateFormatter",        Pattern.CASE_INSENSITIVE),
        Pattern.compile("deserialization.*failed",     Pattern.CASE_INSENSITIVE),
        Pattern.compile("System\\.Runtime\\.Serialization", Pattern.CASE_INSENSITIVE)
    );

    // A minimal tampered __VIEWSTATE value: valid Base64, but binary content that
    // will fail deserialization if the server tries to process it. Used to probe
    // whether MAC validation is enforced (MAC-enabled server rejects before trying
    // to deserialize; MAC-disabled server tries and produces a deserialization error).
    private static final String TAMPERED_VIEWSTATE =
        "/wEPDwUKMTkzNTg5MDQ1Mg8WCB4HY29udGVudAUfYnVycG1heC10YW1wZXJlZC05NzQxLXRlc3Q"
        + "WAgIBEBYCHgNyb2wFBWFkbWluFgICAQ8WAh4EbmFtZQUFYWRtaW5kZGQY";

    // Unique marker embedded in the tampered ViewState string for reflection detection
    private static final String TAMPER_MARKER = "burpmax-tampered-9741-test";

    // ── Entry point ───────────────────────────────────────────────────────────

    static List<ActiveScanResult> probe(ProbeContext ctx,
                                        RequestBuilder rb,
                                        HttpSender sender,
                                        OobClient oob) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Gate: must have at least one ViewState / WebForms field
        if (!hasViewstateFields(ctx)) return results;

        // ── Check 1: MAC validation (active — tamper the ViewState) ───────────
        ActiveScanResult macResult = checkMacValidation(ctx, rb, sender);
        if (macResult != null) results.add(macResult);

        // ── Check 2: ViewState encryption (passive — analyse original value) ──
        ActiveScanResult encResult = checkEncryption(ctx);
        if (encResult != null) results.add(encResult);

        // ── Check 3: ViewState in URL (passive) ───────────────────────────────
        ActiveScanResult urlResult = checkViewstateInUrl(ctx);
        if (urlResult != null) results.add(urlResult);

        // ── Check 4: OOB deserialization (if MAC check didn't return a result) ─
        // Only run if MAC check didn't fire (would be redundant) and OOB is available
        if (macResult == null && oob != null && oob.isAvailable()) {
            probeOobDeserialization(ctx, rb, sender, oob);
        }

        return results;
    }

    // ── Check 1: MAC validation ────────────────────────────────────────────────

    private static ActiveScanResult checkMacValidation(ProbeContext ctx,
                                                         RequestBuilder rb,
                                                         HttpSender sender) {
        // Find the __VIEWSTATE parameter
        String vsParam = findViewstateParam(ctx);
        if (vsParam == null) return null;

        // Baseline response
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        if (baseline == null) return null;
        String baseBody = baseline.body();

        // Probe with tampered ViewState
        byte[] probeReq = rb.buildProbeRequest(ctx, vsParam, TAMPERED_VIEWSTATE);
        if (probeReq == null) return null;

        HttpSender.Response resp = sender.send(ctx.service, probeReq);
        if (resp == null) return null;
        String respBody = resp.body();

        // If the response contains a MAC error, the server IS validating — not vulnerable
        boolean macErrorInResp = MAC_ERROR_PATTERNS.stream()
                .anyMatch(p -> p.matcher(respBody).find());
        if (macErrorInResp) return null;  // MAC validation is active - correct behaviour

        // Check if the server attempted deserialization (deser error = MAC was skipped)
        boolean deserError = DESER_ERROR_PATTERNS.stream()
                .anyMatch(p -> p.matcher(respBody).find());

        // Check if our marker value was reflected (server decoded and processed the tampered state)
        boolean markerReflected = respBody.contains(TAMPER_MARKER);

        // Check: meaningful response body divergence — not just "both are 2xx".
        // Many WebForms pages return HTTP 200 for all requests (error content in body, custom
        // error pages, silent logging). Using "2xx" alone would fire on every WebForms endpoint
        // where customErrors mode="On" suppresses the MAC error from the response body.
        // Require actual content divergence in addition to status.
        int baseBodyLen = baseBody.length();
        int respBodyLen = respBody.length();
        boolean significantBodyChange = Math.abs(baseBodyLen - respBodyLen) > 50
                || (baseBodyLen > 0 && (double)Math.abs(baseBodyLen - respBodyLen) / baseBodyLen > 0.05);
        boolean bodyDiverged = significantBodyChange
                || (!baseBody.isEmpty() && !respBody.isEmpty() && !baseBody.equals(respBody));

        // Require at least one positive signal: deserialization error, marker reflection,
        // or meaningful body divergence (not just "both 2xx")
        if (!deserError && !markerReflected && !bodyDiverged) return null;

        // Confirm: re-send to ensure the signal is reproducible (not transient)
        HttpSender.Response confirm = sender.send(ctx.service, probeReq);
        if (confirm == null) return null;
        String confirmBody = confirm.body();

        // Confirm signal must also be positive — avoids transient body differences
        boolean confirmDeserError   = DESER_ERROR_PATTERNS.stream().anyMatch(p -> p.matcher(confirmBody).find());
        boolean confirmReflected    = confirmBody.contains(TAMPER_MARKER);
        int     confirmBodyLen      = confirmBody.length();
        boolean confirmBodyDiverged = Math.abs(baseBodyLen - confirmBodyLen) > 50
                || (!baseBody.isEmpty() && !confirmBody.isEmpty() && !baseBody.equals(confirmBody));

        if (!confirmDeserError && !confirmReflected && !confirmBodyDiverged) return null;

        String signal = deserError ? "deserialization error in response (server tried to process tampered state)"
                : markerReflected ? "tampered marker value reflected in response"
                : "server returned 2xx with tampered ViewState (no MAC rejection)";

        return new ActiveScanResult(
            ".NET ViewState MAC Validation Disabled (Deserialization Risk)", SEV_CRITICAL,
            "The ASP.NET ViewState MAC validation appears to be disabled on this endpoint. " +
            "A tampered __VIEWSTATE value was sent and the server did not return a 'ViewState " +
            "is invalid' / 'MAC validation failed' error - instead it " + signal + ". " +
            "When EnableViewStateMac=false (or no machineKey is configured), the server " +
            "deserializes the __VIEWSTATE value without verifying its integrity. An attacker " +
            "can craft a malicious ViewState using ysoserial.net gadget chains to achieve " +
            "remote code execution on the web server. Affected gadgets include: TypeConfuseDelegate, " +
            "ObjectDataProvider, TextFormattingRunProperties, and others depending on " +
            ".NET version and installed libraries.",
            "ViewState field: " + vsParam +
            " | Tampered value sent: " + TAMPERED_VIEWSTATE.substring(0, 40) + "..." +
            " | Signal: " + signal +
            " | Baseline status: " + baseline.statusCode() +
            " | Probe status: " + resp.statusCode(),
            VIEWSTATE_REMEDIATION, "CWE-502",
            ctx.url, vsParam, TAMPERED_VIEWSTATE,
            trunc(new String(probeReq, StandardCharsets.ISO_8859_1), 300),
            "Signal: " + signal + " | Body snippet: " + trunc(respBody, 150),
            probeReq, resp.raw(), -1L
        );
    }

    // ── Check 2: ViewState encryption ────────────────────────────────────────

    private static ActiveScanResult checkEncryption(ProbeContext ctx) {
        String vsParam = findViewstateParam(ctx);
        if (vsParam == null) return null;
        String vsValue = ctx.paramValue(vsParam);
        if (vsValue == null || vsValue.length() < 20) return null;

        // Attempt to base64 decode and check if it's plaintext (not encrypted)
        try {
            // URL-decode the ViewState value first — URL-encoded forms use %2B for +, %2F for /,
            // %3D for =. Failing to decode before base64 decode causes decode failure.
            String vsDecoded;
            try {
                vsDecoded = java.net.URLDecoder.decode(vsValue, java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception e) {
                vsDecoded = vsValue;
            }
            byte[] decoded = java.util.Base64.getDecoder().decode(
                    vsDecoded.replaceAll("\\s", "").replace('-', '+').replace('_', '/'));
            String decodedStr = new String(decoded, StandardCharsets.ISO_8859_1);

            // Encrypted ViewState starts with 0xFF 0xFF (or other non-ASCII prefix)
            // Unencrypted ViewState starts with 0xFF 0x01 (LosFormatter header)
            // and typically contains readable string fragments
            boolean looksUnencrypted = decodedStr.length() > 10
                    && decodedStr.chars().filter(c -> c >= 32 && c < 127).count()
                        > decodedStr.length() * 0.3;  // >30% printable ASCII

            if (!looksUnencrypted) return null;

            // Look for suspicious readable content in the ViewState
            boolean hasSensitiveContent = decodedStr.toLowerCase().contains("role")
                    || decodedStr.toLowerCase().contains("user")
                    || decodedStr.toLowerCase().contains("admin")
                    || decodedStr.toLowerCase().contains("session")
                    || decodedStr.toLowerCase().contains("password")
                    || decodedStr.toLowerCase().contains("email")
                    || decodedStr.toLowerCase().contains("select");

            if (!hasSensitiveContent) return null;

            return new ActiveScanResult(
                ".NET ViewState Unencrypted (Sensitive Data Exposure)", SEV_MEDIUM,
                "The __VIEWSTATE field does not appear to be encrypted. The decoded content " +
                "contains readable strings including potentially sensitive data fragments. " +
                "Unencrypted ViewState can expose server-side object graphs, session data, " +
                "database query results, and user attributes to any client that can intercept " +
                "or read the HTML source. If page state contains user roles, permissions, or " +
                "sensitive business data, an attacker can read or tamper with it.",
                "ViewState field: " + vsParam +
                " | Decoded preview: " + trunc(decodedStr, 120) +
                " | Readable fraction: " + (int)(decodedStr.chars().filter(c -> c >= 32 && c < 127).count() * 100 / decodedStr.length()) + "%",
                "Enable ViewState encryption in Web.config:\n" +
                "  <pages viewStateEncryptionMode=\"Always\" />\n\n" +
                "Configure a strong machineKey in Web.config (or use auto-generate in IIS):\n" +
                "  <machineKey validationKey=\"[64-hex-chars]\" decryptionKey=\"[48-hex-chars]\"\n" +
                "              validation=\"HMACSHA256\" decryption=\"AES\" />\n\n" +
                "Or migrate away from WebForms ViewState entirely by using Session state\n" +
                "or client-side frameworks that don't need server-side page state.",
                "CWE-312",
                ctx.url, vsParam, "(unencrypted ViewState)",
                trunc(new String(ctx.originalRequest, StandardCharsets.ISO_8859_1), 300),
                "Decoded ViewState preview: " + trunc(decodedStr, 150),
                ctx.originalRequest, ctx.originalResponse, -1L
            );
        } catch (Exception e) {
            return null;  // Base64 decode failed - ViewState may be encrypted or malformed
        }
    }

    // ── Check 3: ViewState in URL ─────────────────────────────────────────────

    private static ActiveScanResult checkViewstateInUrl(ProbeContext ctx) {
        String urlLower = ctx.url.toLowerCase();
        if (!urlLower.contains("__viewstate") && !urlLower.contains("%5f%5fviewstate"))
            return null;

        return new ActiveScanResult(
            ".NET ViewState in URL (CSRF and Leakage Risk)", SEV_LOW,
            "The __VIEWSTATE value appears in the URL query string. ViewState in URLs " +
            "leaks page state via the HTTP Referer header to any third-party resources " +
            "on the page (analytics, CDN assets, external fonts). If the ViewState is " +
            "not encrypted, it may expose sensitive server-side data. Additionally, " +
            "ViewState in GET requests can be shared via URL sharing, enabling unintended " +
            "state replay by other users.",
            "URL contains __VIEWSTATE: " + trunc(ctx.url, 200),
            "Move __VIEWSTATE to a POST body field:\n" +
            "  WebForms by default uses POST for postbacks - ensure no form is using\n" +
            "  GET method. Check Page.SmartNavigation and any custom URL routing.\n" +
            "Enable Referrer-Policy: no-referrer on ViewState-bearing pages to prevent\n" +
            "  leakage even if ViewState ends up in URLs.",
            "CWE-598",
            ctx.url, "__VIEWSTATE", "(in URL)",
            trunc(new String(ctx.originalRequest, StandardCharsets.ISO_8859_1), 300),
            "ViewState found in URL: " + trunc(ctx.url, 200),
            ctx.originalRequest, ctx.originalResponse, -1L
        );
    }

    // ── Check 4: OOB deserialization ──────────────────────────────────────────

    /**
     * Injects a specially crafted __VIEWSTATE payload that, if deserialized without
     * MAC validation, triggers an OOB DNS callback via a .NET deserialization gadget.
     *
     * The payload uses the same URLDNS-equivalent pattern as JavaDeserializationProbe
     * but wrapped in the LosFormatter/ObjectStateFormatter container that ASP.NET uses
     * for ViewState. Without MAC validation, the server will attempt to deserialize
     * this and trigger the DNS lookup.
     */
    private static void probeOobDeserialization(ProbeContext ctx,
                                                  RequestBuilder rb,
                                                  HttpSender sender,
                                                  OobClient oob) {
        String vsParam = findViewstateParam(ctx);
        if (vsParam == null) return;

        String oobHost = oob.generateHost("viewstate-deser");
        if (oobHost == null) return;

        // Build a ViewState payload that embeds the OOB hostname in a string
        // field that will trigger a DNS resolution if deserialized.
        // This is a minimal LosFormatter-wrapped payload with an embedded URL reference.
        // It is designed to cause a deserialization attempt, not actual code execution.
        String oobPayload = buildViewstateOobPayload(oobHost);
        if (oobPayload == null) return;

        byte[] probeReq = rb.buildProbeRequest(ctx, vsParam, oobPayload);
        if (probeReq == null) return;

        oob.recordInjection(oobHost, ".NET ViewState Deserialization (OOB)",
                ctx.url, vsParam,
                "LosFormatter gadget → DNS lookup → " + oobHost,
                probeReq);
        sender.send(ctx.service, probeReq);
    }

    /**
     * Builds a __VIEWSTATE payload that embeds the OOB hostname. This is a
     * base64-encoded byte sequence that looks like a valid ViewState structure
     * but contains the OOB hostname in a position where .NET's LosFormatter
     * would attempt to resolve it as a type or URL reference.
     */
    private static String buildViewstateOobPayload(String oobHost) {
        // Minimal LosFormatter header (0xFF 0x01) + object marker + OOB hostname
        // This is not a full gadget chain — it is a probe payload that, if the
        // server calls deserialize(), will fail with an error but only AFTER
        // attempting to process the embedded hostname (which may trigger DNS).
        try {
            byte[] header = {(byte)0xFF, 0x01, 0x03, 0x00};  // LosFormatter type marker
            byte[] hostBytes = ("http://" + oobHost + "/viewstate").getBytes(StandardCharsets.UTF_8);
            // Length-prefixed string as LosFormatter stores strings
            int len = hostBytes.length;
            byte[] lenBytes = {(byte)(len & 0xFF), (byte)((len >> 8) & 0xFF)};

            byte[] payload = new byte[header.length + lenBytes.length + hostBytes.length];
            System.arraycopy(header,    0, payload, 0,                    header.length);
            System.arraycopy(lenBytes,  0, payload, header.length,        lenBytes.length);
            System.arraycopy(hostBytes, 0, payload, header.length + 2,    hostBytes.length);

            return java.util.Base64.getEncoder().encodeToString(payload);
        } catch (Exception e) {
            return null;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean hasViewstateFields(ProbeContext ctx) {
        return ctx.allParamNames().stream()
                .anyMatch(p -> VIEWSTATE_FIELDS.contains(p.toLowerCase()));
    }

    private static String findViewstateParam(ProbeContext ctx) {
        return ctx.allParamNames().stream()
                .filter(p -> p.toLowerCase().equals("__viewstate"))
                .findFirst().orElse(null);
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    // ── OOB finding builder ───────────────────────────────────────────────────

    public static ActiveScanResult buildOobFinding(OobClient.OobHit hit) {
        return new ActiveScanResult(
            ".NET ViewState Deserialization (OOB-Confirmed)", SEV_CRITICAL,
            "Unsafe .NET ViewState deserialization was confirmed via an out-of-band " +
            hit.interactionType() + " callback. The tampered __VIEWSTATE payload injected into '" +
            hit.parameter() + "' was deserialized by the server without MAC verification, " +
            "causing it to make an outbound connection to our OOB server (" +
            hit.interactionDetail() + "). MAC validation is disabled (EnableViewStateMac=false or " +
            "no machineKey configured), allowing an attacker to craft a malicious ViewState " +
            "using ysoserial.net gadget chains (TypeConfuseDelegate, ObjectDataProvider, " +
            "TextFormattingRunProperties) to achieve remote code execution on the web server.",
            "OOB callback: " + hit.interactionDetail() +
            " | Injection: " + hit.parameter() +
            " | Follow-up: craft ysoserial.net payload targeting detected .NET version",
            VIEWSTATE_REMEDIATION, "CWE-502",
            hit.endpoint(), hit.parameter(), hit.payload(), "", hit.interactionDetail());
    }

    private static final String VIEWSTATE_REMEDIATION =
        "PRIMARY FIX - Enable ViewState MAC validation (mandatory):\n" +
        "In Web.config, ensure:\n" +
        "  <pages enableViewStateMac=\"true\" />   ← default in .NET 4.5.2+\n" +
        "  <pages viewStateEncryptionMode=\"Always\" />\n\n" +
        "Configure a strong machineKey (do NOT use auto-generate in a web farm):\n" +
        "  <machineKey\n" +
        "    validationKey=\"[64 random hex chars]\"\n" +
        "    decryptionKey=\"[48 random hex chars]\"\n" +
        "    validation=\"HMACSHA256\"\n" +
        "    decryption=\"AES\" />\n\n" +
        "Generate a secure machineKey:\n" +
        "  $bytes = New-Object byte[] 64; [Security.Cryptography.RNGCryptoServiceProvider]::" +
        "Create().GetBytes($bytes); [Convert]::ToBase64String($bytes)\n\n" +
        ".NET FRAMEWORK VERSIONS:\n" +
        "  .NET 4.5.2+: ViewState MAC is enforced by default and cannot be disabled globally\n" +
        "  .NET 4.0 and earlier: you MUST explicitly set enableViewStateMac=\"true\"\n" +
        "  .NET Core / ASP.NET Core: does not use WebForms ViewState - not affected\n\n" +
        "ADDITIONAL CONTROLS:\n" +
        "  - Set a ViewState user key per session to prevent cross-user ViewState replay:\n" +
        "    Page.ViewStateUserKey = Session.SessionID;\n" +
        "  - Minimise ViewState content - store sensitive data in Session, not ViewState\n" +
        "  - Consider migrating from WebForms to ASP.NET Core MVC or Razor Pages";
}
