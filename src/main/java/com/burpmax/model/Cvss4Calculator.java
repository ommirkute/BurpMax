package com.burpmax.model;

import java.util.Map;

/**
 * CVSS 4.0 base score lookup for all BurpMax findings.
 *
 * Scores are pre-calculated CVSS 4.0 base scores using the official
 * scoring formula (https://www.first.org/cvss/v4.0) with the most
 * representative vector for each vulnerability class.
 *
 * Vector components used:
 *   AV  Attack Vector        (N=Network, A=Adjacent, L=Local, P=Physical)
 *   AC  Attack Complexity    (L=Low, H=High)
 *   AT  Attack Requirements  (N=None, P=Present)
 *   PR  Privileges Required  (N=None, L=Low, H=High)
 *   UI  User Interaction     (N=None, P=Passive, A=Active)
 *   VC/VI/VA  Confidentiality/Integrity/Availability impact on Vulnerable system
 *   SC/SI/SA  Same for Subsequent system
 *
 * Returns a pre-set score + vector string. Analysts can override via
 * the Override Severity button or by editing the finding note.
 */
public class Cvss4Calculator {

    public record CvssResult(double score, String vector) {}

    // Pre-calculated scores mapped by finding name prefix (case-insensitive)
    // Key = lowercase prefix of finding name, Value = CvssResult
    private static final Map<String, CvssResult> SCORES = Map.ofEntries(
        // ── Critical findings ──────────────────────────────────────────────
        Map.entry("sql injection",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")),
        Map.entry("os command injection",
            new CvssResult(10.0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")),
        Map.entry("server-side template injection",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N")),
        Map.entry("xml external entity",
            new CvssResult(8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N")),
        Map.entry("path traversal",
            new CvssResult(8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("log4shell",
            new CvssResult(10.0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")),
        Map.entry("jwt algorithm set to none",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")),
        Map.entry("jwt algorithm none",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")),
        Map.entry("authentication bypass",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")),
        Map.entry("server-side prototype pollution",
            new CvssResult(8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("hardcoded secret",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")),
        Map.entry("aws access key",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")),
        Map.entry("rsa private key",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")),
        Map.entry("generic private key",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")),

        // ── High findings ──────────────────────────────────────────────────
        Map.entry("server-side request forgery",
            new CvssResult(8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N")),
        Map.entry("reflected cross-site scripting",
            new CvssResult(7.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:H/SI:L/SA:N")),
        Map.entry("reflected xss",
            new CvssResult(7.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:H/SI:L/SA:N")),
        Map.entry("stored xss",
            new CvssResult(8.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:H/SI:H/SA:N")),
        Map.entry("dom-based xss",
            new CvssResult(7.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:H/SI:L/SA:N")),
        Map.entry("sensitive file exposure",
            new CvssResult(7.5, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("sensitive endpoint",
            new CvssResult(6.9, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("unrestricted file upload",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")),
        Map.entry("xss via",
            new CvssResult(7.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:H/SI:L/SA:N")),
        Map.entry("cors: arbitrary origin reflected with credentials",
            new CvssResult(8.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("idor",
            new CvssResult(7.5, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("http request smuggling",
            new CvssResult(8.7, "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N")),
        Map.entry("jwt weak",
            new CvssResult(8.1, "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("ldap injection",
            new CvssResult(8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("nosql injection",
            new CvssResult(8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("sensitive data in authorization bearer",
            new CvssResult(7.5, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("pii exposure",
            new CvssResult(7.5, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("sensitive pii",
            new CvssResult(7.5, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("graphql alias overloading",
            new CvssResult(7.5, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N")),
        Map.entry("graphql batch",
            new CvssResult(7.5, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N")),

        // ── Medium findings ────────────────────────────────────────────────
        Map.entry("csrf",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("open redirect",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N")),
        Map.entry("host header injection",
            new CvssResult(6.9, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("cors: arbitrary origin reflected (no credentials)",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("missing rate limiting",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("graphql introspection",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("graphql no query depth",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N")),
        Map.entry("insecure cache-control",
            new CvssResult(4.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("cleartext credentials",
            new CvssResult(4.0, "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("credentials transmitted",
            new CvssResult(4.0, "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("dangerous http methods",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N")),

        // ── Low findings ───────────────────────────────────────────────────
        Map.entry("http strict transport security",
            new CvssResult(2.0, "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("content security policy",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("clickjacking",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("mass assignment",
            new CvssResult(7.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("over-posting",
            new CvssResult(7.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("race condition",
            new CvssResult(8.1, "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N")),
        Map.entry("toctou",
            new CvssResult(8.1, "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N")),
        Map.entry("oauth 2.0: open redirect_uri",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("oauth 2.0: authorization code reuse",
            new CvssResult(8.1, "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("oauth 2.0: redirect_uri matching bypass",
            new CvssResult(8.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("oauth 2.0: missing state",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("oauth 2.0: token exposed in url",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("oauth 2.0: implicit flow",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("oauth 2.0: pkce not used",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("java deserialization",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")),
        Map.entry(".net viewstate mac validation disabled",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")),
        Map.entry(".net viewstate unencrypted",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry(".net viewstate in url",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("hidden / undocumented parameter",
            new CvssResult(5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("http request smuggling (h2.cl)",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N")),
        Map.entry("http request smuggling (h2.te)",
            new CvssResult(9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N")),
        Map.entry("x-content-type",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("referrer-policy",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("permissions-policy",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("subresource integrity",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("cookie",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("server version disclosure",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("internal ip disclosure",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("version disclosure",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
        Map.entry("outdated",
            new CvssResult(2.0, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"))
    );

    /**
     * Look up CVSS 4.0 score for a finding by name.
     * Matches on the longest prefix that matches a known vulnerability class.
     * Returns null if no match found (caller should use severity default).
     */
    public static CvssResult calculate(String findingName) {
        if (findingName == null || findingName.isBlank()) return null;
        // Strip [ACTIVE] prefix and normalise
        String name = findingName
                .replaceFirst("(?i)^\\[ACTIVE\\]\\s*", "")
                .toLowerCase().trim();

        // Try exact prefix matches — longest match wins
        String bestKey = null;
        for (String key : SCORES.keySet()) {
            if (name.startsWith(key)) {
                if (bestKey == null || key.length() > bestKey.length()) {
                    bestKey = key;
                }
            }
        }
        return bestKey != null ? SCORES.get(bestKey) : null;
    }

    /** Returns the CVSS score for display — uses lookup then severity default. */
    public static double scoreFor(Finding f) {
        CvssResult r = calculate(f.name);
        if (r != null) return r.score;
        return Finding.defaultCvssScore(f.effectiveSeverity());
    }

    /** Returns the CVSS vector string, or empty string if not known. */
    public static String vectorFor(Finding f) {
        CvssResult r = calculate(f.name);
        return r != null ? r.vector : "";
    }
}
