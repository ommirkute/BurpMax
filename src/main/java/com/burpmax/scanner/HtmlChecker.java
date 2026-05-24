package com.burpmax.scanner;

import java.util.*;
import java.util.Set;
import java.util.regex.*;
import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

public class HtmlChecker {
    // Match <script src=...> and <link href=...> pointing to external URLs
    // We match case-insensitively on the lowercased tag string in code
    private static final Pattern RE_EXT = Pattern.compile(
        "(?i)<(script|link)(\\s[^>]*)?>",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    // Separate URL extractor for src/href values
    private static final Pattern RE_EXT_URL = Pattern.compile(
        "(?i)(?:src|href)=[\\x22\\x27](https?://(?!localhost)[^\\x22\\x27]+)[\\x22\\x27]");

    // CDN domains where SRI is structurally impractical (dynamic content, versioning by CDN, etc.)
    private static final Set<String> SRI_EXEMPT_DOMAINS = Set.of(
        "fonts.googleapis.com", "fonts.gstatic.com",
        "www.google-analytics.com", "www.googletagmanager.com", "analytics.google.com",
        "cdn.stripe.com", "js.stripe.com",
        "www.recaptcha.net", "recaptcha.net",
        "hcaptcha.com", "js.hcaptcha.com",
        "challenges.cloudflare.com",
        "connect.facebook.net",
        "platform.twitter.com", "cdn.syndication.twimg.com",
        "www.google.com" // Google sign-in button
    );

    public static List<CheckResult> check(String body, String contentType) {
        List<CheckResult> results = new ArrayList<>();
        if (body == null || contentType == null || !contentType.toLowerCase().contains("html")) return results;

        // SRI check — supply chain risk is real; skip known no-SRI CDNs and non-executable resources
        Matcher m = RE_EXT.matcher(body);
        while (m.find()) {
            String tag     = m.group();
            String tagLower= tag.toLowerCase();
            String tagName = m.group(1).toLowerCase(); // "script" or "link"

            // Skip non-executable link rel types (preconnect, dns-prefetch, preload)
            if ("link".equals(tagName) && (tagLower.contains("preconnect")
                    || tagLower.contains("dns-prefetch") || tagLower.contains("preload"))) continue;

            // Extract the external URL from src or href attribute
            Matcher urlM = RE_EXT_URL.matcher(tag);
            if (!urlM.find()) continue;
            String url    = urlM.group(1);
            String domain = url.replaceAll("https?://([^/?#]+).*", "$1").toLowerCase();

            // Skip exempt CDN domains
            if (SRI_EXEMPT_DOMAINS.contains(domain)) continue;

            // Only flag executable resources: <script src=...> and <link rel="stylesheet" href=...>
            boolean isScript     = "script".equals(tagName);
            boolean isStylesheet = "link".equals(tagName) && tagLower.contains("stylesheet");
            if (!isScript && !isStylesheet) continue;

            if (!tagLower.contains("integrity=")) {
                results.add(new CheckResult("Subresource Integrity (SRI) Missing on External Resource", SEV_LOW,
                    "This page loads a script or stylesheet from an external domain without a Subresource Integrity (SRI) hash. Without SRI, if the CDN is compromised, the attacker's modified script is silently loaded and executed with full DOM access.",
                    "External resource without SRI: " + trunc(tag, 120),
                    "- Generate SRI hashes: openssl dgst -sha384 -binary resource.js | openssl base64 -A\n- Add to each tag: <script src=\"...\" integrity=\"sha384-{hash}\" crossorigin=\"anonymous\">\n- Consider self-hosting critical third-party scripts to eliminate supply chain risk",
                    "CWE-353"));
                break;
            }
        }
        return results;
    }
}
