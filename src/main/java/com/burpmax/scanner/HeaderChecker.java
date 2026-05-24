package com.burpmax.scanner;

import com.burpmax.model.Finding;

import java.util.*;
import java.util.regex.*;

import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

public class HeaderChecker {

    public static List<CheckResult> check(
            Map<String, String> respHeaders,
            Map<String, String> reqHeaders,
            int statusCode) {

        List<CheckResult> results = new ArrayList<>();

        Map<String, String> h  = lower(respHeaders);
        Map<String, String> rh = lower(reqHeaders != null ? reqHeaders : Collections.emptyMap());

        String contentType = h.getOrDefault("content-type", "").toLowerCase();

        // FALSE POSITIVE GUARD: header findings only apply to actual successful page
        // responses. Probe-generated 4xx/5xx responses and non-HTML API responses
        // should not be reported — the headers are irrelevant on error responses.
        // Exception: HSTS fires on all HTTPS responses including redirects (3xx).
        boolean is2xx   = statusCode >= 200 && statusCode < 300;
        boolean is3xx   = statusCode >= 300 && statusCode < 400;
        boolean isHtmlOrPage = contentType.contains("text/html") || contentType.contains("text/xhtml")
                            || contentType.contains("application/xhtml") || contentType.isEmpty();
        // Skip entirely for 4xx/5xx — probe error responses should never generate header findings
        if (statusCode >= 400) return results;

        // ── X-Frame-Options ───────────────────────────────────────────────
        if (is2xx && isHtmlOrPage && !h.containsKey("x-frame-options")) {
            results.add(new CheckResult(
                "Website is Vulnerable to Clickjacking", SEV_LOW,
                "Clickjacking (UI Redressing) occurs when an attacker embeds the target page inside a hidden or transparent iframe on a malicious website. The victim sees innocent-looking UI elements -- buttons, links, checkboxes -- but is actually interacting with the target application behind them. This can result in unintended fund transfers, account changes, permission grants, or form submissions without the victim's awareness. Since the attack uses the victim's own authenticated session, it bypasses authentication entirely. This page is missing the X-Frame-Options header, meaning any external site can embed it in an iframe.",
                "X-Frame-Options header is absent in the response.",
                "- Set X-Frame-Options: DENY to block all framing, or SAMEORIGIN to allow only same-origin frames\n- Prefer the modern CSP directive: Content-Security-Policy: frame-ancestors 'self' (more granular and overrides X-Frame-Options)\n- Apply the header on every HTML response, not just the homepage or login page\n- Test by loading the page inside an iframe on a different domain and confirming it is blocked\n- Use securityheaders.com to verify the header is present across all routes",
                "CWE-1021"));
        }

        // ── HSTS ──────────────────────────────────────────────────────────
        if ((is2xx || is3xx) && !h.containsKey("strict-transport-security")) {
            results.add(new CheckResult(
                "HTTP Strict Transport Security (HSTS) Disabled", SEV_LOW,
                "HTTP Strict Transport Security (HSTS) instructs browsers to always use HTTPS for your domain and refuse to downgrade to HTTP, even if the user types http:// explicitly. Without HSTS, an attacker on the same network (public Wi-Fi, corporate proxy, ISP) can perform an SSL-stripping attack: intercepting the initial HTTP request before the browser upgrades to HTTPS and silently proxying the connection in plaintext. This exposes session cookies, credentials, tokens, and all transmitted data. SSL stripping is invisible to the user -- the browser shows no warning. HSTS eliminates this attack class by ensuring the browser never makes an HTTP connection to the domain.",
                "Strict-Transport-Security header is absent.",
                "- Add to all HTTPS responses: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n- max-age=31536000 enforces HTTPS for 1 year; use 63072000 (2 years) for high-security applications\n- includeSubDomains protects all subdomains -- ensure every subdomain supports HTTPS before enabling this\n- preload registers your domain in browser preload lists (hstspreload.org) enforcing HTTPS even on first visit\n- Redirect all HTTP traffic to HTTPS at the load balancer or web server before setting this header\n- Test using ssllabs.com and securityheaders.com to verify HSTS is correctly configured",
                "CWE-319"));
        }

        // ── CSP ───────────────────────────────────────────────────────────
        // CSP is only meaningful on responses that render content (2xx).
        // 3xx redirects are immediately followed by another request — no content rendered.
        String csp = h.get("content-security-policy");
        if (is2xx) {
            if (csp == null) {
                results.add(new CheckResult(
                    "Content Security Policy Header is Missing", SEV_LOW,
                    "Content Security Policy (CSP) is a browser security mechanism that restricts which sources of scripts, styles, images, and other resources the browser is permitted to load and execute. Without a CSP, a successful Cross-Site Scripting (XSS) attack has unlimited reach: injected scripts can steal session cookies, log keystrokes, exfiltrate data to attacker servers, redirect users, and perform actions on their behalf. CSP is a critical defence-in-depth control -- even if XSS input bypasses server-side validation and reaches the page, CSP can prevent the injected script from executing or making outbound requests. This response has no Content-Security-Policy header.",
                    "Content-Security-Policy header is absent.",
                    "- Start with a report-only policy to identify violations without breaking functionality: Content-Security-Policy-Report-Only: default-src 'self'\n- Move to enforcement once violations are resolved: Content-Security-Policy: default-src 'self'; object-src 'none'\n- Replace unsafe-inline with nonces on inline scripts: script-src 'self' 'nonce-{random-per-request}'\n- Add base-uri 'self' to prevent base-tag injection attacks\n- Include a report-uri or report-to directive to collect real-world violation reports\n- Never use wildcards (*) in any directive -- they defeat the purpose of CSP\n- Validate your policy using CSP Evaluator (csp-evaluator.withgoogle.com) before deploying",
                    "CWE-116"));
            } else if (csp.contains("unsafe-inline") || csp.contains("unsafe-eval") || csp.contains("*")) {
                results.add(new CheckResult(
                    "Misconfigured CSP Security Header", SEV_LOW,
                    "A Content-Security-Policy is present but configured with directives that largely negate its protection. 'unsafe-inline' permits inline <script> blocks and event handlers -- the primary XSS vector -- meaning injected inline scripts can execute freely. 'unsafe-eval' allows eval(), new Function(), and setTimeout(string), enabling attackers to run arbitrary JavaScript if they can inject a string into these functions. A wildcard (*) in script-src or default-src permits scripts from any domain on the internet. Any one of these directives alone can be sufficient to bypass CSP entirely and achieve full XSS exploitation despite the header being present.",
                    "CSP: " + trunc(csp, 150),
                    "- Remove unsafe-inline from script-src and replace with per-request nonces: script-src 'self' 'nonce-{random}'\n- Remove unsafe-eval and refactor code using eval(), new Function(), or setTimeout with string arguments\n- Replace wildcard origins (*) with an explicit list of trusted domains\n- Use Subresource Integrity (integrity= attribute) on all third-party scripts alongside CSP\n- Regenerate nonces cryptographically on every page load (never reuse nonces)\n- Test the updated policy with CSP Evaluator (csp-evaluator.withgoogle.com) and browser console violations",
                    "CWE-116"));
            }
        }   // end is2xx CSP block

        // ── X-Content-Type-Options ────────────────────────────────────────
        // Only meaningful on responses with actual content — skip redirects.
        if (is2xx && !h.containsKey("x-content-type-options")) {
            results.add(new CheckResult(
                "X-Content-Type Header is Missing", SEV_LOW,
                "The X-Content-Type-Options: nosniff header prevents browsers from MIME-sniffing a response away from the declared Content-Type. Without it, if an attacker can upload a file that contains HTML or JavaScript but is stored with a non-script MIME type, browsers may ignore the server's content-type and execute the content as a script. This is particularly dangerous for file upload functionality: an attacker uploads a .jpg that actually contains JavaScript, and without nosniff, browsers interpret it as a script when requested directly.",
                "X-Content-Type-Options header is absent.",
                "- Add to all responses: X-Content-Type-Options: nosniff\n- Configure at the web server or reverse proxy level to apply globally rather than per-route\n- Nginx: add_header X-Content-Type-Options nosniff always;\n- Apache: Header always set X-Content-Type-Options nosniff\n- Express.js: Use helmet middleware (helmet.noSniff()) to set this header automatically\n- Verify presence using browser dev tools or securityheaders.com across all application routes",
                "CWE-16"));
        }

        // ── Server header ─────────────────────────────────────────────────
        String server = h.get("server");
        if (server != null && server.matches(".*\\d+\\.\\d+.*")) {
            results.add(new CheckResult(
                "Server Version Disclosure in Header", SEV_LOW,
                "The Server response header reveals the web server software name and exact version number. Attackers cross-reference this information with CVE databases to identify known vulnerabilities in that specific version and target the server with exploit code written for it. Version disclosure significantly reduces the reconnaissance time required before an attack, turning a general web server into a specific, exploitable target with known weaknesses.",
                "Server: " + trunc(server, 100),
                "- Nginx: Add 'server_tokens off;' to the http block in nginx.conf\n- Apache: Set 'ServerTokens Prod' and 'ServerSignature Off' in httpd.conf\n- IIS: Remove the Server header using URL Rewrite outbound rules or custom HttpModule\n- Never include version numbers in Server, X-Powered-By, or any other response header\n- Use a reverse proxy (nginx, Cloudflare) to strip or replace server identification headers before they reach clients",
                "CWE-200"));
        }

        // ── X-Powered-By ──────────────────────────────────────────────────
        if (h.containsKey("x-powered-by")) {
            results.add(new CheckResult(
                "Technology Disclosed via X-Powered-By Header", SEV_LOW,
                "The X-Powered-By header reveals the server-side technology stack (PHP version, ASP.NET version, Express). This information assists attackers in identifying technology-specific vulnerabilities, selecting exploit payloads, and understanding the application architecture. Combined with other headers, it enables precise fingerprinting of the complete technology stack with zero active probing.",
                "X-Powered-By: " + trunc(h.get("x-powered-by"), 100),
                "- PHP: Set expose_php = Off in php.ini\n- Express.js: app.disable('x-powered-by') or use helmet middleware\n- ASP.NET: Remove the header via web.config <customHeaders> or HttpModule\n- Configure at the reverse proxy to strip all X-Powered-By headers regardless of application setting",
                "CWE-200"));
        }

        // ── CORS ──────────────────────────────────────────────────────────
        String acao = h.getOrDefault("access-control-allow-origin", "");
        String acac = h.getOrDefault("access-control-allow-credentials", "").trim().toLowerCase();
        String reqOrigin = rh.getOrDefault("origin", "");
        boolean hasOriginReq = !reqOrigin.isEmpty();

        if ("*".equals(acao) && "true".equals(acac)
                && is2xx   // skip on error responses - many middleware emit this on 4xx/5xx by default
                && (contentType.contains("application/json") || contentType.contains("text/html")
                    || contentType.isEmpty())) {
            results.add(new CheckResult(
                "CORS Misconfiguration: Credentials with Wildcard Origin", SEV_MEDIUM,
                "This response sets Access-Control-Allow-Credentials: true alongside Access-Control-Allow-Origin: *. Browsers reject this specific combination per the CORS specification -- but this reveals a fundamentally broken CORS implementation that attempts to allow any origin to make credentialed requests. Non-browser clients (scripts, server-side HTTP clients, automation tools) are not subject to browser CORS enforcement and can exploit this directly.",
                "Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *",
                "- Remove the wildcard and replace with an explicit origin allowlist maintained server-side\n- Only echo the request Origin in ACAO if it matches a pre-approved list; return no header otherwise\n- Set Access-Control-Allow-Credentials: true only on endpoints that explicitly require cookie/token forwarding\n- For public APIs that do not need credentials, omit the credentials header and use wildcard or restrict by explicit origin\n- Audit all CORS middleware for reflected-origin patterns: response.header('ACAO', request.header('Origin'))\n- Add integration tests verifying that requests from non-whitelisted origins receive no ACAO header",
                "CWE-942"));
        } else if ("true".equals(acac) && hasOriginReq && acao.equals(reqOrigin)) {
            results.add(new CheckResult(
                "CORS Reflected Origin with Credentials Allowed", SEV_HIGH,
                "The server dynamically mirrors the request's Origin header into Access-Control-Allow-Origin without validating it against a whitelist. Combined with Access-Control-Allow-Credentials: true, this allows any website on the internet to make fully credentialed cross-origin requests to this endpoint and read the complete response.",
                "ACAO: " + acao + " | ACAC: true | Request Origin: " + reqOrigin,
                "- Never reflect the Origin header into ACAO without explicit validation against a server-side whitelist\n- Implement the pattern: if (ALLOWED_ORIGINS.contains(request.getOrigin())) { response.setHeader('ACAO', request.getOrigin()); }\n- If the origin is not in the allowlist, return no ACAO header -- the browser will block the cross-origin read\n- Search all CORS middleware and filters for code that sets ACAO to request.getHeader('Origin') without validation\n- For microservices, enforce CORS validation at the API gateway rather than in each service",
                "CWE-942"));
        }

        // ── Open Redirect ─────────────────────────────────────────────────
        // Only fire when the URL has parameters that commonly carry redirect destinations.
        // Firing on ALL 3xx redirects to external domains is far too noisy (SSO, CDNs,
        // OAuth flows all redirect externally by design).
        String location = h.getOrDefault("location", "");
        if (!location.isEmpty() && statusCode >= 300 && statusCode < 400 && location.startsWith("http")) {
            String reqUrl = rh.getOrDefault("x-original-url",
                           rh.getOrDefault("referer", ""));
            boolean hasRedirectParam = reqUrl.matches(
                "(?i).*[?&](?:redirect|redirect_uri|redirect_url|return|return_url|" +
                "returnto|next|goto|url|target|dest|destination|redir|forward|continue)" +
                "[=][^&]*.*");
            if (hasRedirectParam) {
                Pattern hostPat = Pattern.compile("https?://([^/?#]+)");
                Matcher mLoc = hostPat.matcher(location);
                Matcher mReq = hostPat.matcher(reqUrl);
                if (mLoc.find() && mReq.find()
                        && !mLoc.group(1).equalsIgnoreCase(mReq.group(1))) {
                    // Check if the redirect parameter value itself is reflected in the Location.
                    // Extract the param value from reqUrl to see if it matches the Location host.
                    // If the destination host in Location matches the redirect param value, it is
                    // much stronger signal that the param drives the redirect (not server-side config).
                    String redirectParamValue = "";
                    java.util.regex.Pattern pvPat = java.util.regex.Pattern.compile(
                        "(?i)[?&](?:redirect|redirect_uri|redirect_url|return|return_url|" +
                        "returnto|next|goto|url|target|dest|destination|redir|forward|continue)" +
                        "=([^&#+\s]{4,})", java.util.regex.Pattern.CASE_INSENSITIVE);
                    java.util.regex.Matcher pvM = pvPat.matcher(reqUrl);
                    if (pvM.find()) redirectParamValue = pvM.group(1);

                    boolean paramDrivesRedirect = !redirectParamValue.isEmpty()
                        && (location.contains(redirectParamValue)
                            || mLoc.group(1).equalsIgnoreCase(
                                redirectParamValue.replaceAll("https?://([^/?#]+).*", "$1")));

                    String sev    = paramDrivesRedirect ? SEV_MEDIUM : SEV_LOW;
                    String conf   = paramDrivesRedirect
                        ? "The Location header value appears to directly reflect the redirect " +
                          "parameter value, strongly indicating the destination is user-controlled."
                        : "This is a passive signal only - the redirect parameter is present but " +
                          "it is not confirmed that the server uses it to drive the Location header. " +
                          "Many SSO/OAuth flows redirect to external domains by design.";

                    results.add(new CheckResult(
                        "Potential Open Redirect", sev,
                        conf + " An attacker can craft URLs that appear to originate from a trusted " +
                        "domain to conduct phishing or bypass referrer-based access controls.",
                        "Location: " + trunc(location, 100) + " | Param detected in: " + trunc(reqUrl, 100),
                        "- CONFIRM: replace the redirect parameter value with https://canary.example.com " +
                        "and verify whether the Location header reflects it before treating as exploitable\n" +
                        "- Fix: replace user-supplied redirect URLs with server-side opaque tokens (integer/UUID) " +
                        "mapped to a pre-approved destination list\n" +
                        "- If a URL must be accepted: validate strictly against a server-side allowlist; " +
                        "reject any value containing :// not on the allowlist\n" +
                        "- Reject //-prefixed (protocol-relative), javascript:, data:, and non-https schemes",
                        "CWE-601"));
                }
            }
        }

        // ── Server Timing / Info Disclosure ──────────────────────────────
        for (String th : new String[]{"x-runtime", "x-response-time", "x-request-id", "x-powered-by-plesk"}) {
            if (h.containsKey(th)) {
                results.add(new CheckResult(
                    "Server Timing Information Disclosure", SEV_LOW,
                    "The response includes the " + th + " header, which exposes server processing time, request tracking IDs, or internal infrastructure details. Timing information can be used to detect back-end systems and in blind injection attacks to confirm successful payloads.",
                    th + ": " + trunc(h.get(th), 80),
                    "- Nginx: proxy_hide_header " + th + ";\n- Apache: Use Header unset " + th + " in httpd.conf\n- Strip diagnostic headers at the reverse proxy layer before they reach clients",
                    "CWE-200"));
                break;
            }
        }

        return results;
    }

    private static Map<String, String> lower(Map<String, String> m) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : m.entrySet())
            out.put(e.getKey().toLowerCase(), e.getValue());
        return out;
    }
}
