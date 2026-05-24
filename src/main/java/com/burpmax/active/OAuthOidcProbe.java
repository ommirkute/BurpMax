package com.burpmax.active;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * OAuth 2.0 / OpenID Connect misconfiguration probe.
 *
 * Tests 7 distinct misconfiguration classes that are commonly missed by
 * generic injection probes because they require understanding the OAuth
 * protocol flow rather than just fuzzing parameter values.
 *
 * Tested checks (in execution order, fast first):
 *
 *  1. Open redirect_uri (CRITICAL)
 *     Inject an attacker-controlled redirect_uri and check whether the
 *     server issues a redirect to it. A vulnerable server allows any URI;
 *     a correct one validates against a pre-registered allowlist.
 *     Detection: 3xx Location header contains the injected evil domain.
 *     Applies to: /authorize, /auth, /oauth/authorize endpoints.
 *
 *  2. state parameter absence (MEDIUM)
 *     Detect OAuth authorize requests that omit the state parameter entirely.
 *     No active probe needed — the original request is analysed.
 *     If state is absent, the flow is vulnerable to CSRF against the auth code grant.
 *
 *  3. Authorization code reuse (HIGH)
 *     If the original request is a token exchange (POST /token with code=),
 *     replay the request to check whether the same code is accepted twice.
 *     A valid server invalidates the code on first use.
 *     Detection: second response is 2xx AND contains an access_token.
 *
 *  4. token in URL / Referer leakage (MEDIUM)
 *     Detect access_token or id_token values in the URL query string.
 *     Tokens in URLs leak via Referer headers, browser history, and server logs.
 *     Applied passively to the original request URL; no additional request sent.
 *
 *  5. implicit flow detection (LOW-MEDIUM)
 *     Detect response_type=token or response_type=id_token (implicit flow).
 *     Implicit flow exposes tokens in URL fragments and has been deprecated in
 *     OAuth 2.1. No active probe needed.
 *
 *  6. PKCE absence on public clients (MEDIUM)
 *     When response_type=code is present (auth code flow) without code_challenge,
 *     and the request originates from a mobile/SPA pattern (no client secret in
 *     headers), the endpoint is vulnerable to auth code interception.
 *
 *  7. redirect_uri host matching bypass (HIGH)
 *     Tests path-traversal and subdomain variants against the registered
 *     redirect_uri to detect overly permissive host/path matching:
 *       - Appending a path:  registered/callback/../evil
 *       - Open subdomain:    evil.registered-host.com
 *       - Null byte:         registered%00evil.com
 *     Detection: 3xx Location header redirects to the bypass URI.
 *
 * Endpoint gating:
 *   Only runs on URLs containing /oauth, /authorize, /auth, /token, /oidc,
 *   /openid, /connect, /sso. The probe is completely skipped on all other
 *   endpoints to avoid false positives.
 *
 * Tier: 1 (fast; most checks are passive on the original request; only
 *        open redirect_uri and code reuse send additional requests).
 */
class OAuthOidcProbe {

    // ── OAuth endpoint detection ───────────────────────────────────────────────
    private static final List<Pattern> OAUTH_ENDPOINT_PATTERNS = List.of(
        Pattern.compile(".*/oauth.*",        Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/authorize.*",    Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/auth/.*",        Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/token.*",        Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/oidc/.*",        Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/openid.*",       Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/connect/.*",     Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/sso/.*",         Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/login/oauth.*",  Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/api/.*/auth.*",  Pattern.CASE_INSENSITIVE)
    );

    // ── Open redirect_uri test domain ─────────────────────────────────────────
    // Chosen to be obviously attacker-controlled without triggering WAF rules
    // that might block known "evil.com" test domains.
    private static final String EVIL_REDIRECT_HOST = "evil-redir-test.burpmax.local";
    private static final String EVIL_REDIRECT_URI  = "https://" + EVIL_REDIRECT_HOST + "/callback";

    // ── Access/id token patterns (for URL leakage detection) ─────────────────
    private static final List<Pattern> TOKEN_IN_URL_PATTERNS = List.of(
        Pattern.compile("[?&]access_token=([^&]{8,})",   Pattern.CASE_INSENSITIVE),
        Pattern.compile("[?&]id_token=([^&]{8,})",       Pattern.CASE_INSENSITIVE),
        Pattern.compile("[#&]access_token=([^&]{8,})",   Pattern.CASE_INSENSITIVE),
        Pattern.compile("#id_token=([^&]{8,})",          Pattern.CASE_INSENSITIVE),
        Pattern.compile("[?&]token=([A-Za-z0-9._-]{20,})",Pattern.CASE_INSENSITIVE)
    );

    // ── Successful token response detection ───────────────────────────────────
    private static final List<Pattern> TOKEN_RESPONSE_PATTERNS = List.of(
        Pattern.compile("\"access_token\"\\s*:\\s*\"[^\"]{8,}\""),
        Pattern.compile("\"id_token\"\\s*:\\s*\"[^\"]{8,}\""),
        Pattern.compile("\"token_type\"\\s*:\\s*\"bearer\"", Pattern.CASE_INSENSITIVE)
    );

    // ── Entry point ───────────────────────────────────────────────────────────

    static List<ActiveScanResult> probe(ProbeContext ctx,
                                        RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Gate: must look like an OAuth/OIDC endpoint
        if (!isOAuthEndpoint(ctx.url)) return results;

        // Parse OAuth parameters from URL and body
        Map<String, String> oauthParams = extractOAuthParams(ctx);

        // ── Check 1: Open redirect_uri ──────────────────────────────────────
        if (oauthParams.containsKey("redirect_uri")) {
            ActiveScanResult r = checkOpenRedirectUri(ctx, rb, sender, oauthParams);
            if (r != null) results.add(r);
        }

        // ── Check 2: Missing state parameter (CSRF on auth code flow) ──────
        if (isAuthorizationEndpoint(ctx.url)) {
            ActiveScanResult r = checkMissingState(ctx, oauthParams);
            if (r != null) results.add(r);
        }

        // ── Check 3: Authorization code reuse ─────────────────────────────
        if (isTokenEndpoint(ctx.url) && oauthParams.containsKey("code")) {
            ActiveScanResult r = checkCodeReuse(ctx, sender);
            if (r != null) results.add(r);
        }

        // ── Check 4: Token in URL (implicit flow leakage) ─────────────────
        {
            ActiveScanResult r = checkTokenInUrl(ctx);
            if (r != null) results.add(r);
        }

        // ── Check 5: Implicit flow (deprecated, token in fragment) ─────────
        if (oauthParams.containsKey("response_type")) {
            ActiveScanResult r = checkImplicitFlow(ctx, oauthParams);
            if (r != null) results.add(r);
        }

        // ── Check 6: PKCE absence on auth code flow ────────────────────────
        if (isAuthorizationEndpoint(ctx.url)) {
            ActiveScanResult r = checkPkceAbsence(ctx, oauthParams);
            if (r != null) results.add(r);
        }

        // ── Check 7: redirect_uri matching bypass variants ─────────────────
        if (oauthParams.containsKey("redirect_uri")) {
            ActiveScanResult r = checkRedirectUriBypass(ctx, rb, sender, oauthParams);
            if (r != null) results.add(r);
        }

        return results;
    }

    // ── Check 1: Open redirect_uri ────────────────────────────────────────────

    private static ActiveScanResult checkOpenRedirectUri(ProbeContext ctx,
                                                          RequestBuilder rb,
                                                          HttpSender sender,
                                                          Map<String, String> oauthParams) {
        String existing = oauthParams.get("redirect_uri");
        if (existing == null || existing.contains(EVIL_REDIRECT_HOST)) return null;

        // Inject the evil redirect_uri
        byte[] probeReq = rb.buildProbeRequest(ctx, "redirect_uri", EVIL_REDIRECT_URI);
        if (probeReq == null) return null;

        HttpSender.Response resp = sender.send(ctx.service, probeReq);
        if (resp == null) return null;

        // Check: server redirects to the evil URI
        String location = resp.header("location");
        if (location == null) return null;

        // Confirm the redirect goes to our injected host (not just any redirect)
        if (!location.contains(EVIL_REDIRECT_HOST)) return null;

        // Confirm with a clean request — should NOT redirect to evil host
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        if (baseline != null) {
            String baseLoc = baseline.header("location");
            if (baseLoc != null && baseLoc.contains(EVIL_REDIRECT_HOST)) return null; // pre-existing
        }

        return new ActiveScanResult(
            "OAuth 2.0: Open redirect_uri", SEV_CRITICAL,
            "The OAuth authorization server accepts arbitrary redirect_uri values " +
            "without validating against a pre-registered allowlist. An attacker can " +
            "craft an authorization URL with redirect_uri pointing to their server, " +
            "trick a victim into clicking it, and steal the authorization code from " +
            "the redirect. Combined with a PKCE or client_secret compromise, this " +
            "enables full account takeover. The injected URI '" + EVIL_REDIRECT_URI +
            "' was accepted and the server issued a redirect to it (Location: " + location + ").",
            "Injected redirect_uri: " + EVIL_REDIRECT_URI +
            " | Server Location response: " + location +
            " | Registered (original) redirect_uri: " + existing,
            OAUTH_REDIRECT_REMEDIATION, "CWE-601",
            ctx.url, "redirect_uri", EVIL_REDIRECT_URI,
            trunc(new String(probeReq, StandardCharsets.ISO_8859_1), 300),
            "HTTP " + resp.statusCode() + " Location: " + location,
            probeReq, resp.raw(), -1L
        );
    }

    // ── Check 2: Missing state parameter ─────────────────────────────────────

    private static ActiveScanResult checkMissingState(ProbeContext ctx,
                                                        Map<String, String> oauthParams) {
        // Only fire if this looks like an auth code or implicit flow request
        String responseType = oauthParams.getOrDefault("response_type", "");
        boolean isOAuthFlow = responseType.contains("code") || responseType.contains("token")
                || oauthParams.containsKey("client_id");
        if (!isOAuthFlow) return null;

        boolean hasState = oauthParams.containsKey("state");
        if (hasState) return null;

        return new ActiveScanResult(
            "OAuth 2.0: Missing state Parameter (CSRF on Auth Code Flow)", SEV_MEDIUM,
            "The OAuth authorization request does not include a 'state' parameter. " +
            "The state parameter is a CSRF token for the OAuth flow: it proves that " +
            "the authorization response was triggered by the user's own browser session. " +
            "Without it, an attacker can craft a valid authorization URL and trick a victim " +
            "into completing an OAuth login that binds the attacker's account to the victim's, " +
            "enabling account takeover (OAuth CSRF / cross-site request forgery on auth flow).",
            "URL: " + ctx.url + " | response_type: " + responseType +
            " | state parameter: absent | client_id: " + oauthParams.getOrDefault("client_id", "(not found)"),
            "PRIMARY FIX - state parameter:\n" +
            "Generate a cryptographically random state value per authorization request:\n" +
            "  state = base64url(random_bytes(32))\n" +
            "Store it in the user's session and validate on callback that the returned\n" +
            "state matches the stored value. Reject any callback where state is absent\n" +
            "or does not match.\n\n" +
            "MODERN ALTERNATIVE - PKCE (for public clients):\n" +
            "Public clients (SPAs, mobile) should use PKCE (RFC 7636) as the primary\n" +
            "binding mechanism. PKCE provides stronger protection than state alone\n" +
            "because it also prevents auth code interception.\n\n" +
            "Both state AND PKCE should be used together for defense in depth.",
            "CWE-352",
            ctx.url, "state", "(absent)",
            trunc(new String(ctx.originalRequest, StandardCharsets.ISO_8859_1), 300),
            "state parameter not found in authorization request",
            ctx.originalRequest, null, -1L
        );
    }

    // ── Check 3: Authorization code reuse ────────────────────────────────────

    private static ActiveScanResult checkCodeReuse(ProbeContext ctx,
                                                     HttpSender sender) {
        // Replay the token exchange request a second time
        HttpSender.Response first  = sender.send(ctx.service, ctx.originalRequest);
        HttpSender.Response second = sender.send(ctx.service, ctx.originalRequest);

        if (first == null || second == null) return null;

        // Both must be 2xx AND contain a token (not just "400 invalid_grant")
        boolean firstOk  = first.statusCode() >= 200 && first.statusCode() < 300
                           && TOKEN_RESPONSE_PATTERNS.stream().anyMatch(p -> p.matcher(first.body()).find());
        boolean secondOk = second.statusCode() >= 200 && second.statusCode() < 300
                           && TOKEN_RESPONSE_PATTERNS.stream().anyMatch(p -> p.matcher(second.body()).find());

        if (!firstOk || !secondOk) return null;

        return new ActiveScanResult(
            "OAuth 2.0: Authorization Code Reuse", SEV_HIGH,
            "The authorization server accepted the same authorization code twice. " +
            "RFC 6749 section 10.5 mandates that authorization codes must be " +
            "single-use: once exchanged for a token, the code must be immediately " +
            "invalidated. Accepting a replayed code allows any party who intercepts " +
            "the original token exchange (e.g. via a proxy or network tap) to obtain " +
            "their own access token using the stolen code.",
            "Two sequential token exchange requests using the same authorization code " +
            "both returned HTTP 200 with an access_token. " +
            "First response status: " + first.statusCode() +
            " | Second response status: " + second.statusCode(),
            "PRIMARY FIX - Single-use codes with immediate invalidation:\n" +
            "After a code is presented at the token endpoint, immediately mark it as\n" +
            "used in your authorization server database BEFORE issuing the token.\n" +
            "Use a database-level unique constraint or atomic compare-and-delete.\n\n" +
            "Detect replay attacks: if a code that has already been used is presented\n" +
            "again, revoke ALL tokens issued under that code (RFC 6749 Section 10.5).\n" +
            "This detects code theft - the attacker replays but the original client\n" +
            "also exchanges, so the second use reveals the theft.\n\n" +
            "Short code lifetime: authorization codes should expire within 60 seconds\n" +
            "(RFC 6749 recommends 10 minutes maximum; 60s is best practice).",
            "CWE-294",
            ctx.url, "code", "(replayed)",
            trunc(new String(ctx.originalRequest, StandardCharsets.ISO_8859_1), 300),
            "Second token exchange: HTTP " + second.statusCode() + " with access_token in body",
            ctx.originalRequest, second.raw(), -1L
        );
    }

    // ── Check 4: Token in URL ─────────────────────────────────────────────────

    private static ActiveScanResult checkTokenInUrl(ProbeContext ctx) {
        for (Pattern p : TOKEN_IN_URL_PATTERNS) {
            Matcher m = p.matcher(ctx.url);
            if (m.find()) {
                String tokenSnippet = trunc(m.group(1), 20) + "...";
                return new ActiveScanResult(
                    "OAuth 2.0: Token Exposed in URL", SEV_MEDIUM,
                    "An OAuth access token or ID token was found in the URL query string or " +
                    "fragment. Tokens in URLs are a serious security risk: they appear in " +
                    "browser history, server access logs, proxy logs, and are sent to " +
                    "third-party servers via the HTTP Referer header. Any system or person " +
                    "with access to these logs can steal the token and impersonate the user. " +
                    "This pattern is characteristic of the deprecated OAuth 2.0 implicit flow " +
                    "(response_type=token), which was removed from OAuth 2.1 for this reason.",
                    "URL: " + ctx.url + " | Token pattern: " + p.pattern() +
                    " | Token prefix: " + tokenSnippet,
                    "PRIMARY FIX - Use authorization code flow with PKCE:\n" +
                    "Replace implicit flow (response_type=token) with authorization code\n" +
                    "flow (response_type=code) + PKCE (RFC 7636). Tokens are returned only\n" +
                    "from the token endpoint (POST /token) in the response body, not in URLs.\n\n" +
                    "If you must return tokens to the client:\n" +
                    "- Use response_mode=form_post instead of response_mode=fragment\n" +
                    "- Set Referrer-Policy: no-referrer on token-receiving pages\n" +
                    "- Issue short-lived tokens and rotate frequently",
                    "CWE-598",
                    ctx.url, m.group(0).split("=")[0].replace("[?&#]", ""), tokenSnippet,
                    trunc(new String(ctx.originalRequest, StandardCharsets.ISO_8859_1), 300),
                    "Token found in URL: " + trunc(ctx.url, 200),
                    ctx.originalRequest, ctx.originalResponse, -1L
                );
            }
        }
        return null;
    }

    // ── Check 5: Implicit flow detection ─────────────────────────────────────

    private static ActiveScanResult checkImplicitFlow(ProbeContext ctx,
                                                        Map<String, String> oauthParams) {
        String responseType = oauthParams.getOrDefault("response_type", "");
        boolean isImplicit = responseType.equalsIgnoreCase("token")
                || responseType.equalsIgnoreCase("id_token")
                || responseType.equalsIgnoreCase("id_token token");
        if (!isImplicit) return null;

        return new ActiveScanResult(
            "OAuth 2.0: Implicit Flow in Use (Deprecated)", SEV_MEDIUM,
            "The OAuth authorization request uses response_type='" + responseType + "', " +
            "which is the implicit flow. The implicit flow returns access tokens directly " +
            "in the URL fragment (#access_token=...) rather than via the token endpoint. " +
            "This exposes tokens in browser history, referrer headers, and any JavaScript " +
            "running on the callback page. The implicit flow was deprecated in OAuth 2.0 " +
            "Security Best Current Practice (RFC 9700) and removed from OAuth 2.1. " +
            "Modern browsers support the more secure authorization code + PKCE flow.",
            "response_type: " + responseType + " | URL: " + ctx.url,
            "PRIMARY FIX - Migrate to Authorization Code + PKCE:\n" +
            "Replace response_type=token with response_type=code and add:\n" +
            "  code_challenge=<base64url(SHA256(random_verifier))>\n" +
            "  code_challenge_method=S256\n\n" +
            "On the callback, exchange the code at the token endpoint (POST /token)\n" +
            "with the code_verifier. The access token is returned in the response body,\n" +
            "never in the URL.\n\n" +
            "Libraries that implement PKCE automatically:\n" +
            "  JavaScript: oauth4webapi, oidc-client-ts, Auth0 SPA SDK\n" +
            "  Mobile: AppAuth (iOS/Android), Microsoft MSAL\n" +
            "  Python: authlib, requests-oauthlib with PKCE extension",
            "CWE-287",
            ctx.url, "response_type", responseType,
            trunc(new String(ctx.originalRequest, StandardCharsets.ISO_8859_1), 300),
            "Implicit flow detected: response_type=" + responseType,
            ctx.originalRequest, null, -1L
        );
    }

    // ── Check 6: PKCE absence ─────────────────────────────────────────────────

    private static ActiveScanResult checkPkceAbsence(ProbeContext ctx,
                                                       Map<String, String> oauthParams) {
        String responseType = oauthParams.getOrDefault("response_type", "");
        if (!responseType.contains("code")) return null;  // only for auth code flow

        boolean hasPkce    = oauthParams.containsKey("code_challenge");
        boolean hasSecret  = ctx.reqHeaders.containsKey("authorization");  // confidential client
        // PKCE is mandatory for public clients; confidential clients are lower priority
        if (hasPkce || hasSecret) return null;

        // Heuristic: public client indicators
        boolean looksPublic = oauthParams.containsKey("client_id")
                && !ctx.reqHeaders.containsKey("authorization");

        if (!looksPublic) return null;

        return new ActiveScanResult(
            "OAuth 2.0: PKCE Not Used on Public Client (Auth Code Flow)", SEV_MEDIUM,
            "The OAuth authorization request uses response_type=code (authorization code " +
            "flow) without a code_challenge parameter (PKCE). For public clients - " +
            "single-page applications and mobile apps that cannot keep a client_secret - " +
            "PKCE (RFC 7636) is mandatory. Without PKCE, authorization codes intercepted " +
            "in transit (via open redirect, browser extension, or URI scheme hijacking on " +
            "mobile) can be exchanged for tokens by any attacker. OAuth 2.1 and all modern " +
            "authorization server guidance (RFC 9700) require PKCE for all clients.",
            "response_type: " + responseType +
            " | code_challenge: absent | client_id: " + oauthParams.getOrDefault("client_id", "(unknown)"),
            "PRIMARY FIX - Add PKCE to every authorization request:\n" +
            "1. Generate a random code_verifier (43-128 random characters, URL-safe Base64):\n" +
            "   code_verifier = base64url(random_bytes(32))\n\n" +
            "2. Compute the challenge:\n" +
            "   code_challenge = base64url(SHA256(ASCII(code_verifier)))\n\n" +
            "3. Add to the authorization request:\n" +
            "   ?code_challenge=<value>&code_challenge_method=S256\n\n" +
            "4. Include code_verifier in the token exchange:\n" +
            "   POST /token ... code_verifier=<value>\n\n" +
            "The authorization server verifies SHA256(code_verifier) == code_challenge,\n" +
            "ensuring only the original requester can exchange the code.",
            "CWE-287",
            ctx.url, "code_challenge", "(absent)",
            trunc(new String(ctx.originalRequest, StandardCharsets.ISO_8859_1), 300),
            "Auth code flow without code_challenge at: " + ctx.url,
            ctx.originalRequest, null, -1L
        );
    }

    // ── Check 7: redirect_uri matching bypass ─────────────────────────────────

    private static ActiveScanResult checkRedirectUriBypass(ProbeContext ctx,
                                                             RequestBuilder rb,
                                                             HttpSender sender,
                                                             Map<String, String> oauthParams) {
        String registered = oauthParams.get("redirect_uri");
        if (registered == null || registered.isBlank()) return null;

        // Don't re-test if we already confirmed full open redirect in Check 1
        // (Check 7 targets servers that do basic host-match but miss bypass variants)

        // Build bypass variants based on the registered URI
        List<String[]> variants = buildBypassVariants(registered);

        for (String[] variant : variants) {
            String bypassUri = variant[0];
            String technique = variant[1];

            if (bypassUri.equals(registered)) continue;  // skip no-op

            byte[] probeReq = rb.buildProbeRequest(ctx, "redirect_uri", bypassUri);
            if (probeReq == null) continue;

            HttpSender.Response resp = sender.send(ctx.service, probeReq);
            if (resp == null) continue;

            // Detection: 3xx redirect to a location we control (not the registered one)
            String location = resp.header("location");
            if (location == null) continue;

            // The Location must contain something from our injected bypass (not the clean URI)
            boolean redirectedToBypass = !locationMatchesRegistered(location, registered)
                    && couldBeOurBypass(location, bypassUri);
            if (!redirectedToBypass) continue;

            return new ActiveScanResult(
                "OAuth 2.0: redirect_uri Matching Bypass (" + technique + ")", SEV_HIGH,
                "The OAuth authorization server validates redirect_uri against the registered " +
                "value, but the validation can be bypassed using '" + technique + "'. " +
                "The injected URI '" + bypassUri + "' was accepted and the server redirected " +
                "to Location: '" + location + "'. This allows an attacker to steal the " +
                "authorization code from the redirect by crafting a malicious authorization " +
                "URL pointing to the bypass URI.",
                "Registered redirect_uri: " + registered +
                " | Bypass technique: " + technique +
                " | Injected URI: " + bypassUri +
                " | Server Location: " + location,
                OAUTH_REDIRECT_REMEDIATION, "CWE-601",
                ctx.url, "redirect_uri", bypassUri,
                trunc(new String(probeReq, StandardCharsets.ISO_8859_1), 300),
                "HTTP " + resp.statusCode() + " Location: " + location,
                probeReq, resp.raw(), -1L
            );
        }
        return null;
    }

    /**
     * Builds redirect_uri bypass variants. Each entry is [bypassUri, techniqueName].
     * Targets misconfigured prefix-match, suffix-match, and contains-match validators.
     */
    private static List<String[]> buildBypassVariants(String registered) {
        List<String[]> variants = new ArrayList<>();
        try {
            java.net.URL u = new java.net.URL(registered);
            String scheme = u.getProtocol();
            String host   = u.getHost();
            int    port   = u.getPort();
            String path   = u.getPath().isEmpty() ? "/" : u.getPath();
            String portStr = port > 0 ? ":" + port : "";
            String base   = scheme + "://" + host + portStr;

            // A. Path traversal bypass: appends /../evil to registered path
            variants.add(new String[]{base + path + "/../evil", "path traversal"});

            // B. Open subdomain: evil.registered-host.com (for suffix-match validators)
            variants.add(new String[]{scheme + "://evil." + host + portStr + path, "subdomain prefix"});

            // C. Registered host in query: ?redirect_uri=evil.com registers the host elsewhere
            // Not a redirect_uri bypass per se, but tests parsers that only check "contains host"
            variants.add(new String[]{"https://evil.burpmax.local?host=" + host + path, "host-in-query"});

            // D. @ bypass: user:pass@evil.com where the host before @ matches
            // Tests parsers that extract host as everything before the last @
            variants.add(new String[]{scheme + "://" + host + "@evil.burpmax.local" + path, "@ bypass"});

            // E. Null byte: registered%00evil.com (for C-string based validators)
            variants.add(new String[]{base + path + "%00evil.burpmax.local", "null-byte suffix"});

        } catch (Exception ignored) {}
        return variants;
    }

    /** Returns true if the location header still points to the registered redirect_uri host. */
    private static boolean locationMatchesRegistered(String location, String registered) {
        try {
            String regHost = new java.net.URL(registered).getHost().toLowerCase();
            String locHost = new java.net.URL(location).getHost().toLowerCase();
            return locHost.equals(regHost) || locHost.endsWith("." + regHost);
        } catch (Exception e) {
            return location.contains(registered);
        }
    }

    /** Returns true if the location could be the bypass we injected (contains our marker domains). */
    private static boolean couldBeOurBypass(String location, String injected) {
        return location.contains("evil.burpmax.local") || location.contains("evil.")
                || location.contains("../evil") || location.contains("%00");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean isOAuthEndpoint(String url) {
        return OAUTH_ENDPOINT_PATTERNS.stream().anyMatch(p -> p.matcher(url).matches());
    }

    private static boolean isAuthorizationEndpoint(String url) {
        String lower = url.toLowerCase();
        return lower.contains("/authorize") || lower.contains("/auth")
                || lower.contains("/oauth/authorize") || lower.contains("/connect/authorize");
    }

    private static boolean isTokenEndpoint(String url) {
        String lower = url.toLowerCase();
        return lower.contains("/token") && !lower.contains("/tokeninfo");
    }

    /**
     * Extracts OAuth-relevant parameters from both query string and body,
     * URL-decoding values so checks don't need to handle encoding variants.
     */
    private static Map<String, String> extractOAuthParams(ProbeContext ctx) {
        Map<String, String> params = new LinkedHashMap<>();
        // From ProbeContext parameter maps (already parsed by ActiveScanner)
        for (String name : ctx.allParamNames()) {
            params.put(name.toLowerCase(), ctx.paramValue(name));
        }
        // Also scan URL directly for fragment params (# is not in query string)
        if (ctx.url.contains("#")) {
            String fragment = ctx.url.substring(ctx.url.indexOf('#') + 1);
            for (String pair : fragment.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2) {
                    try {
                        params.put(kv[0].toLowerCase(),
                                URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
                    } catch (Exception ignored) {}
                }
            }
        }
        return params;
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    // ── Remediation text ──────────────────────────────────────────────────────

    private static final String OAUTH_REDIRECT_REMEDIATION =
        "PRIMARY FIX - Strict redirect_uri validation:\n" +
        "Register exact redirect URIs for each client. Validate using exact string\n" +
        "equality, not prefix/suffix matching or regex:\n\n" +
        "  WRONG: location.startsWith('https://myapp.com')  // bypassed by myapp.com.evil.com\n" +
        "  WRONG: location.contains('myapp.com')            // bypassed by ?host=myapp.com\n" +
        "  CORRECT: registeredUris.contains(location)       // exact match only\n\n" +
        "OAuth 2.0 RFC 6749 Section 3.1.2.2 requires the server to compare the\n" +
        "redirect_uri as a complete string. Path traversal, subdomain, and @ variants\n" +
        "all exploit validators that do substring or prefix matching.\n\n" +
        "AUTHORIZATION SERVER SETTINGS:\n" +
        "- Keycloak: set 'Valid Redirect URIs' to exact URIs (avoid trailing *)\n" +
        "- Auth0: list exact callback URLs in Application Settings\n" +
        "- Okta: use exact match in 'Login redirect URIs'\n" +
        "- Spring Security: configure ExactMatchingRedirectUriResolver\n\n" +
        "SECONDARY CONTROLS:\n" +
        "- Use PKCE (code_challenge) so intercepted codes are unusable without verifier\n" +
        "- Bind authorization codes to the client IP where possible\n" +
        "- Implement short code lifetimes (60 seconds) to limit interception window";
}
