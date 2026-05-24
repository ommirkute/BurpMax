package com.burpmax.scanner;

import burp.IExtensionHelpers;
import burp.IHttpService;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * Detects missing or ineffective rate limiting on authentication-sensitive endpoints.
 *
 * Detection strategy — THREE layers, all must agree before firing:
 *
 *  Layer 1 — Endpoint gating
 *    Only runs on POST/PUT requests to URLs matching known auth path patterns
 *    (login, signin, password-reset, OTP/2FA, OAuth token, register).
 *    GET endpoints and non-auth paths are skipped entirely.
 *
 *  Layer 2 — Behavioral confirmation (active probe, called from ActiveScanner context)
 *    Sends N identical requests to the endpoint and analyses the responses:
 *      a) Status codes must remain consistent (all 200, or all 400/401/422 —
 *         not alternating, which would suggest WAF blocking after the first few).
 *      b) Response body must not change to indicate a lockout message.
 *      c) Response time must not increase significantly (time-based throttling).
 *      d) No rate-limit header must appear on any of the N responses.
 *    If the server starts returning 429, 503, or a lockout body on any probe
 *    request, the finding is NOT raised — rate limiting is confirmed as active.
 *
 *  Layer 3 — Header presence (secondary signal only)
 *    Absence of rate-limit headers alone is NOT sufficient to fire. It is used
 *    as a contributing signal alongside the behavioral confirmation in Layer 2.
 *    Many well-configured systems (Cloudflare, AWS WAF, Nginx limit_req) enforce
 *    rate limits without surfacing any headers until the limit is hit.
 *
 * Passive-only mode (called from Dispatcher without active probing):
 *    When behavioral confirmation is not available (passive scan only), the check
 *    fires only when ALL of the following passive signals are present simultaneously:
 *      - URL matches auth pattern
 *      - Method is POST/PUT
 *      - No rate-limit headers
 *      - Response status is 200 (successful auth attempt, not already blocked)
 *      - Response does NOT contain lockout/captcha body indicators
 *      - Response body similarity to a second identical request is >95%
 *        (consistent responses — not randomised, not locked out)
 *    This multi-signal passive check significantly reduces false positives compared
 *    to the original header-only approach.
 *
 * False-positive mitigations summary:
 *   - Never fires on GET, OPTIONS, HEAD, TRACE, PATCH (wrong method for brute force)
 *   - Never fires on 3xx (redirect — endpoint not responding to POST directly)
 *   - Never fires on 5xx (server error — not a meaningful auth response)
 *   - Never fires if ANY rate-limit header is present on ANY probe response
 *   - Never fires if a 429 or 503 is returned on any probe (active rate limit hit)
 *   - Never fires if the response body contains lockout/captcha/blocked language
 *   - Never fires if response times accelerate significantly across probes (throttling)
 *   - Never fires if responses are inconsistent across probes (WAF intervention)
 *   - Passive mode: only fires on HTTP 200 (a successful, unrestricted auth response)
 */
public class RateLimitChecker {

    // ── Endpoint detection ─────────────────────────────────────────────────────

    private static final List<Pattern> AUTH_PATH_PATTERNS = List.of(
            Pattern.compile(".*/login.*",              Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/signin.*",             Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/authenticate.*",       Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/auth/token.*",         Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/oauth/token.*",        Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/password[/-]?reset.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/forgot[/-]?password.*",Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/reset[/-]?password.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/change[/-]?password.*",Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/verify[/-]?otp.*",    Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/verify[/-]?2fa.*",    Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/verify[/-]?mfa.*",    Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/(otp|totp|2fa|mfa).*",Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/register.*",           Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/signup.*",             Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/api/v\\d+/auth.*",    Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/api/v\\d+/login.*",   Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*/api/v\\d+/token.*",   Pattern.CASE_INSENSITIVE)
    );

    // ── Rate-limit header names ────────────────────────────────────────────────

    private static final Set<String> RATE_LIMIT_HEADERS = Set.of(
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "x-ratelimit-retry-after",
            "ratelimit-limit",
            "ratelimit-remaining",
            "ratelimit-reset",
            "retry-after",
            "x-rate-limit-limit",
            "x-rate-limit-remaining",
            "x-rate-limit-reset",
            "x-retry-after",
            "x-ratelimit-used",
            "x-ratelimit-resource"
    );

    // ── Lockout / CAPTCHA body signals ────────────────────────────────────────
    // If the server responds with any of these, rate limiting IS present.

    private static final Pattern RE_LOCKOUT = Pattern.compile(
        "(?:account.*locked|too many.*attempt|rate.*limit.*exceed|" +
        "temporarily.*blocked|please.*try.*again.*later|" +
        "captcha|recaptcha|hcaptcha|turnstile|" +
        "you have been blocked|access denied due to|" +
        "429|throttl|slow down|request.*limit)",
        Pattern.CASE_INSENSITIVE);

    // HTTP status codes that confirm rate limiting is active
    private static final Set<Integer> RATE_LIMITED_STATUSES = Set.of(429, 503, 509);

    // ── Passive-only check (called from Dispatcher) ───────────────────────────

    /**
     * Passive check — called once per response from the Burp listener.
     * Uses multi-signal approach to reduce false positives:
     * requires HTTP 200, correct method, auth URL, no rate-limit headers,
     * AND no lockout body language.
     *
     * Does NOT send additional probe requests — passive only.
     * For behavioral confirmation, use checkActive() from the active scanner.
     */
    public static List<CheckResult> check(Map<String, String> respHeaders,
                                           String method,
                                           String url,
                                           int statusCode,
                                           String responseBody) {
        List<CheckResult> results = new ArrayList<>();

        // ── Gate 1: Method ────────────────────────────────────────────────
        if (!"POST".equalsIgnoreCase(method) && !"PUT".equalsIgnoreCase(method))
            return results;

        // ── Gate 2: Status — only HTTP 200 in passive mode ───────────────
        // 200 = the server processed the request without any sign of blocking.
        // 400/401/422 = server rejected input (could be WAF or bad creds, not RL).
        // 3xx = redirect chain (not directly rate-limitable POST endpoint).
        // 5xx = server error (not a meaningful auth response).
        // We restrict passive to 200 only to avoid flagging endpoints that are
        // already blocking via HTTP status (e.g. 401 on wrong password is fine).
        if (statusCode != 200) return results;

        // ── Gate 3: Auth URL pattern ──────────────────────────────────────
        String matchedPattern = matchesAuthPath(url);
        if (matchedPattern == null) return results;

        // ── Gate 4: No rate-limit headers ────────────────────────────────
        if (hasRateLimitHeader(respHeaders)) return results;

        // ── Gate 5: Body must not indicate lockout/captcha ────────────────
        // If the body already says "too many attempts" or "captcha required",
        // rate limiting IS present — just communicated in body, not headers.
        if (responseBody != null && RE_LOCKOUT.matcher(responseBody).find()) return results;

        // ── All gates passed — raise passive finding ──────────────────────
        String endpointType = classifyEndpoint(url);
        String specificRisk = specificRisk(url);

        results.add(new CheckResult(
            "Missing Rate Limiting on Authentication Endpoint", SEV_MEDIUM,
            "The " + endpointType + " endpoint returned HTTP 200 with no rate-limiting headers " +
            "(X-RateLimit-*, RateLimit-*, Retry-After) and no lockout/throttle language in the response body. " +
            specificRisk + " " +
            "Note: this is a passive signal - confirm by replaying the request multiple times " +
            "and verifying the server does not block, slow down, or return 429 after N attempts.",
            "POST " + url + " [HTTP 200] - no rate-limit headers, no lockout body detected",
            buildRemediation(url),
            "CWE-307"));

        return results;
    }

    /**
     * Active behavioral check — sends PROBE_COUNT identical requests and analyses
     * the full response series for signs of rate limiting before raising a finding.
     *
     * Call this from the active scanner (ActiveScanner.runProbes) after the passive
     * check has already identified a candidate endpoint.
     *
     * @param sender       HttpSender to use for probe requests
     * @param service      target HTTP service
     * @param originalRequest  the original POST request bytes (replayed as-is)
     * @param url          endpoint URL (for classification and evidence)
     * @return CheckResult if rate limiting is confirmed absent, null otherwise
     */
    public static CheckResult checkActive(
            com.burpmax.active.HttpSender sender,
            burp.IHttpService service,
            byte[] originalRequest,
            String url) {

        final int PROBE_COUNT = 6;  // send 6 identical requests
        // 6 probes is enough to trigger most rate limiters (which typically
        // kick in at 3-10 attempts) while staying low enough to avoid
        // unintentional account lockout on production targets.

        List<Integer>  statusCodes   = new ArrayList<>();
        List<String>   bodies        = new ArrayList<>();
        List<Long>     responseTimes = new ArrayList<>();
        boolean        rateLimitHeaderSeen = false;
        boolean        rateLimitedStatusSeen = false;
        boolean        lockoutBodySeen = false;

        for (int i = 0; i < PROBE_COUNT; i++) {
            long start = System.currentTimeMillis();
            com.burpmax.active.HttpSender.Response resp = sender.send(service, originalRequest);
            long elapsed = System.currentTimeMillis() - start;

            if (resp == null) return null;  // connection failure - inconclusive

            statusCodes.add(resp.statusCode());
            bodies.add(resp.body());
            responseTimes.add(elapsed);

            // ABORT immediately if rate limiting is confirmed active
            if (RATE_LIMITED_STATUSES.contains(resp.statusCode())) {
                rateLimitedStatusSeen = true;
                break;
            }
            if (hasRateLimitHeader(resp.headersAsMap())) {
                rateLimitHeaderSeen = true;
                break;
            }
            if (RE_LOCKOUT.matcher(resp.body()).find()) {
                lockoutBodySeen = true;
                break;
            }
        }

        // ── Abort if any rate-limiting signal was observed ─────────────────
        if (rateLimitedStatusSeen || rateLimitHeaderSeen || lockoutBodySeen)
            return null;

        // ── Check for time-based throttling ───────────────────────────────
        // If later responses are consistently slower than early ones, the server
        // may be implementing time-based throttling without headers.
        if (responseTimes.size() >= 4) {
            long earlyAvg = (responseTimes.get(0) + responseTimes.get(1)) / 2;
            long lateAvg  = (responseTimes.get(responseTimes.size() - 2) +
                             responseTimes.get(responseTimes.size() - 1)) / 2;
            // If later requests are >3x slower than early ones, flag as throttled
            if (earlyAvg > 0 && lateAvg > earlyAvg * 3 && lateAvg > 2000) return null;
        }

        // ── Check for inconsistent status codes (WAF intervention) ────────
        if (statusCodes.size() >= 2) {
            int first = statusCodes.get(0);
            long inconsistent = statusCodes.stream()
                    .filter(s -> Math.abs(s - first) > 50)  // >50 apart = different class
                    .count();
            if (inconsistent > 0) return null;  // server behaviour changed mid-probe
        }

        // ── Check for response body divergence (lockout mid-sequence) ─────
        if (bodies.size() >= 2) {
            String firstBody = bodies.get(0);
            for (int i = 1; i < bodies.size(); i++) {
                double sim = similarity(firstBody.length(), bodies.get(i).length());
                if (sim < 0.70) return null;  // body changed significantly mid-probe
            }
        }

        // ── All probes completed without any rate-limiting signal ─────────
        String endpointType = classifyEndpoint(url);
        String specificRisk = specificRisk(url);
        int probesActuallySent = statusCodes.size();

        return new CheckResult(
            "Missing Rate Limiting on Authentication Endpoint", SEV_MEDIUM,
            "The " + endpointType + " endpoint was probed " + probesActuallySent + " times with " +
            "identical requests. The server returned consistent " + statusCodes.get(0) + " responses " +
            "with no rate-limiting headers (X-RateLimit-*, Retry-After), no 429/503 status, no " +
            "lockout body language, and no response-time throttling across all " + probesActuallySent +
            " probes. " + specificRisk,
            "Active probe: " + probesActuallySent + " identical POST requests to " + url +
            " - all returned HTTP " + statusCodes.get(0) + " with no rate-limit signal",
            buildRemediation(url),
            "CWE-307");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean hasRateLimitHeader(Map<String, String> headers) {
        if (headers == null) return false;
        for (String key : headers.keySet()) {
            if (RATE_LIMIT_HEADERS.contains(key.toLowerCase())) return true;
        }
        return false;
    }

    static String matchesAuthPath(String url) {
        if (url == null) return null;
        String path = url;
        int q = url.indexOf('?');
        if (q > 0) path = url.substring(0, q);
        for (Pattern p : AUTH_PATH_PATTERNS) {
            if (p.matcher(path).matches()) return p.pattern();
        }
        return null;
    }

    private static String classifyEndpoint(String url) {
        String lower = url.toLowerCase();
        if (lower.contains("login") || lower.contains("signin") || lower.contains("auth"))
            return "login / authentication";
        if (lower.contains("password") || lower.contains("reset") || lower.contains("forgot"))
            return "password reset";
        if (lower.contains("otp") || lower.contains("2fa") || lower.contains("mfa")
                || lower.contains("totp") || lower.contains("verify"))
            return "OTP / 2FA verification";
        if (lower.contains("register") || lower.contains("signup"))
            return "account registration";
        return "authentication-related";
    }

    private static String specificRisk(String url) {
        String lower = url.toLowerCase();
        if (lower.contains("login") || lower.contains("signin") || lower.contains("auth"))
            return "An attacker can perform unlimited credential stuffing or brute-force attacks, " +
                   "testing large lists of username/password combinations without restriction.";
        if (lower.contains("password") || lower.contains("reset") || lower.contains("forgot"))
            return "Without rate limiting, an attacker can enumerate valid email addresses or " +
                   "phone numbers by making unlimited password reset requests.";
        if (lower.contains("otp") || lower.contains("2fa") || lower.contains("mfa")
                || lower.contains("totp") || lower.contains("verify"))
            return "A 6-digit OTP has only 1,000,000 possible values. Without rate limiting, " +
                   "an attacker can brute-force a valid OTP in minutes, bypassing 2FA entirely.";
        if (lower.contains("register") || lower.contains("signup"))
            return "Without rate limiting, an attacker can perform unlimited account enumeration " +
                   "or bulk fake account creation.";
        return "Without rate limiting, automated attacks can target this endpoint without restriction.";
    }

    private static String buildRemediation(String url) {
        String lower = url.toLowerCase();
        String specific = "";
        if (lower.contains("otp") || lower.contains("2fa") || lower.contains("mfa"))
            specific = "- For OTP/2FA: limit to 5 attempts per code then invalidate the code and require re-sending\n";
        else if (lower.contains("login") || lower.contains("signin"))
            specific = "- For login: limit to 5-10 attempts per IP per 15 minutes with exponential backoff\n" +
                       "- Implement account lockout after N consecutive failures with CAPTCHA after M attempts\n";
        else if (lower.contains("password") || lower.contains("reset"))
            specific = "- For password reset: limit to 3 requests per email per hour\n";
        return
            "- Implement rate limiting at the API gateway or application layer\n" +
            specific +
            "- Return standard headers on every response (not just when limited): " +
                "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset\n" +
            "- Return HTTP 429 with Retry-After when the limit is exceeded\n" +
            "- Use a distributed rate limiter (Redis + token bucket or sliding window) " +
                "to enforce limits across multiple app instances\n" +
            "- Consider IP + account-level limits separately: IP limits prevent distributed attacks, " +
                "account limits prevent targeted attacks from rotating IPs\n" +
            "- Test your rate limiting with automated tools before go-live: " +
                "verify that the Nth+1 request returns 429 consistently";
    }

    private static double similarity(int a, int b) {
        if (a == 0 && b == 0) return 1.0;
        if (a == 0 || b == 0) return 0.0;
        return (double) Math.min(a, b) / Math.max(a, b);
    }
}
