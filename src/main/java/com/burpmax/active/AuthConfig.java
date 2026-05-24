package com.burpmax.active;

/**
 * Immutable configuration for authenticated scanning.
 *
 * Supports two auth modes:
 *
 *   STATIC  - a pre-supplied token/cookie is injected verbatim into every probe
 *             request. No login sequence is performed. The tester captures a
 *             valid session from Burp, pastes the value, and scanning begins
 *             immediately. Simplest and most reliable approach when the session
 *             is long-lived.
 *
 *   LOGIN   - a login HTTP request is replayed to obtain a fresh session token
 *             before scanning starts. The tester supplies the full login request
 *             bytes (captured from Burp) and a regex that matches the token in
 *             the login response. On 401 from any probe or when the
 *             SessionHealthMonitor detects an expired session, the login is
 *             replayed automatically and all subsequent probes use the new token.
 *
 * Health check:
 *   An optional URL is probed periodically (and on every 401 received from a
 *   probe) to confirm the session is still live. A healthy response must match
 *   healthOkPattern (if set) and must NOT return 401/403. When the health check
 *   fails, AuthManager triggers a re-auth (login mode) or raises a warning flag
 *   (static mode, where re-auth is impossible).
 */
public final class AuthConfig {

    public enum Mode { STATIC, LOGIN }

    // ── Common ──────────────────────────────────────────────────────────────

    /** Which auth strategy is active. */
    public final Mode mode;

    /**
     * Header to inject when mode == STATIC, or the header whose value the
     * login-mode extractor populates. Canonical form ("Authorization",
     * "Cookie", or any custom header). Case-preserving; sent as-is.
     */
    public final String headerName;

    /**
     * URL that proves the session is alive. If null/blank, health checks are
     * skipped (auth is assumed valid until a 401 is received from a probe).
     */
    public final String healthUrl;

    /**
     * Regex that must match in the health-check response body/headers for the
     * session to be considered live. If null/blank, only the HTTP status code
     * is checked (non-401, non-403 == healthy).
     */
    public final String healthOkPattern;

    // ── STATIC mode ─────────────────────────────────────────────────────────

    /**
     * Token/cookie value to inject as-is into the headerName header.
     * Used in STATIC mode. Ignored in LOGIN mode.
     * Example for Authorization: "Bearer eyJhb..."
     * Example for Cookie: "session=abc123"
     */
    public final String staticTokenValue;

    // ── LOGIN mode ───────────────────────────────────────────────────────────

    /**
     * Full raw HTTP request bytes for the login endpoint.
     * Used in LOGIN mode. The scanner replays these bytes verbatim when it
     * needs a fresh session. The request must already be complete (correct
     * host, body, Content-Type, Content-Length).
     */
    public final byte[] loginRequestBytes;

    /**
     * Regex applied to the login response body to extract the token value.
     * The first capture group is used. Example patterns:
     *   "\"token\"\\s*:\\s*\"([^\"]+)\""     -- JSON bearer
     *   "Set-Cookie: session=([^;]+)"         -- cookie extraction
     *   "\"access_token\":\\s*\"([^\"]+)\""  -- OAuth2
     */
    public final String loginTokenRegex;

    /**
     * Host/port/protocol for the login request.
     * If null, extracted from the Host header in loginRequestBytes.
     */
    public final String loginHost;
    public final int    loginPort;
    public final String loginProtocol;

    // ── Constructor (LOGIN mode) ──────────────────────────────────────────────

    public static AuthConfig loginMode(String headerName,
                                       byte[] loginRequestBytes,
                                       String loginTokenRegex,
                                       String loginHost, int loginPort, String loginProtocol,
                                       String healthUrl, String healthOkPattern) {
        return new AuthConfig(Mode.LOGIN, headerName, null,
                loginRequestBytes, loginTokenRegex,
                loginHost, loginPort, loginProtocol,
                healthUrl, healthOkPattern);
    }

    // ── Constructor (STATIC mode) ─────────────────────────────────────────────

    public static AuthConfig staticMode(String headerName,
                                        String tokenValue,
                                        String healthUrl,
                                        String healthOkPattern) {
        return new AuthConfig(Mode.STATIC, headerName, tokenValue,
                null, null, null, 0, null,
                healthUrl, healthOkPattern);
    }

    private AuthConfig(Mode mode, String headerName, String staticTokenValue,
                       byte[] loginRequestBytes, String loginTokenRegex,
                       String loginHost, int loginPort, String loginProtocol,
                       String healthUrl, String healthOkPattern) {
        this.mode               = mode;
        this.headerName         = headerName;
        this.staticTokenValue   = staticTokenValue;
        // Defensive copy - caller's array mutation must not corrupt the stored request.
        this.loginRequestBytes  = loginRequestBytes != null
                                    ? java.util.Arrays.copyOf(loginRequestBytes, loginRequestBytes.length)
                                    : null;
        this.loginTokenRegex    = loginTokenRegex;
        this.loginHost          = loginHost;
        this.loginPort          = loginPort;
        this.loginProtocol      = loginProtocol;
        this.healthUrl          = (healthUrl != null && !healthUrl.isBlank()) ? healthUrl.trim() : null;
        this.healthOkPattern    = (healthOkPattern != null && !healthOkPattern.isBlank())
                                    ? healthOkPattern.trim() : null;
    }

    public boolean isStaticMode() { return mode == Mode.STATIC; }
    public boolean isLoginMode()  { return mode == Mode.LOGIN; }

    @Override
    public String toString() {
        return "AuthConfig[mode=" + mode
                + ", header=" + headerName
                + ", healthUrl=" + healthUrl + "]";
    }
}
