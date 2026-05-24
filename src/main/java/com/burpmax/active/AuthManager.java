package com.burpmax.active;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Injects authentication credentials into every probe request and
 * automatically refreshes the session when it expires.
 *
 * Thread safety:
 *   Multiple probe threads call applyAuth() concurrently. The current token
 *   is stored in an AtomicReference so reads require no locking. The login
 *   replay is guarded by a ReentrantLock (loginLock) so only one thread
 *   performs re-auth while all others wait for the new token.
 *
 * Lifecycle:
 *   1. Caller constructs AuthManager with an AuthConfig.
 *   2. Caller calls initialise() once before the scan starts.
 *      - LOGIN mode: performs the login request and extracts the token.
 *      - STATIC mode: stores the configured token immediately.
 *   3. Before every probe send, caller calls applyAuth(requestBytes) to
 *      get a copy of the request with the auth header injected.
 *   4. After receiving a 401 from any probe, caller calls notifyUnauthorized()
 *      which triggers a re-auth (LOGIN mode) or logs a warning (STATIC mode).
 *   5. SessionHealthMonitor calls notifyUnauthorized() on its own schedule
 *      when the health check URL indicates session expiry.
 */
public class AuthManager {

    private final AuthConfig              config;
    private final IBurpExtenderCallbacks  callbacks;
    private final IExtensionHelpers       helpers;
    private final Consumer<String>        log;

    /** Current live token value (header value). Null means not yet initialised. */
    private final AtomicReference<String> currentToken   = new AtomicReference<>(null);
    /** True once the first initialise() succeeds. */
    private final AtomicBoolean           initialised    = new AtomicBoolean(false);
    /** Guards login replays so only one thread re-authenticates at a time. */
    private final ReentrantLock           loginLock      = new ReentrantLock();
    /** Set true after a static-mode 401 to suppress repeated warnings. */
    private volatile boolean              staticWarned   = false;

    // Compiled once from config.loginTokenRegex
    private Pattern loginTokenPattern;

    public AuthManager(AuthConfig config,
                       IBurpExtenderCallbacks callbacks,
                       IExtensionHelpers helpers,
                       Consumer<String> log) {
        this.config    = config;
        this.callbacks = callbacks;
        this.helpers   = helpers;
        this.log       = log != null ? log : msg -> {};
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    /**
     * Initialise the session. Must be called once before scanning starts.
     *
     * @return true if the session is ready, false if initialisation failed
     *         (scan should be aborted or run unauthenticated with a warning).
     */
    public boolean initialise() {
        if (config.isStaticMode()) {
            currentToken.set(config.staticTokenValue);
            initialised.set(true);
            log.accept("[Auth] Static token configured (header: " + config.headerName + ").");
            return true;
        }

        // LOGIN mode - compile regex once
        try {
            loginTokenPattern = Pattern.compile(config.loginTokenRegex,
                    Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            log.accept("[Auth] Invalid loginTokenRegex: " + e.getMessage());
            return false;
        }

        return performLogin("initial login");
    }

    /**
     * Returns true if auth is ready to use (initialise() succeeded).
     */
    public boolean isReady() { return initialised.get(); }

    // ── Core API ───────────────────────────────────────────────────────────────

    /**
     * Returns a copy of the request bytes with the auth header injected.
     * If not yet initialised, returns the original request unchanged.
     *
     * This is called on probe threads - must be fast. Token read is lock-free.
     */
    public byte[] applyAuth(byte[] requestBytes) {
        String token = currentToken.get();
        if (token == null || token.isBlank()) return requestBytes;
        return injectHeader(requestBytes, config.headerName, token);
    }

    /**
     * Called when any probe receives an HTTP 401 or 403 response,
     * or when the health monitor detects an expired session.
     *
     * In LOGIN mode: triggers a re-auth (serialised via loginLock).
     * In STATIC mode: logs a one-time warning; cannot refresh automatically.
     */
    public void notifyUnauthorized() {
        if (config.isStaticMode()) {
            if (!staticWarned) {
                staticWarned = true;
                log.accept("[Auth] WARNING: received 401/403 with static token. "
                        + "The session may have expired. Update the token and restart the scan.");
            }
            return;
        }

        // LOGIN mode - acquire lock so only one thread re-auths
        String tokenBefore = currentToken.get();
        if (loginLock.tryLock()) {
            try {
                // Double-check: another thread may have refreshed while we were scheduling.
                // If the token changed since we read it above, a concurrent re-auth already
                // succeeded - skip the replay to avoid unnecessary login requests.
                if (tokenBefore != null && tokenBefore.equals(currentToken.get())) {
                    // Token unchanged - this thread owns the re-auth
                    performLogin("re-auth on 401");
                }
            } finally {
                loginLock.unlock();
            }
        } else {
            // Another thread holds the lock and is already re-authing.
            // Wait for it to finish (getting the fresh token) then continue.
            // Use lockInterruptibly so scan cancellation can propagate cleanly.
            try {
                loginLock.lockInterruptibly();
                loginLock.unlock();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Returns the current token value (may be null if not yet initialised). */
    public String getCurrentToken() { return currentToken.get(); }

    // ── Login replay ──────────────────────────────────────────────────────────

    /**
     * Replays the configured login request and extracts the token from the response.
     *
     * @return true on success, false on failure (token unchanged).
     */
    private boolean performLogin(String context) {
        log.accept("[Auth] Performing " + context + "...");
        try {
            IHttpService svc = buildLoginService();
            if (svc == null) {
                log.accept("[Auth] Could not determine login service host/port.");
                return false;
            }

            IHttpRequestResponse result = callbacks.makeHttpRequest(svc, config.loginRequestBytes);
            if (result == null || result.getResponse() == null) {
                log.accept("[Auth] Login request received no response.");
                return false;
            }

            byte[] respBytes = result.getResponse();
            IResponseInfo info = helpers.analyzeResponse(respBytes);
            int status = info.getStatusCode();

            if (status >= 400) {
                log.accept("[Auth] Login response returned HTTP " + status + ". Check login request.");
                return false;
            }

            // Combine full response (headers + body) so regex can match Set-Cookie or JSON body
            String responseText = new String(respBytes, StandardCharsets.ISO_8859_1);

            Matcher m = loginTokenPattern.matcher(responseText);
            if (!m.find() || m.groupCount() < 1) {
                log.accept("[Auth] Token regex did not match login response. "
                        + "Check loginTokenRegex pattern.");
                return false;
            }

            String token = m.group(1);
            if (token == null || token.isBlank()) {
                log.accept("[Auth] Token regex matched but capture group was empty.");
                return false;
            }

            currentToken.set(token);
            initialised.set(true);
            log.accept("[Auth] " + context + " succeeded. Token extracted (length: "
                    + token.length() + ").");
            return true;

        } catch (Exception e) {
            log.accept("[Auth] Login exception: " + e.getMessage());
            return false;
        }
    }

    /**
     * Builds the IHttpService for the login endpoint.
     * Priority: explicit config fields -> parse Host header from loginRequestBytes.
     */
    private IHttpService buildLoginService() {
        // Use explicit config fields if provided
        if (config.loginHost != null && !config.loginHost.isBlank()) {
            final String host  = config.loginHost;
            final int    port  = config.loginPort > 0 ? config.loginPort : 443;
            final String proto = config.loginProtocol != null ? config.loginProtocol : "https";
            return makeService(host, port, proto);
        }

        // Parse from Host header in loginRequestBytes
        try {
            String reqStr = new String(config.loginRequestBytes, StandardCharsets.ISO_8859_1);
            // Find Host header (case-insensitive)
            Pattern hostPat = Pattern.compile("(?im)^Host:\\s*([^\\r\\n]+)");
            Matcher hm = hostPat.matcher(reqStr);
            if (!hm.find()) return null;
            String hostValue = hm.group(1).trim();

            // Split host:port before protocol detection so we can do exact port comparison
            String host; int port;
            if (hostValue.contains(":")) {
                String[] parts = hostValue.split(":", 2);
                host = parts[0];
                try { port = Integer.parseInt(parts[1]); }
                catch (NumberFormatException e) { port = 443; }
            } else {
                host = hostValue;
                port = -1;  // no explicit port; determined by protocol
            }

            // Protocol: check explicit port number, then default to HTTPS.
            // Do NOT use reqStr.startsWith("https") - raw HTTP starts with the method verb.
            // Do NOT use substring match on hostValue - ":8080".contains(":80") = true.
            boolean isHttps;
            if (port == 80) {
                isHttps = false;
            } else if (port == 443 || port < 0) {
                isHttps = true;
            } else {
                // Non-standard port: default HTTPS (most internal APIs use TLS today).
                // User can override by setting explicit loginHost/loginPort/loginProtocol.
                isHttps = true;
            }
            String proto = isHttps ? "https" : "http";
            if (port < 0) port = isHttps ? 443 : 80;

            return makeService(host, port, proto);
        } catch (Exception e) {
            return null;
        }
    }

    private static IHttpService makeService(final String host, final int port, final String proto) {
        return new IHttpService() {
            public String getHost()     { return host; }
            public int    getPort()     { return port; }
            public String getProtocol() { return proto; }
        };
    }

    // ── Header injection ──────────────────────────────────────────────────────

    /**
     * Injects or replaces a header in a raw HTTP request byte array.
     * Uses ISO-8859-1 throughout (same as RequestBuilder) to preserve binary safety.
     */
    static byte[] injectHeader(byte[] req, String headerName, String value) {
        String reqStr = new String(req, StandardCharsets.ISO_8859_1);

        // Replace existing header if present (case-insensitive match)
        Pattern existing = Pattern.compile(
                "(?im)^" + Pattern.quote(headerName) + ":\\s*[^\\r\\n]*");
        Matcher m = existing.matcher(reqStr);
        if (m.find()) {
            String replaced = m.replaceFirst(Matcher.quoteReplacement(headerName + ": " + value));
            return replaced.getBytes(StandardCharsets.ISO_8859_1);
        }

        // Insert new header before the blank line separating headers from body
        int sep = reqStr.indexOf("\r\n\r\n");
        if (sep < 0) return req;   // malformed - leave untouched
        String inserted = reqStr.substring(0, sep)
                + "\r\n" + headerName + ": " + value
                + reqStr.substring(sep);
        return inserted.getBytes(StandardCharsets.ISO_8859_1);
    }
}
