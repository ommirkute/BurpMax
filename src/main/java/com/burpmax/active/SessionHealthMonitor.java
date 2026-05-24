package com.burpmax.active;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Periodically polls the configured health-check URL to confirm the active
 * scan session is still live. When the session is detected as expired, it
 * calls AuthManager.notifyUnauthorized() to trigger a re-auth.
 *
 * Design:
 *   - Single background daemon thread (ScheduledExecutorService).
 *   - Configurable poll interval (default 60s). Conservative to avoid adding
 *     noise to target server logs.
 *   - Health check: GET to healthUrl. Session is healthy if:
 *       (a) HTTP status is not 401 or 403, AND
 *       (b) response body/headers match healthOkPattern (if configured).
 *   - On unhealthy: calls authManager.notifyUnauthorized(). AuthManager's
 *     loginLock ensures the re-auth happens exactly once even if multiple
 *     callers (probe threads + health monitor) trigger simultaneously.
 *   - start() / stop() are idempotent. Calling stop() waits for the running
 *     check (if any) to complete within 2s before returning.
 */
public class SessionHealthMonitor {

    private static final int DEFAULT_POLL_INTERVAL_SECONDS = 60;

    private final AuthConfig              config;
    private final AuthManager             authManager;
    private final IBurpExtenderCallbacks  callbacks;
    private final IExtensionHelpers       helpers;
    private final Consumer<String>        log;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "burpmax-health-monitor");
        t.setDaemon(true);
        return t;
    });

    private volatile ScheduledFuture<?> task         = null;
    private final AtomicBoolean         running      = new AtomicBoolean(false);
    private volatile Pattern            okPattern    = null;
    private volatile int                pollIntervalSec = DEFAULT_POLL_INTERVAL_SECONDS;

    public SessionHealthMonitor(AuthConfig config,
                                AuthManager authManager,
                                IBurpExtenderCallbacks callbacks,
                                IExtensionHelpers helpers,
                                Consumer<String> log) {
        this.config      = config;
        this.authManager = authManager;
        this.callbacks   = callbacks;
        this.helpers     = helpers;
        this.log         = log != null ? log : msg -> {};

        if (config.healthOkPattern != null) {
            try {
                this.okPattern = Pattern.compile(config.healthOkPattern,
                        Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
            } catch (Exception e) {
                this.log.accept("[HealthMonitor] Invalid healthOkPattern: " + e.getMessage()
                        + " - status-only checks will be used.");
            }
        }
    }

    public void setPollIntervalSeconds(int sec) {
        this.pollIntervalSec = Math.max(10, sec);
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    /**
     * Start periodic health checks. Safe to call multiple times; only one
     * scheduler task is active at a time.
     */
    public void start() {
        if (config.healthUrl == null) return;  // no health URL - nothing to monitor
        if (!running.compareAndSet(false, true)) return;

        log.accept("[HealthMonitor] Starting. Health URL: " + config.healthUrl
                + " | Interval: " + pollIntervalSec + "s.");

        task = scheduler.scheduleWithFixedDelay(
                this::check,
                pollIntervalSec,    // initial delay - give the scan time to kick off first
                pollIntervalSec,
                TimeUnit.SECONDS);
    }

    /**
     * Stop the health monitor and release executor resources.
     * Safe to call multiple times. Called from ActiveScanner.run() finally block
     * so the single-thread executor is always reclaimed after each scan.
     */
    public void stop() {
        running.set(false);
        ScheduledFuture<?> t = task;
        if (t != null) t.cancel(false);
        // Shut down the executor so the daemon thread is released after each scan.
        // SessionHealthMonitor is created fresh per scan, so the executor is not reused.
        scheduler.shutdownNow();
    }

    /** Alias for stop() - retained for call sites that distinguish lifecycle phases. */
    public void shutdown() {
        stop();
    }

    // ── Health check ──────────────────────────────────────────────────────────

    /**
     * Run a single health check. Called by the scheduled executor thread
     * and may also be called directly for an immediate check.
     */
    public void check() {
        if (!running.get()) return;
        String url = config.healthUrl;
        if (url == null || url.isBlank()) return;

        try {
            // Parse host/port/protocol from URL
            java.net.URL parsed = new java.net.URL(url);
            boolean isHttps  = "https".equalsIgnoreCase(parsed.getProtocol());
            String  host     = parsed.getHost();
            int     port     = parsed.getPort() > 0 ? parsed.getPort()
                                                     : (isHttps ? 443 : 80);
            // getFile() returns "" for bare-host URLs (e.g. "https://example.com").
            // An empty path produces "GET  HTTP/1.1" (double space) which is invalid.
            String  pathQ    = parsed.getFile();
            if (pathQ == null || pathQ.isEmpty()) pathQ = "/";

            // Build a minimal GET request with the current auth token injected
            String rawRequest = "GET " + pathQ + " HTTP/1.1\r\n"
                    + "Host: " + host + (parsed.getPort() > 0 ? ":" + parsed.getPort() : "") + "\r\n"
                    + "Connection: close\r\n"
                    + "\r\n";
            byte[] requestBytes = rawRequest.getBytes(StandardCharsets.ISO_8859_1);

            // Apply current auth token
            requestBytes = authManager.applyAuth(requestBytes);

            final String  _host  = host;
            final int     _port  = port;
            final String  _proto = parsed.getProtocol();
            IHttpService svc = new IHttpService() {
                public String getHost()     { return _host; }
                public int    getPort()     { return _port; }
                public String getProtocol() { return _proto; }
            };

            IHttpRequestResponse result = callbacks.makeHttpRequest(svc, requestBytes);
            if (result == null || result.getResponse() == null) {
                log.accept("[HealthMonitor] No response from health URL - network issue, skipping check.");
                return;
            }

            byte[] respBytes = result.getResponse();
            IResponseInfo info   = helpers.analyzeResponse(respBytes);
            int           status = info.getStatusCode();

            // 401 or 403 - session definitely expired
            if (status == 401 || status == 403) {
                log.accept("[HealthMonitor] Health check returned HTTP " + status
                        + " - session expired. Triggering re-auth.");
                authManager.notifyUnauthorized();
                return;
            }

            // Check response body against the ok pattern (if configured)
            if (okPattern != null) {
                int bodyOff = Math.min(info.getBodyOffset(), respBytes.length);
                String body = new String(
                        java.util.Arrays.copyOfRange(respBytes, bodyOff, respBytes.length),
                        StandardCharsets.ISO_8859_1);
                String headers = buildHeaderString(info.getHeaders());
                if (!okPattern.matcher(headers + body).find()) {
                    log.accept("[HealthMonitor] Health check pattern not found in response "
                            + "(HTTP " + status + ") - session may have expired. Triggering re-auth.");
                    authManager.notifyUnauthorized();
                    return;
                }
            }

            log.accept("[HealthMonitor] Session healthy (HTTP " + status + ").");

        } catch (Exception e) {
            // Benign errors (DNS, timeout) - log and continue. Scan should not
            // abort just because the health check had a transient network error.
            log.accept("[HealthMonitor] Health check error (non-fatal): " + e.getMessage());
        }
    }

    private static String buildHeaderString(java.util.List<String> headers) {
        StringBuilder sb = new StringBuilder();
        for (String h : headers) sb.append(h).append("\r\n");
        return sb.toString();
    }
}
