package com.burpmax.active;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;

import java.util.*;

/**
 * Thin wrapper around Burp's makeHttpRequest API.
 * Enforces a response size cap and applies a configurable inter-request delay
 * to avoid triggering WAF rate-limiting on active scan probes.
 */
public class HttpSender {

    private final IBurpExtenderCallbacks     callbacks;
    private final IExtensionHelpers          helpers;
    private final int                        delayMs;
    // Shared cancelled flag from ActiveScanner -- checked before every request
    // and inside the delay sleep so cancel is near-instant.
    private final java.util.concurrent.atomic.AtomicBoolean cancelled;
    // Optional auth manager -- when set, injects/refreshes auth headers before every send.
    private volatile AuthManager             authManager = null;

    private static final int MAX_RESP_BODY  = 131_072;   // 128KB
    private static final int MAX_RETRIES    = 2;
    private static final long RETRY_BASE_MS = 800L;

    public HttpSender(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this(callbacks, helpers, 0, new java.util.concurrent.atomic.AtomicBoolean(false));
    }

    public HttpSender(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                      int delayMs,
                      java.util.concurrent.atomic.AtomicBoolean cancelled) {
        this.callbacks  = callbacks;
        this.helpers    = helpers;
        this.delayMs    = Math.max(0, delayMs);
        this.cancelled  = cancelled;
    }

    /**
     * Attach an AuthManager. When set, every request is passed through
     * AuthManager.applyAuth() before it is sent. Call after construction
     * and before any probes start.
     */
    public void setAuthManager(AuthManager am) { this.authManager = am; }

    /**
     * Send an HTTP request, retrying up to MAX_RETRIES times on transient failure.
     *
     * Transient failures (null response, null response bytes) are common on:
     *   - Unstable VPN connections
     *   - Targets with aggressive rate limiting that drops connections
     *   - Burp's internal HTTP stack timing out on slow responses
     *
     * Retry strategy: exponential backoff starting at RETRY_BASE_MS.
     *   Attempt 1: immediate
     *   Attempt 2: wait ~800ms  (RETRY_BASE_MS × 2^0 ± 20% jitter)
     *   Attempt 3: wait ~1600ms (RETRY_BASE_MS × 2^1 ± 20% jitter)
     *
     * Does NOT retry on HTTP error responses (4xx/5xx) — those are valid
     * responses and probes need to see them. Only retries on connection-level
     * failures where no response was received at all.
     *
     * Time-based probes are not affected: they track elapsed time themselves
     * and pass the result to ConfirmationEngine.confirmTimeBased which ignores
     * responses that arrived too fast (retry result would arrive after a longer
     * delay and would not match the sleep threshold).
     */
    public Response send(IHttpService service, byte[] request) {
        if (cancelled.get()) return null;  // abort immediately if scan cancelled
        applyDelay();
        if (cancelled.get()) return null;  // abort after delay in case cancel happened during wait

        // Apply auth before the first attempt
        AuthManager am = this.authManager;
        if (am != null && am.isReady()) request = am.applyAuth(request);

        for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            if (attempt > 0) {
                if (cancelled.get()) return null;
                long backoff = RETRY_BASE_MS * (1L << (attempt - 1));
                long jitter  = (long)(backoff * 0.2);
                long sleep   = backoff - jitter + (long)(java.util.concurrent.ThreadLocalRandom.current().nextDouble() * jitter * 2);
                try { Thread.sleep(Math.max(0, sleep)); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); return null; }
            }
            Response r = doSend(service, request);
            if (r == null) continue;  // connection-level failure - retry

            // On 401: trigger re-auth once per send call, then retry with new token.
            // Only on first attempt so we don't loop infinitely if re-auth also yields 401.
            if (r.statusCode() == 401 && attempt == 0 && am != null) {
                am.notifyUnauthorized();
                // Re-apply auth (token may have been refreshed by notifyUnauthorized)
                request = am.applyAuth(request);
                continue;  // retry immediately with the fresh token
            }

            return r;
        }
        return null;  // all attempts exhausted
    }

    /** Apply the inter-request delay (with jitter) before sending. */
    private void applyDelay() {
        if (delayMs <= 0) return;
        int jitter = (int)(delayMs * 0.3);
        int actual = delayMs - jitter + java.util.concurrent.ThreadLocalRandom.current().nextInt(jitter * 2 + 1);
        // Sleep in 50ms chunks so cancel is detected within 50ms
        long remaining = actual;
        while (remaining > 0 && !cancelled.get()) {
            long chunk = Math.min(remaining, 50);
            try { Thread.sleep(chunk); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
            remaining -= chunk;
        }
    }

    /** Single send attempt — returns null on any connection-level error. */
    private Response doSend(IHttpService service, byte[] request) {
        try {
            IHttpRequestResponse result = callbacks.makeHttpRequest(service, request);
            if (result == null) return null;

            byte[] respBytes = result.getResponse();
            if (respBytes == null) return null;

            IResponseInfo info    = helpers.analyzeResponse(respBytes);
            int           status  = info.getStatusCode();
            int           bodyOff = info.getBodyOffset();
            int           bodyLen = Math.min(respBytes.length - bodyOff, MAX_RESP_BODY);
            String body;
            try {
                body = helpers.bytesToString(
                        Arrays.copyOfRange(respBytes, bodyOff, bodyOff + bodyLen));
            } catch (Exception e) { body = ""; }

            Map<String, String> headers = new LinkedHashMap<>();
            for (String h : info.getHeaders()) {
                int colon = h.indexOf(':');
                if (colon > 0)
                    headers.put(h.substring(0, colon).trim().toLowerCase(),
                                h.substring(colon + 1).trim());
            }
            return new Response(status, headers, body, respBytes);
        } catch (Exception e) {
            return null;
        }
    }

    // ── Response value object ─────────────────────────────────────────────────

    public static class Response {
        private final int                 statusCode;
        private final Map<String, String> headers;
        private final String              body;
        private final byte[]              raw;

        Response(int statusCode, Map<String, String> headers, String body, byte[] raw) {
            this.statusCode = statusCode;
            this.headers    = headers;
            this.body       = body;
            this.raw        = raw;
        }

        public int    statusCode()        { return statusCode; }
        public String body()              { return body; }
        public byte[] raw()               { return raw; }
        // Returns headers in HTTP wire format (Name: value\r\n...) not Map.toString().
        // Probes that do resp.body() + " " + resp.headers() to search for error
        // patterns need actual header syntax, not {key=value} Java map format.
        public String headers() {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> e : headers.entrySet()) {
                sb.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            }
            return sb.toString();
        }
        public String header(String name) { return headers.get(name.toLowerCase()); }
        /** Returns a read-only view of all response headers (keys already lowercase). */
        public Map<String, String> headersAsMap() { return Collections.unmodifiableMap(headers); }
    }
}
