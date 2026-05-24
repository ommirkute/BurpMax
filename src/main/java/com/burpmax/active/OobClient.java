package com.burpmax.active;

import java.util.List;

/**
 * Abstraction over an out-of-band (OOB) interaction server.
 *
 * Implementations:
 *   InteractshOobClient  — public/self-hosted interactsh server (default)
 *   CollaboratorOobClient — Burp Collaborator (optional, Pro only)
 *
 * Probes call registerPayload() to get a unique subdomain per injection point,
 * inject it into their payload, then record the token via recordInjection().
 * After all probes complete, ActiveScanner calls pollAndMatch() which fetches
 * all interactions that arrived since the scan started and matches them back
 * to the injection records to produce OobHit findings.
 *
 * Thread-safety: registerPayload() and recordInjection() are called from the
 * single active-scanner thread. pollAndMatch() is also called from that thread
 * (at the end of the scan), so no locking is needed.
 */
public interface OobClient {

    /**
     * @return true if this client is properly configured and ready to use.
     */
    boolean isAvailable();

    /**
     * Generate a unique subdomain token for one injection attempt.
     * The returned string is the full hostname to embed in payloads,
     * e.g. "a1b2c3d4.oast.pro" or "a1b2c3d4.burpcollaborator.net".
     *
     * IMPORTANT: callers MUST immediately follow this with recordInjection()
     * using the returned host. Failing to call recordInjection() will result
     * in the generated uniqueId being orphaned — any OOB callback for that host
     * will be silently dropped because no injection record will match it.
     *
     * Prefer generateAndRecord() which atomically combines both operations.
     *
     * @param label  human-readable label for debugging (e.g. "ssrf-Referer")
     * @return       unique OOB hostname, or null if client is unavailable
     */
    String generateHost(String label);

    /**
     * Atomically generate a host and record the injection in one operation.
     * Preferred over calling generateHost() + recordInjection() separately
     * because it prevents the orphaned-host problem if the probe throws
     * between the two calls.
     *
     * Returns the OOB hostname (same as generateHost would return), or null if unavailable.
     * The injection is recorded immediately so any callback will match regardless of
     * what happens next in the probe.
     */
    default String generateAndRecord(String label, String probeName,
                                      String endpoint, String parameter,
                                      String payload, byte[] probeRequestBytes) {
        String host = generateHost(label);
        if (host == null) return null;
        recordInjection(host, probeName, endpoint, parameter, payload, probeRequestBytes);
        return host;
    }

    /**
     * Record metadata about an injection so a callback can be matched back.
     *
     * @param oobHost    the hostname returned by generateHost()
     * @param probeName  e.g. "SSRF", "Log4Shell", "Blind XXE"
     * @param endpoint   the URL that was probed
     * @param parameter  the parameter / header that was injected
     * @param payload    the full payload string sent
     */
    /**
     * Record metadata about an injection so a callback can be matched back.
     * probeRequestBytes carries the raw mutated HTTP request for PoC rendering.
     */
    void recordInjection(String oobHost, String probeName,
                          String endpoint, String parameter, String payload,
                          byte[] probeRequestBytes);

    /** Convenience overload without probe bytes (OOB-only finding builders). */
    default void recordInjection(String oobHost, String probeName,
                                  String endpoint, String parameter, String payload) {
        recordInjection(oobHost, probeName, endpoint, parameter, payload, null);
    }

    /**
     * Poll the OOB server for any interactions that arrived since the scan started,
     * match them to recorded injections, and return confirmed hits.
     *
     * Called once, after the active probe loop completes, with a configurable
     * poll delay to allow DNS TTL propagation.
     *
     * @return list of confirmed OOB hits (may be empty, never null)
     */
    List<OobHit> pollAndMatch();

    /**
     * Release any resources held by this client (HTTP connections, etc.).
     * Called when the scan completes or is cancelled.
     */
    void close();

    // ── Value object returned by pollAndMatch() ───────────────────────────────

    record OobHit(
        String probeName,
        String endpoint,
        String parameter,
        String payload,
        String interactionType,    // "dns", "http", "smtp"
        String interactionDetail,  // e.g. query type, HTTP method+path
        byte[] probeRequestBytes   // raw probe request for PoC rendering (may be null)
    ) {}
}
