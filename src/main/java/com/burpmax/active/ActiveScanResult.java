package com.burpmax.active;

/**
 * Result from a single active probe.
 *
 * Carries both the truncated string snapshots (for legacy text use) and
 * the raw probe request/response byte arrays (for high-fidelity PoC rendering).
 * Also carries timingMs for time-based findings so the renderer can annotate
 * the response panel with the observed delay.
 */
public class ActiveScanResult {

    public final String name;         // finding name - will be prefixed with [ACTIVE]
    public final String severity;
    public final String description;
    public final String evidence;
    public final String remediation;
    public final String cwe;
    public final String endpoint;     // URL that was probed
    public final String parameter;    // parameter/header that was fuzzed
    public final String payload;      // exact payload that triggered the finding
    public final String request;      // raw probe request (truncated string - legacy)
    public final String response;     // raw probe response snippet (legacy)

    // ── High-fidelity PoC fields ──────────────────────────────────────────────
    /** Raw bytes of the mutated probe request (the request that triggered the finding). */
    public final byte[] probeRequestBytes;
    /** Raw bytes of the probe response confirming the finding. */
    public final byte[] probeResponseBytes;
    /**
     * For time-based findings: observed response time in milliseconds.
     * -1 means not applicable (non-timing findings).
     * Rendered as an annotation overlay on the response panel.
     */
    public final long timingMs;

    // ── Full constructor (preferred) ──────────────────────────────────────────
    public ActiveScanResult(String name, String severity,
                             String description, String evidence,
                             String remediation, String cwe,
                             String endpoint, String parameter,
                             String payload,
                             String request, String response,
                             byte[] probeRequestBytes, byte[] probeResponseBytes,
                             long timingMs) {
        this.name              = "[ACTIVE] " + name;
        this.severity          = severity;
        this.description       = description;
        this.evidence          = evidence;
        this.remediation       = remediation;
        this.cwe               = cwe;
        this.endpoint          = endpoint;
        this.parameter         = parameter;
        this.payload           = payload;
        this.request           = request;
        this.response          = response;
        this.probeRequestBytes = probeRequestBytes;
        this.probeResponseBytes= probeResponseBytes;
        this.timingMs          = timingMs;
    }

    // ── Legacy constructor (11-arg) — kept for OOB finding builders ──────────
    public ActiveScanResult(String name, String severity,
                             String description, String evidence,
                             String remediation, String cwe,
                             String endpoint, String parameter,
                             String payload, String request, String response) {
        this(name, severity, description, evidence, remediation, cwe,
             endpoint, parameter, payload, request, response,
             null, null, -1L);
    }
}
