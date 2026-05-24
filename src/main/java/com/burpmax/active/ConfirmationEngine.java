package com.burpmax.active;

import burp.IHttpService;

/**
 * Centralised confirmation logic for active scan probes.
 *
 * Every confirmation strategy follows this pattern:
 *   1. Detection request  — already sent by the probe, marker found in response
 *   2. Variation request  — send a DIFFERENT payload with a new unique marker
 *                          to prove the reflection/execution is driven by our
 *                          input, not cached or coincidental
 *   3. Baseline check     — send the original clean request to verify the
 *                          marker is NOT present in a normal response
 *                          (rules out persistent state / always-present content)
 *
 * For time-based probes (SQLi, CmdI blind) the variation step is replaced by
 * a timing confirmation that uses an absolute threshold rather than a relative
 * "half elapsed time" ratio, which is fragile on slow servers.
 *
 * Usage:
 *   boolean confirmed = ConfirmationEngine.confirmReflection(
 *       sender, service, probeReq, altProbeReq, originalReq, marker, altMarker);
 */
public class ConfirmationEngine {

    // How many ms the baseline can take before we consider it "slow server"
    // and skip confirmation (to avoid false negatives on legitimately slow apps)
    private static final long SLOW_SERVER_THRESHOLD_MS = 4000;

    // ── Reflection confirmation (XSS, SSTI, CmdI output-based) ──────────────

    /**
     * Confirm a reflection-based finding.
     *
     * @param sender         HTTP sender
     * @param service        target service
     * @param probeReq       the request that triggered the detection (marker1 payload)
     * @param altProbeReq    a DIFFERENT probe request with a distinct marker (marker2)
     * @param originalReq    the clean original request (no payload)
     * @param marker1        the marker expected in probeReq response
     * @param marker2        the marker expected in altProbeReq response (different value)
     * @return true if confirmed: marker1 in probe response, marker2 in alt response,
     *         and neither marker in the clean response
     */
    public static boolean confirmReflection(HttpSender sender, IHttpService service,
                                             byte[] probeReq, byte[] altProbeReq,
                                             byte[] originalReq,
                                             String marker1, String marker2) {
        // Step 2: Alternative marker probe
        HttpSender.Response altResp = sender.send(service, altProbeReq);
        if (altResp == null || !altResp.body().contains(marker2)) return false;

        // Step 3: Baseline — markers must NOT appear in clean response
        HttpSender.Response baseResp = sender.send(service, originalReq);
        if (baseResp == null) return false;

        String baseBody = baseResp.body();
        // If either marker appears in the clean response, it's not our doing
        return !baseBody.contains(marker1) && !baseBody.contains(marker2);
    }

    /**
     * Simplified confirmation for probes that cannot easily generate a second
     * unique payload (e.g. header-based XSS, error-based SQLi).
     *
     * Strategy: re-send the probe request, then send a clean request.
     * Finding fires only if:
     *   - Probe re-send ALSO contains the marker (rules out transient errors)
     *   - Clean response does NOT contain the marker (rules out persistent state)
     */
    public static boolean confirmSingleMarker(HttpSender sender, IHttpService service,
                                               byte[] probeReq, byte[] originalReq,
                                               String marker) {
        // Re-send probe
        HttpSender.Response reProbe = sender.send(service, probeReq);
        if (reProbe == null || !reProbe.body().contains(marker)) return false;

        // Baseline clean check
        HttpSender.Response base = sender.send(service, originalReq);
        if (base == null) return false;

        return !base.body().contains(marker);
    }

    // ── Error-based confirmation (SQLi error-based) ───────────────────────────

    /**
     * Confirm an error-based injection finding.
     *
     * Strategy:
     *   1. Re-send probe — error must appear again (rules out transient server errors)
     *   2. Send clean request — error must NOT appear (rules out existing broken state)
     *
     * @param errorPattern   regex pattern or substring to find in response
     */
    public static boolean confirmError(HttpSender sender, IHttpService service,
                                        byte[] probeReq, byte[] originalReq,
                                        java.util.regex.Pattern errorPattern) {
        // Re-send to confirm error is reproducible
        HttpSender.Response reProbe = sender.send(service, probeReq);
        if (reProbe == null) return false;
        String reBody = reProbe.body() + " " + reProbe.headers();
        if (!errorPattern.matcher(reBody).find()) return false;

        // Clean request must not trigger the same error
        HttpSender.Response base = sender.send(service, originalReq);
        if (base == null) return false;
        String baseBody = base.body() + " " + base.headers();
        return !errorPattern.matcher(baseBody).find();
    }

    // ── Time-based confirmation ───────────────────────────────────────────────

    /**
     * Confirm a time-based blind injection finding.
     *
     * Strategy:
     *   1. Re-send the SLEEP payload — elapsed must again exceed the threshold
     *      (rules out network jitter on the first request)
     *   2. Send a clean request — it must complete WITHIN the threshold
     *      (rules out "slow server" false positives)
     *
     * Uses absolute thresholds, not relative ("half of elapsed") which is fragile.
     *
     * @param sleepThresholdMs   minimum expected delay caused by the sleep payload
     * @param baselineMs         measured baseline response time
     */
    public static boolean confirmTimeBased(HttpSender sender, IHttpService service,
                                            byte[] probeReq, byte[] originalReq,
                                            long sleepThresholdMs, long baselineMs) {
        // If the server was already slow, don't attempt time-based confirmation
        if (baselineMs > SLOW_SERVER_THRESHOLD_MS) return false;

        // Step 2: Re-send sleep payload — must be slow again
        long start2    = System.currentTimeMillis();
        HttpSender.Response re = sender.send(service, probeReq);
        long elapsed2  = System.currentTimeMillis() - start2;
        if (re == null || elapsed2 < sleepThresholdMs) return false;

        // Step 3: Send clean request — must be fast (< threshold + baseline)
        long start3    = System.currentTimeMillis();
        HttpSender.Response clean = sender.send(service, originalReq);
        long elapsed3  = System.currentTimeMillis() - start3;
        if (clean == null) return false;

        // Clean request must complete well BELOW the sleep threshold.
        // The old formula: max(sleepThreshold/2, baseline*2+500) could exceed
        // sleepThresholdMs on slow servers (e.g. baseline=3000ms → maxClean=6500ms
        // but sleepThreshold=4000ms), causing the clean request to also "confirm"
        // the sleep and producing a false positive.
        //
        // Correct formula: cap at 60% of sleepThresholdMs so there is always a
        // clear gap between "fast enough to be clean" and "slow enough to confirm sleep".
        // Also require the clean request to be within 2x the measured baseline.
        long maxClean = Math.min(sleepThresholdMs * 6 / 10,
                                 Math.max(baselineMs * 2 + 500, 1500L));
        return elapsed3 < maxClean;
    }

    // ── Differential confirmation (NoSQLi, IDOR, boolean SQLi) ───────────────

    /**
     * Confirm a differential (true/false condition) finding.
     *
     * Strategy: swap the payloads and check that the responses ALSO differ.
     * This rules out A/B testing, personalisation, and random content variation.
     *
     * @param trueLen    body length from true-condition probe
     * @param falseLen   body length from false-condition probe
     * @param baseLen    baseline body length
     * @param threshold  minimum similarity difference to consider "significant"
     */
    public static boolean confirmDifferential(HttpSender sender, IHttpService service,
                                               byte[] trueReq2, byte[] falseReq2,
                                               int trueLen, int falseLen, int baseLen,
                                               double threshold) {
        // Send the true/false probes a second time
        HttpSender.Response r2true  = sender.send(service, trueReq2);
        HttpSender.Response r2false = sender.send(service, falseReq2);
        if (r2true == null || r2false == null) return false;

        int len2true  = r2true.body().length();
        int len2false = r2false.body().length();

        // Both runs must show the same differential pattern
        boolean run1differs = similarity(trueLen, falseLen) < (1 - threshold);
        boolean run2differs = similarity(len2true, len2false) < (1 - threshold);
        boolean consistent  = similarity(trueLen, len2true) > 0.8
                           && similarity(falseLen, len2false) > 0.8;

        return run1differs && run2differs && consistent;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static double similarity(int a, int b) {
        if (a == 0 && b == 0) return 1.0;
        if (a == 0 || b == 0) return 0.0;
        return (double) Math.min(a, b) / Math.max(a, b);
    }
}
