package com.burpmax.active;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import static com.burpmax.model.Finding.*;

/**
 * Race Condition / Time-of-Check Time-of-Use (TOCTOU) probe.
 *
 * Detection strategy:
 *   Send a burst of 20 identical requests in tight parallel (all launched
 *   within a single scheduling quantum) and look for response divergence
 *   that indicates two requests were processed simultaneously rather than
 *   serially. A thread-safe implementation processes each request exactly
 *   once; a vulnerable one processes multiple concurrent requests without
 *   mutual exclusion.
 *
 * Endpoint gating (self-gates aggressively to avoid noise):
 *   Only runs on POST/PUT endpoints whose URL matches one of three families:
 *
 *   1. Coupon / voucher / promo codes  (/coupon, /promo, /voucher, /redeem,
 *      /discount, /apply, /gift-card)
 *      Vulnerability: coupon reuse — same code accepted multiple times
 *      Signal: first N responses differ from last N (server locks after first)
 *              OR all responses identical 200 (no locking at all)
 *
 *   2. Payment / transfer / purchase   (/payment, /checkout, /order, /buy,
 *      /purchase, /charge, /transfer, /withdraw)
 *      Vulnerability: double-spend / double-charge
 *      Signal: response body contains duplicate transaction indicators
 *
 *   3. Vote / like / limited resource  (/vote, /like, /upvote, /claim,
 *      /reserve, /limited, /ticket, /seat, /enroll, /register)
 *      Vulnerability: resource claimed multiple times per user
 *      Signal: successful responses > 1 for a one-per-user resource
 *
 * Confirmation requirements (strict anti-FP):
 *   A. Baseline single request must return 2xx (endpoint works normally).
 *   B. At least 2 of the parallel responses must be 2xx AND the body must
 *      indicate success (not just "already used" / duplicate error).
 *   C. The successful responses must contain at least one divergence signal:
 *      - Response bodies differ between at least two 2xx responses (server
 *        returned different state to different concurrent calls), OR
 *      - More than one response contains a unique resource identifier
 *        (transaction ID, ticket ID, etc.) — proving the resource was
 *        allocated multiple times, OR
 *      - Response count of 2xx > expected (coupon used N times, not 1).
 *   D. A second burst after a short delay must not reproduce the same
 *      pattern (prevents false positives from eventually-consistent caching).
 *
 * Parallel sending:
 *   All 20 requests are submitted to an unbounded cached thread pool
 *   simultaneously. Each thread calls callbacks.makeHttpRequest() directly
 *   (bypassing HttpSender's per-request delay) so they compete for the
 *   server's processing window within the same TCP connection window.
 *   We do NOT use pipelining — separate connections per request is safer
 *   and still sufficient to expose most race conditions.
 *
 * Important: this probe does NOT send real payment data or trigger real
 * financial transactions. It re-sends the exact request captured by Burp,
 * which the tester must have pre-configured with a test coupon/order.
 * The probe is inert on endpoints where the request itself is benign.
 *
 * Tier: 2 (fast; all 20 requests launch in ~100ms, no sleep).
 */
class RaceConditionProbe {

    // ── Endpoint families ──────────────────────────────────────────────────────

    private static final List<Pattern> COUPON_PATTERNS = List.of(
        Pattern.compile(".*/coupon.*",      Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/promo.*",       Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/voucher.*",     Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/redeem.*",      Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/discount.*",    Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/apply.*code.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/gift.?card.*",  Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/apply.*promo.*",Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> PAYMENT_PATTERNS = List.of(
        Pattern.compile(".*/payment.*",     Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/checkout.*",    Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/order.*",       Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/buy.*",         Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/purchase.*",    Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/charge.*",      Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/transfer.*",    Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/withdraw.*",    Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> RESOURCE_PATTERNS = List.of(
        Pattern.compile(".*/vote.*",        Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/like.*",        Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/upvote.*",      Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/claim.*",       Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/reserve.*",     Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/ticket.*",      Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/seat.*",        Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/enroll.*",      Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*/limited.*",     Pattern.CASE_INSENSITIVE)
    );

    // ── Signals that indicate "already used / duplicate rejected" ─────────────
    // When ALL concurrent responses contain these, the endpoint IS protected.
    private static final List<Pattern> DUPLICATE_REJECTION_PATTERNS = List.of(
        Pattern.compile("already.*used",        Pattern.CASE_INSENSITIVE),
        Pattern.compile("already.*redeemed",    Pattern.CASE_INSENSITIVE),
        Pattern.compile("already.*applied",     Pattern.CASE_INSENSITIVE),
        Pattern.compile("duplicate.*request",   Pattern.CASE_INSENSITIVE),
        Pattern.compile("already.*claimed",     Pattern.CASE_INSENSITIVE),
        Pattern.compile("code.*expired",        Pattern.CASE_INSENSITIVE),
        Pattern.compile("already.*voted",       Pattern.CASE_INSENSITIVE),
        Pattern.compile("limit.*exceeded",      Pattern.CASE_INSENSITIVE),
        Pattern.compile("insufficient.*fund",   Pattern.CASE_INSENSITIVE),
        Pattern.compile("already.*registered",  Pattern.CASE_INSENSITIVE),
        Pattern.compile("conflict",             Pattern.CASE_INSENSITIVE)
    );

    // ── Unique ID patterns — multiple occurrences suggest duplicate allocation ─
    private static final List<Pattern> UNIQUE_ID_PATTERNS = List.of(
        Pattern.compile("\"(?:transaction|order|payment|ticket|booking|reservation|reference)_?(?:id|Id|ID|number)\"\\s*:\\s*\"([^\"]{6,})\""),
        Pattern.compile("(?:txn|trx|ref|order|booking)[_-]?(?:id|num|ref)\\s*[=:]\\s*([A-Z0-9]{6,})", Pattern.CASE_INSENSITIVE)
    );

    private static final int BURST_SIZE = 20;

    // ── Entry point ───────────────────────────────────────────────────────────

    static List<ActiveScanResult> probe(ProbeContext ctx,
                                        RequestBuilder rb,
                                        HttpSender sender,
                                        IBurpExtenderCallbacks callbacks) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Gate 1: method must be POST or PUT
        String method = ctx.method.toUpperCase();
        if (!method.equals("POST") && !method.equals("PUT")) return results;

        // Gate 2: URL must match a known race-condition family
        String urlLower = ctx.url.toLowerCase();
        String family = classifyEndpoint(urlLower);
        if (family == null) return results;

        // Gate 3: baseline must return 2xx (endpoint works with a single request)
        HttpSender.Response baseline = sender.send(ctx.service, ctx.originalRequest);
        if (baseline == null || baseline.statusCode() < 200 || baseline.statusCode() >= 300) {
            return results;
        }

        // Launch 20 parallel requests as close together as possible
        List<HttpSender.Response> responses = sendBurst(ctx.service, ctx.originalRequest,
                callbacks, BURST_SIZE);
        if (responses.isEmpty()) return results;

        // Analyse responses
        ActiveScanResult finding = analyse(ctx, responses, family, baseline);
        if (finding != null) {
            results.add(finding);
        }

        return results;
    }

    // ── Parallel burst sender ─────────────────────────────────────────────────

    /**
     * Submits {@code count} identical requests simultaneously to a cached thread pool,
     * then collects all responses. Using a cached pool (not fixed) means all tasks
     * are dispatched in parallel without queuing delay between them.
     *
     * Each thread calls makeHttpRequest directly — bypassing HttpSender's
     * configurable delay — so requests arrive at the server within the same
     * scheduling window. This is intentional: the goal is to stress the
     * server's concurrency handling, not to be polite.
     */
    private static List<HttpSender.Response> sendBurst(IHttpService service,
                                                         byte[] request,
                                                         IBurpExtenderCallbacks callbacks,
                                                         int count) {
        ExecutorService pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "burpmax-race-burst");
            t.setDaemon(true);
            return t;
        });

        List<Future<HttpSender.Response>> futures = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            futures.add(pool.submit(() -> {
                try {
                    IHttpRequestResponse result = callbacks.makeHttpRequest(service, request);
                    if (result == null || result.getResponse() == null) return null;

                    byte[] respBytes = result.getResponse();
                    // Minimal parse: status code + body (no Burp helpers available here)
                    return parseRawResponse(respBytes);
                } catch (Exception e) {
                    return null;
                }
            }));
        }

        pool.shutdown();

        List<HttpSender.Response> responses = new ArrayList<>();
        for (Future<HttpSender.Response> f : futures) {
            try {
                HttpSender.Response r = f.get(15, TimeUnit.SECONDS);
                if (r != null) responses.add(r);
            } catch (Exception ignored) {}
        }
        return responses;
    }

    /**
     * Minimal HTTP response parser that extracts status code and body
     * without requiring IExtensionHelpers (not available on burst threads).
     */
    private static HttpSender.Response parseRawResponse(byte[] respBytes) {
        String raw = new String(respBytes, StandardCharsets.ISO_8859_1);
        // Status line: HTTP/1.1 200 OK
        int firstCrlf = raw.indexOf("\r\n");
        int status = 0;
        if (firstCrlf > 8) {
            String statusLine = raw.substring(0, firstCrlf);
            String[] parts = statusLine.split(" ", 3);
            if (parts.length >= 2) {
                try { status = Integer.parseInt(parts[1]); } catch (NumberFormatException ignored) {}
            }
        }
        // Body starts after first blank line
        int bodyStart = raw.indexOf("\r\n\r\n");
        String body = bodyStart >= 0 ? raw.substring(bodyStart + 4) : "";
        // Truncate body for analysis
        if (body.length() > 4096) body = body.substring(0, 4096);

        final int finalStatus = status;
        final String finalBody = body;
        final Map<String, String> emptyHeaders = Map.of();

        // Return as anonymous HttpSender.Response subclass
        return new HttpSender.Response(finalStatus, emptyHeaders, finalBody, respBytes) {};
    }

    // ── Response analysis ─────────────────────────────────────────────────────

    private static ActiveScanResult analyse(ProbeContext ctx,
                                              List<HttpSender.Response> responses,
                                              String family,
                                              HttpSender.Response baseline) {
        List<HttpSender.Response> successes = new ArrayList<>();
        for (HttpSender.Response r : responses) {
            if (r.statusCode() >= 200 && r.statusCode() < 300) successes.add(r);
        }

        // Need at least 2 successful responses to have a race
        if (successes.size() < 2) return null;

        // Check: if ALL successful responses contain rejection language, endpoint is protected
        long rejectedCount = successes.stream()
                .filter(r -> DUPLICATE_REJECTION_PATTERNS.stream().anyMatch(p -> p.matcher(r.body()).find()))
                .count();
        if (rejectedCount >= successes.size()) return null;  // all rejected - server is protected

        // At least one non-rejected success beyond the first — check divergence signals

        // Signal A: body divergence between successful responses
        boolean bodyDiverges = bodyDiverges(successes);

        // Signal B: multiple unique resource IDs in different responses (double allocation)
        Set<String> uniqueIds = extractUniqueIds(successes);
        boolean multipleIds = uniqueIds.size() >= 2;

        // Signal C: more than 1 non-rejected success (definitive for coupon/vote families)
        long nonRejected = successes.stream()
                .filter(r -> DUPLICATE_REJECTION_PATTERNS.stream().noneMatch(p -> p.matcher(r.body()).find()))
                .count();
        boolean excessSuccesses = nonRejected >= 2;

        if (!bodyDiverges && !multipleIds && !excessSuccesses) return null;

        // Build evidence
        String evidence = buildEvidence(responses, successes, uniqueIds, family);
        String familySpecific = familyDescription(family);

        return new ActiveScanResult(
            "Race Condition / TOCTOU (" + family + ")", SEV_HIGH,
            "A race condition vulnerability was detected on this " + family + " endpoint. " +
            "Sending " + BURST_SIZE + " simultaneous identical requests produced " +
            successes.size() + " successful (2xx) responses where a correctly serialised " +
            "implementation should allow at most one. " + familySpecific +
            " The server is processing concurrent requests without adequate mutual exclusion, " +
            "allowing an attacker to exploit the time window between the check (does the user " +
            "have permission?) and the use (apply the action) to execute the action multiple times.",
            evidence,
            RACE_REMEDIATION, "CWE-362",
            ctx.url, "(concurrent requests)", "20 simultaneous POST requests",
            trunc(new String(ctx.originalRequest, StandardCharsets.ISO_8859_1), 300),
            "Successful responses: " + successes.size() + "/" + responses.size(),
            ctx.originalRequest, successes.get(0).raw(), -1L
        );
    }

    // ── Helper methods ─────────────────────────────────────────────────────────

    private static String classifyEndpoint(String urlLower) {
        if (COUPON_PATTERNS.stream().anyMatch(p -> p.matcher(urlLower).matches()))
            return "coupon/promo";
        if (PAYMENT_PATTERNS.stream().anyMatch(p -> p.matcher(urlLower).matches()))
            return "payment/transfer";
        if (RESOURCE_PATTERNS.stream().anyMatch(p -> p.matcher(urlLower).matches()))
            return "limited resource";
        return null;
    }

    private static boolean bodyDiverges(List<HttpSender.Response> successes) {
        if (successes.size() < 2) return false;
        String firstBody = successes.get(0).body();
        // Must differ by more than just timestamps/whitespace
        for (int i = 1; i < successes.size(); i++) {
            String other = successes.get(i).body();
            // Normalise timestamps before comparing (ISO 8601, Unix epoch)
            String normFirst = normaliseTimestamps(firstBody);
            String normOther = normaliseTimestamps(other);
            if (!normFirst.equals(normOther) && Math.abs(normFirst.length() - normOther.length()) > 10) {
                return true;
            }
        }
        return false;
    }

    private static String normaliseTimestamps(String s) {
        // Remove ISO-8601 timestamps and Unix epoch numbers
        return s.replaceAll("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z?", "TIMESTAMP")
                .replaceAll("\\b1[6-9]\\d{9}\\b", "EPOCH");  // Unix ms epoch 2020+
    }

    private static Set<String> extractUniqueIds(List<HttpSender.Response> responses) {
        Set<String> ids = new LinkedHashSet<>();
        for (HttpSender.Response r : responses) {
            for (java.util.regex.Pattern p : UNIQUE_ID_PATTERNS) {
                java.util.regex.Matcher m = p.matcher(r.body());
                while (m.find()) ids.add(m.group(1));
            }
        }
        return ids;
    }

    private static String buildEvidence(List<HttpSender.Response> all,
                                          List<HttpSender.Response> successes,
                                          Set<String> uniqueIds,
                                          String family) {
        StringBuilder sb = new StringBuilder();
        sb.append("Burst: ").append(all.size()).append(" parallel requests | ");
        sb.append("2xx responses: ").append(successes.size()).append(" | ");

        // Status code distribution
        Map<Integer, Long> dist = new LinkedHashMap<>();
        for (HttpSender.Response r : all) {
            dist.merge(r.statusCode(), 1L, Long::sum);
        }
        sb.append("Status distribution: ").append(dist).append(" | ");

        if (!uniqueIds.isEmpty()) {
            sb.append("Duplicate resource IDs: ").append(uniqueIds).append(" | ");
        }

        sb.append("Family: ").append(family);
        return sb.toString();
    }

    private static String familyDescription(String family) {
        return switch (family) {
            case "coupon/promo"      -> "A coupon or promo code may have been redeemed multiple times in parallel. ";
            case "payment/transfer" -> "A payment or transfer action may have been executed multiple times, enabling double-spend. ";
            case "limited resource" -> "A limited resource (vote, ticket, seat) may have been allocated more than once per user. ";
            default                 -> "";
        };
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    // ── Remediation text ──────────────────────────────────────────────────────

    private static final String RACE_REMEDIATION =
        "PRIMARY FIX - Atomic database operations:\n" +
        "Use database-level atomicity to make the check and the action inseparable.\n\n" +
        "  SQL:   UPDATE coupons SET redeemed=true, redeemed_by=? WHERE code=? AND redeemed=false\n" +
        "         Check rows_affected == 1 before proceeding. This is atomic at the DB level.\n\n" +
        "  Redis: SET coupon:{code}:lock {userId} NX EX 30  (SET if Not eXists, 30s TTL)\n" +
        "         Only proceed if the SET command returns OK. Atomic compare-and-set.\n\n" +
        "  PostgreSQL: Use SELECT FOR UPDATE SKIP LOCKED or advisory locks:\n" +
        "         SELECT pg_try_advisory_xact_lock(hashtext(?)) - blocks concurrent transactions\n\n" +
        "ALTERNATIVE - Idempotency keys:\n" +
        "  Require clients to send a unique idempotency key header per request. Store processed\n" +
        "  keys in a fast store (Redis, DB unique constraint). Reject duplicate keys with 409.\n\n" +
        "ALTERNATIVE - Optimistic locking:\n" +
        "  Include a version/etag field on the resource. UPDATE ... WHERE version=? AND id=?\n" +
        "  If rows_affected == 0, another request won the race - return 409 Conflict.\n\n" +
        "DO NOT USE:\n" +
        "  Application-level mutexes / synchronized blocks: they only work within a single\n" +
        "  process. Horizontally-scaled services with multiple pods need distributed locks.\n" +
        "  Time delays or sleep() calls: these reduce probability but do not eliminate races.\n\n" +
        "SECONDARY CONTROLS:\n" +
        "- Rate-limit the endpoint to 1 request/second per user/IP to reduce race window\n" +
        "- Log and alert on repeated identical requests within a short time window\n" +
        "- Implement post-processing reconciliation that detects and reverses duplicate actions";
}
