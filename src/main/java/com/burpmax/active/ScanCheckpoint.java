package com.burpmax.active;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

/**
 * Persists active scan progress to Burp's extension settings so a scan can
 * resume after Burp restarts mid-engagement.
 *
 * What is saved:
 *   - List of target URLs not yet scanned (pending)
 *   - List of target URLs already scanned (completed) — for dedup on resume
 *   - Scan start timestamp and total target count
 *
 * What is NOT saved:
 *   - Raw request/response bytes (too large for Burp settings storage)
 *   - In-memory ProbeContext objects (rebuilt from Burp site map on resume)
 *
 * Resume strategy:
 *   On scan start, if a checkpoint exists for the same host set, skip all
 *   targets whose URLs are in the completed set. The site map will still
 *   have the original request/response bytes for each target, so ProbeContext
 *   objects are rebuilt normally — only the ones already probed are skipped.
 *
 * Storage:
 *   Burp's saveExtensionSetting API — persists across restarts, ~1MB limit.
 *   JSON is compact (URL strings only, no bytes), so 500 targets ≈ 30KB.
 */
public class ScanCheckpoint {

    private static final String KEY_CHECKPOINT = "burpmax_scan_checkpoint";
    private static final int    MAX_URLS       = 2000;  // cap to stay well under 1MB

    // ── Checkpoint data ───────────────────────────────────────────────────────
    public final Set<String> completedUrls;   // URLs already probed
    public final Set<String> pendingUrls;     // URLs not yet probed
    public final String      startedAt;       // ISO timestamp of scan start
    public final int         totalTargets;    // total targets at scan start

    private ScanCheckpoint(Set<String> completed, Set<String> pending,
                            String startedAt, int totalTargets) {
        this.completedUrls = Collections.unmodifiableSet(new LinkedHashSet<>(completed));
        this.pendingUrls   = Collections.unmodifiableSet(new LinkedHashSet<>(pending));
        this.startedAt     = startedAt;
        this.totalTargets  = totalTargets;
    }

    /** Create a new checkpoint at scan start with all targets pending. */
    public static ScanCheckpoint start(List<String> allTargetUrls) {
        int cap = Math.min(allTargetUrls.size(), MAX_URLS);
        Set<String> pending = new LinkedHashSet<>(allTargetUrls.subList(0, cap));
        return new ScanCheckpoint(new LinkedHashSet<>(), pending,
                java.time.Instant.now().toString(), allTargetUrls.size());
    }

    /** Return a new checkpoint with the given URL moved from pending → completed. */
    public ScanCheckpoint markCompleted(String url) {
        Set<String> newCompleted = new LinkedHashSet<>(completedUrls);
        Set<String> newPending   = new LinkedHashSet<>(pendingUrls);
        newCompleted.add(url);
        newPending.remove(url);
        return new ScanCheckpoint(newCompleted, newPending, startedAt, totalTargets);
    }

    /** True if this checkpoint is still relevant (has pending work). */
    public boolean hasPending() {
        return !pendingUrls.isEmpty();
    }

    /** Percentage complete, 0–100. */
    public int percentComplete() {
        if (totalTargets == 0) return 100;
        return (int)((completedUrls.size() * 100L) / totalTargets);
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /** Save this checkpoint to Burp extension settings. */
    public void save(Object burpCallbacks) {
        try {
            JSONObject o = new JSONObject();
            o.put("started_at",    startedAt);
            o.put("total_targets", totalTargets);
            JSONArray comp = new JSONArray();
            for (String u : completedUrls) comp.put(u);
            o.put("completed", comp);
            JSONArray pend = new JSONArray();
            for (String u : pendingUrls) pend.put(u);
            o.put("pending", pend);

            java.lang.reflect.Method m = burpCallbacks.getClass()
                    .getMethod("saveExtensionSetting", String.class, String.class);
            m.invoke(burpCallbacks, KEY_CHECKPOINT, o.toString());
        } catch (Exception e) {
            // Log to stderr so save failures are visible in Burp's extension error output.
            // Previously swallowed silently, making it impossible to diagnose resume failures.
            System.err.println("[BurpMax] ScanCheckpoint.save() failed: " + e);
        }
    }

    /** Load checkpoint from Burp settings. Returns null if none exists or is invalid. */
    public static ScanCheckpoint load(Object burpCallbacks) {
        try {
            java.lang.reflect.Method m = burpCallbacks.getClass()
                    .getMethod("loadExtensionSetting", String.class);
            String raw = (String) m.invoke(burpCallbacks, KEY_CHECKPOINT);
            if (raw == null || raw.isBlank()) return null;

            JSONObject o = new JSONObject(raw);
            String startedAt    = o.optString("started_at", "");
            int    totalTargets = o.optInt("total_targets", 0);

            Set<String> completed = new LinkedHashSet<>();
            JSONArray comp = o.optJSONArray("completed");
            if (comp != null) for (int i = 0; i < comp.length(); i++) { Object v = comp.get(i); if (v != null && !v.toString().isEmpty()) completed.add(v.toString()); }

            Set<String> pending = new LinkedHashSet<>();
            JSONArray pend = o.optJSONArray("pending");
            if (pend != null) for (int i = 0; i < pend.length(); i++) { Object v = pend.get(i); if (v != null && !v.toString().isEmpty()) pending.add(v.toString()); }

            if (pending.isEmpty() && completed.isEmpty()) return null;
            return new ScanCheckpoint(completed, pending, startedAt, totalTargets);
        } catch (Exception e) { return null; }
    }

    /** Clear the saved checkpoint — called when a scan completes cleanly. */
    public static void clear(Object burpCallbacks) {
        try {
            java.lang.reflect.Method m = burpCallbacks.getClass()
                    .getMethod("saveExtensionSetting", String.class, String.class);
            m.invoke(burpCallbacks, KEY_CHECKPOINT, "");
        } catch (Exception ignored) {}
    }
}
