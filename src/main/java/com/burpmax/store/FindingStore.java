package com.burpmax.store;

import com.burpmax.model.Finding;
import org.json.JSONArray;
import org.json.JSONObject;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe in-memory finding store.
 * add() / mergeEndpoint() called from Burp listener thread.
 * Listeners fired on the same thread — callers must post to EDT themselves.
 */
public class FindingStore {

    private final Map<String, Finding>    index    = new LinkedHashMap<>();
    private final List<Finding>           findings = new ArrayList<>();
    private final List<Runnable>          listeners = new CopyOnWriteArrayList<>();

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // ── Mutation ──────────────────────────────────────────────────────────────

    private static final int MAX_FINDINGS = 5_000;

    /** @return true if new finding added, false if merged into existing or cap reached */
    // Semantic dedup: maps a "family key" (host + vuln family) to the strongest
    // finding already stored. When a weaker passive finding arrives and an active
    // confirmation for the same family already exists, the passive is suppressed.
    private final Map<String, String> familyIndex = new LinkedHashMap<>();

    /** Canonical family name for a finding — strips [ACTIVE] prefix and variant suffixes. */
    private static String familyKey(Finding f) {
        String name = f.name
            .replaceFirst("^\\[ACTIVE\\]\\s*", "")   // strip [ACTIVE] prefix
            .replaceFirst("\\s*\\(.*\\)$", "")        // strip variant suffix e.g. "(CL.TE)"
            .replaceFirst("\\s*:\\s*.*$", "")          // strip sub-type suffix after ":"
            .trim().toLowerCase();
        return f.host + "|" + name;
    }

    public boolean add(Finding f) {
        boolean isNew;
        boolean changed = false;  // only true if store state actually changed
        synchronized (this) {
            String key = f.dedupKey();
            String fKey = familyKey(f);
            boolean isActive = f.name.startsWith("[ACTIVE]");

            // Semantic dedup: if an active confirmation already exists for this vuln
            // family, suppress the weaker passive finding entirely.
            if (!isActive && familyIndex.containsKey(fKey)) {
                // Passive finding for a family already confirmed actively — merge endpoint only
                String activeKey = familyIndex.get(fKey);
                Finding existing = index.get(activeKey);
                if (existing != null) {
                    Finding.EndpointEntry ep0 = f.affectedEndpoints.isEmpty()
                            ? null : f.affectedEndpoints.get(0);
                    if (ep0 != null) {
                        existing.mergeEndpoint(f.url, f.statusCode,
                                ep0.rawRequest, ep0.rawResponse, ep0.httpService);
                    }
                }
                isNew = false;
                changed = true;
            } else if (!index.containsKey(key)) {
                if (findings.size() >= MAX_FINDINGS) return false;  // hard cap - nothing changed
                index.put(key, f);
                findings.add(f);
                // Register in family index — active findings take priority
                if (isActive || !familyIndex.containsKey(fKey)) {
                    familyIndex.put(fKey, key);
                }
                isNew = true;
                changed = true;
            } else {
                Finding existing = index.get(key);
                Finding.EndpointEntry ep0 = f.affectedEndpoints.isEmpty()
                        ? null : f.affectedEndpoints.get(0);
                if (ep0 != null) {
                    // Use full constructor to preserve probe data from active findings
                    existing.mergeEndpointFull(f.url, f.statusCode,
                            ep0.rawRequest, ep0.rawResponse, ep0.httpService,
                            ep0.probeRequest, ep0.probeResponse,
                            ep0.payload, ep0.parameter, ep0.timingMs);
                }
                isNew = false;
                changed = true;
            }
        }
        // fire() is always called OUTSIDE the lock so listeners (which may re-enter
        // the store via getAll()/summary()) never run while the monitor is held.
        if (changed) fire();
        return isNew;
    }

    public void clear() {
        synchronized (this) {
            index.clear();
            familyIndex.clear();
            findings.clear();
        }
        fire();
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public synchronized List<Finding> getAll() {
        return new ArrayList<>(findings);
    }

    public synchronized List<Finding> getVisible() {
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings) if (!f.suppressed) out.add(f);
        return out;
    }

    public synchronized List<Finding> getSuppressed() {
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings) if (f.suppressed) out.add(f);
        return out;
    }

    public synchronized int size() { return findings.size(); }

    public synchronized Map<String, Integer> summary() {
        Map<String, Integer> m = new LinkedHashMap<>();
        m.put(Finding.SEV_CRITICAL, 0);
        m.put(Finding.SEV_HIGH,     0);
        m.put(Finding.SEV_MEDIUM,   0);
        m.put(Finding.SEV_LOW,      0);
        m.put(Finding.SEV_INFO,     0);
        for (Finding f : findings) {
            if (!f.suppressed) {
                String sev = f.effectiveSeverity();
                m.merge(sev, 1, Integer::sum);
            }
        }
        return m;
    }

    // ── Listeners ─────────────────────────────────────────────────────────────

    public void addListener(Runnable cb) { listeners.add(cb); }

    private void fire() {
        for (Runnable cb : listeners) {
            try {
                // Dispatch to EDT — listeners update Swing components.
                // If already on EDT (e.g. called from UI action), run directly
                // to avoid re-entrancy via invokeLater.
                if (javax.swing.SwingUtilities.isEventDispatchThread()) {
                    cb.run();
                } else {
                    javax.swing.SwingUtilities.invokeLater(cb);
                }
            } catch (Exception ignored) {}
        }
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    public String serialize() {
        // Snapshot the finding list under lock (fast — just copies references).
        // JSON building and toString() happen outside the lock so passive scanner
        // add() calls are never blocked by a slow serialization pass.
        final List<Finding> snapshot;
        synchronized (this) {
            snapshot = new ArrayList<>(findings);
        }
        JSONObject root = new JSONObject();
        root.put("version",  2);
        root.put("saved_at", LocalDateTime.now().format(FMT));
        JSONArray arr = new JSONArray();
        for (Finding f : snapshot) arr.put(f.toJson());  // toJson reads only final/volatile fields
        root.put("findings", arr);
        return root.toString(2);
    }

    /** @return [restored, skipped] */
    public int[] deserialize(String json) {
        JSONObject root = new JSONObject(json);
        JSONArray arr = root.optJSONArray("findings");
        if (arr == null) return new int[]{0, 0};

        // Phase 1: Parse all Finding objects OUTSIDE the lock.
        // Finding.fromJson() runs Cvss4Calculator.calculate(), Base64.decode(),
        // and ArrayList operations — none of these need the store lock, and holding it
        // would block passive scanner add() calls for the entire load duration.
        List<Finding> parsed  = new ArrayList<>(arr.length());
        int skippedParse = 0;
        for (int i = 0; i < arr.length(); i++) {
            try {
                parsed.add(Finding.fromJson(arr.getJSONObject(i)));
            } catch (Exception e) {
                skippedParse++;
            }
        }

        // Phase 2: Batch-insert under lock. Only the index/list mutations need the lock.
        int restored = 0, skipped = skippedParse;
        synchronized (this) {
            int i = 0;
            for (Finding f : parsed) {
                if (findings.size() >= MAX_FINDINGS) {
                    // Account for ALL remaining unprocessed Findings, including
                    // the current one. indexOf(f) was previously used here, but
                    // it returns the FIRST occurrence on duplicates, miscounting
                    // the tail, and is O(n) on every cap-hit.
                    skipped += parsed.size() - i;
                    break;
                }
                String key = f.dedupKey();
                if (!index.containsKey(key)) {
                    index.put(key, f);
                    findings.add(f);
                    String fKey = familyKey(f);
                    boolean isActive = f.name.startsWith("[ACTIVE]");
                    if (isActive || !familyIndex.containsKey(fKey)) {
                        familyIndex.put(fKey, key);
                    }
                    restored++;
                } else {
                    skipped++;
                }
                i++;
            }
        }
        fire();
        return new int[]{restored, skipped};
    }
}
