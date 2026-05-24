package com.burpmax.export;

import com.burpmax.model.Finding;
import com.burpmax.store.FindingStore;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Compares the current finding store against a saved baseline session file
 * and produces a diff result tagging each finding as:
 *
 *   NEW       — present in current scan, absent from baseline
 *   EXISTING  — present in both (same dedup key)
 *   RESOLVED  — present in baseline, absent from current scan
 *
 * Usage:
 *   ScanDiff.Result diff = ScanDiff.compare(store, "/path/to/baseline.json");
 *   diff.newFindings()      → List<Finding>
 *   diff.existingFindings() → List<Finding>
 *   diff.resolvedCount()    → int
 *   diff.summary()          → "3 new, 12 existing, 2 resolved"
 *
 * The diff is computed on Finding.dedupKey() (host + "|" + name) so it is
 * stable across scan runs even if endpoint URLs differ slightly.
 */
public class ScanDiff {

    // ── Result value object ───────────────────────────────────────────────────

    public static class Result {
        private final List<Finding> newFindings;
        private final List<Finding> existingFindings;
        private final List<String>  resolvedKeys;     // dedup keys of resolved findings
        private final List<String>  resolvedNames;    // human-readable names

        Result(List<Finding> newFindings, List<Finding> existingFindings,
               List<String> resolvedKeys, List<String> resolvedNames) {
            this.newFindings      = Collections.unmodifiableList(newFindings);
            this.existingFindings = Collections.unmodifiableList(existingFindings);
            this.resolvedKeys     = Collections.unmodifiableList(resolvedKeys);
            this.resolvedNames    = Collections.unmodifiableList(resolvedNames);
        }

        public List<Finding> newFindings()      { return newFindings; }
        public List<Finding> existingFindings() { return existingFindings; }
        public int           resolvedCount()    { return resolvedKeys.size(); }
        public List<String>  resolvedNames()    { return resolvedNames; }

        public String summary() {
            return newFindings.size() + " new, " +
                   existingFindings.size() + " existing, " +
                   resolvedKeys.size() + " resolved";
        }

        public boolean hasChanges() {
            return !newFindings.isEmpty() || !resolvedKeys.isEmpty();
        }

        /** All current findings tagged with their diff status. */
        public List<TaggedFinding> tagged() {
            List<TaggedFinding> out = new ArrayList<>();
            for (Finding f : newFindings)      out.add(new TaggedFinding(f, "NEW"));
            for (Finding f : existingFindings) out.add(new TaggedFinding(f, "EXISTING"));
            return out;
        }
    }

    public record TaggedFinding(Finding finding, String status) {}

    // ── Compare ───────────────────────────────────────────────────────────────

    /**
     * Compare current store against a baseline session file.
     *
     * @param current      the live FindingStore
     * @param baselinePath path to a previously saved .json session file
     * @return             diff result
     * @throws Exception   if the baseline file cannot be read or parsed
     */
    public static Result compare(FindingStore current, String baselinePath) throws Exception {
        // Load baseline findings
        Set<String> baselineKeys   = new LinkedHashSet<>();
        Map<String, String> baselineNames = new LinkedHashMap<>(); // key → name
        loadBaseline(baselinePath, baselineKeys, baselineNames);

        // Current findings
        List<Finding> currentAll = current.getAll();
        Set<String>   currentKeys = new LinkedHashSet<>();
        for (Finding f : currentAll) currentKeys.add(f.dedupKey());

        // Classify
        List<Finding> newFindings      = new ArrayList<>();
        List<Finding> existingFindings = new ArrayList<>();
        for (Finding f : currentAll) {
            if (baselineKeys.contains(f.dedupKey())) existingFindings.add(f);
            else                                      newFindings.add(f);
        }

        // Resolved = in baseline but not in current
        List<String> resolvedKeys  = new ArrayList<>();
        List<String> resolvedNames = new ArrayList<>();
        for (String key : baselineKeys) {
            if (!currentKeys.contains(key)) {
                resolvedKeys.add(key);
                resolvedNames.add(baselineNames.getOrDefault(key, key));
            }
        }

        return new Result(newFindings, existingFindings, resolvedKeys, resolvedNames);
    }

    // ── Baseline loading ──────────────────────────────────────────────────────

    /**
     * Load finding dedup keys and names from a session JSON file.
     * Uses minimal parsing to avoid a full FindingStore deserialisation
     * (which would fire listeners and mutate state).
     */
    private static void loadBaseline(String path,
                                      Set<String> keys,
                                      Map<String, String> names) throws Exception {
        File f = new File(path);
        if (!f.exists())  throw new FileNotFoundException("Baseline not found: " + path);
        if (f.length() > 50 * 1024 * 1024L)
            throw new IOException("Baseline file too large (max 50 MB)");

        String json;
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
            json = sb.toString();
        }

        // Parse using the org.json stubs available at runtime (Burp bundles org.json)
        try {
            org.json.JSONObject root = new org.json.JSONObject(json);
            org.json.JSONArray  arr  = root.optJSONArray("findings");
            if (arr == null) return;
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject obj = arr.optJSONObject(i);
                if (obj == null) continue;
                String name     = obj.optString("name",     "");
                String host     = obj.optString("host",     "");
                String endpoint = obj.optString("endpoint", "");
                if (name.isBlank() || host.isBlank()) continue;
                // Mirror Finding.dedupKey() exactly:
                //   Active findings ([ACTIVE] prefix): host|name|endpoint
                //   Passive findings:                  host|name
                // Previously used endpoint for all findings, causing passive baseline
                // findings to never match current scan and appear as RESOLVED every run.
                boolean isActive = name.startsWith("[ACTIVE]");
                String key = isActive
                        ? host + "|" + name + "|" + endpoint
                        : host + "|" + name;
                keys.add(key);
                names.put(key, name);
            }
        } catch (Exception e) {
            throw new IOException("Could not parse baseline session file: " + e.getMessage(), e);
        }
    }
}
