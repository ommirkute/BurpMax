package com.burpmax.active;

import burp.IBurpExtenderCallbacks;
import java.lang.reflect.*;
import java.util.*;

/**
 * OOB client backed by Burp Collaborator (Burp Suite Pro only).
 *
 * Uses reflection against IBurpExtenderCallbacks to avoid a hard compile-time
 * dependency on the Collaborator API methods that only exist in Pro. If the
 * methods are absent (Community Edition), isAvailable() returns false and the
 * OOB system transparently falls back to InteractshOobClient.
 *
 * Collaborator API (accessed via reflection):
 *   IBurpExtenderCallbacks.createBurpCollaboratorClientContext()
 *     → IBurpCollaboratorClientContext
 *       .generatePayload(boolean includeCollaboratorServerLocation) → String
 *       .fetchAllCollaboratorInteractions()
 *         → IBurpCollaboratorInteraction[]
 *           .getProperty(String name) → String
 *             properties: "type", "interaction_id", "client_ip",
 *                         "time_stamp", "query_type" (DNS), "request" (HTTP)
 */
public class CollaboratorOobClient implements OobClient {

    private final Object  clientContext;   // IBurpCollaboratorClientContext (via reflection)
    private final boolean available;

    // Maps interaction_id → injection metadata
    private final Map<String, InjectionRecord> injections = new LinkedHashMap<>();

    public CollaboratorOobClient(IBurpExtenderCallbacks callbacks) {
        Object ctx  = null;
        boolean ok  = false;
        try {
            Method create = callbacks.getClass()
                    .getMethod("createBurpCollaboratorClientContext");
            ctx = create.invoke(callbacks);
            ok  = ctx != null;
        } catch (Exception ignored) {
            // Method absent (Community Edition) or invocation failed
        }
        this.clientContext = ctx;
        this.available     = ok;
    }

    // ── OobClient interface ────────────────────────────────────────────────────

    @Override
    public boolean isAvailable() { return available; }

    @Override
    public String generateHost(String label) {
        if (!available) return null;
        try {
            Method gen = clientContext.getClass()
                    .getMethod("generatePayload", boolean.class);
            Object result = gen.invoke(clientContext, true);
            return result != null ? result.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void recordInjection(String oobHost, String probeName,
                                 String endpoint, String parameter, String payload,
                                 byte[] probeRequestBytes) {
        if (oobHost == null) return;
        String id = oobHost.endsWith(".") ? oobHost.substring(0, oobHost.length() - 1) : oobHost;
        injections.put(id, new InjectionRecord(probeName, endpoint, parameter, payload,
                                                probeRequestBytes));
    }

    @Override
    public List<OobHit> pollAndMatch() {
        List<OobHit> hits = new ArrayList<>();
        if (!available || injections.isEmpty()) return hits;

        try {
            Method fetch = clientContext.getClass()
                    .getMethod("fetchAllCollaboratorInteractions");
            Object[] interactions = (Object[]) fetch.invoke(clientContext);
            if (interactions == null) return hits;

            for (Object interaction : interactions) {
                OobHit hit = parseInteraction(interaction);
                if (hit != null) hits.add(hit);
            }
        } catch (Exception ignored) {}

        return hits;
    }

    @Override
    public void close() { /* no resources to release */ }

    // ── Interaction parsing ───────────────────────────────────────────────────

    private OobHit parseInteraction(Object interaction) {
        try {
            Method getProp = interaction.getClass().getMethod("getProperty", String.class);
            String type   = (String) getProp.invoke(interaction, "type");
            String id     = (String) getProp.invoke(interaction, "interaction_id");
            if (id == null) return null;

            // Match against recorded injections — Collaborator IDs are substrings of the payload
            InjectionRecord rec = findBySubstring(id);
            if (rec == null) return null;

            String detail;
            if ("dns".equalsIgnoreCase(type)) {
                String qType = (String) getProp.invoke(interaction, "query_type");
                detail = "DNS " + (qType != null ? qType : "query");
            } else if ("http".equalsIgnoreCase(type)) {
                String req = (String) getProp.invoke(interaction, "request");
                detail = "HTTP callback" + (req != null ? ": " + req.substring(0, Math.min(60, req.length())) : "");
            } else {
                detail = type != null ? type + " interaction" : "unknown interaction";
            }

            return new OobHit(rec.probeName, rec.endpoint, rec.parameter, rec.payload, type, detail,
                    rec.probeRequestBytes());
        } catch (Exception e) {
            return null;
        }
    }

    private InjectionRecord findBySubstring(String interactionId) {
        // Prefer exact match: Collaborator interaction_id is unique per payload,
        // so exact equality is the correct and safe comparison.
        // The old bidirectional substring check could attribute a callback to the
        // wrong injection point if one recorded ID is a prefix of another.
        InjectionRecord exact = injections.get(interactionId);
        if (exact != null) return exact;
        // Fallback: Collaborator sometimes returns a truncated ID — check if the
        // interaction_id is a suffix of any recorded key (Collaborator payload format).
        for (Map.Entry<String, InjectionRecord> e : injections.entrySet()) {
            String key = e.getKey();
            // Only accept if the interaction_id is a suffix of the full payload host,
            // not if the recorded key is contained within the interaction_id.
            if (key.endsWith(interactionId) || key.equals(interactionId)) {
                return e.getValue();
            }
        }
        return null;
    }

    private record InjectionRecord(String probeName, String endpoint,
                                    String parameter, String payload,
                                    byte[] probeRequestBytes) {}
}
