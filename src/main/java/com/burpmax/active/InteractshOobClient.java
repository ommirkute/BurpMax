package com.burpmax.active;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * OOB client backed by an interactsh server.
 *
 * Protocol overview
 * ─────────────────
 * interactsh uses a register/poll REST API over HTTPS:
 *
 *  1. POST /register
 *     Body: {"public-key": "<RSA-2048 pub key PEM>", "secret-key": "<UUID>", "correlation-id": "<9-char ID>"}
 *     The server will use the public key to encrypt any interaction payloads it sends back.
 *
 *  2. GET /poll?id=<correlation-id>&secret=<secret-key>
 *     Returns: {"data": ["<base64-RSA-encrypted AES key>|<base64-AES-encrypted JSON>", ...], "aes_key": "..."}
 *     Each element in data[] is one interaction.
 *
 *  3. Subdomains: <unique-id>.<correlation-id>.<server-domain>
 *     The unique-id portion is what distinguishes individual injection points.
 *
 * Encryption
 * ──────────
 * interactsh encrypts interactions so the server cannot read probe results
 * (privacy model). Each interaction is wrapped:
 *   - AES-256-CFB key encrypted with our RSA-2048 public key
 *   - Interaction JSON encrypted with the AES key
 * We decrypt on the client side.
 *
 * Public servers (no auth required):
 *   oast.pro, oast.live, oast.site, oast.online, oast.fun
 *
 * Self-hosted: any interactsh-server instance behind HTTPS.
 *
 * Fallback (no crypto available): the client falls back to a no-encryption
 * registration which some older/self-hosted servers support; interactions
 * arrive as plaintext JSON. This covers most corporate lab deployments.
 */
public class InteractshOobClient implements OobClient {

    // ── Configuration ──────────────────────────────────────────────────────────
    private final String serverUrl;       // e.g. "https://oast.pro"
    private final int    pollDelayMs;     // wait before polling (DNS TTL propagation)
    private final int    pollTimeoutMs;   // HTTP timeout for poll request

    // ── Session state ──────────────────────────────────────────────────────────
    private final String correlationId;   // 9-char alphanum, part of every subdomain
    private final String secretKey;       // UUID, used as poll auth token
    private final String serverDomain;    // e.g. "oast.pro" (extracted from serverUrl)

    private KeyPair     rsaKeyPair;
    private boolean     registered = false;
    private boolean     available  = false;

    // ── Injection tracking ────────────────────────────────────────────────────
    // Maps unique-id portion of subdomain → injection metadata
    // ConcurrentHashMap: generateHost() and recordInjection() are called concurrently
    // from multiple probe threads; LinkedHashMap is not thread-safe for concurrent writes.
    private final Map<String, InjectionRecord> injections = new java.util.concurrent.ConcurrentHashMap<>();

    // ── Constants ─────────────────────────────────────────────────────────────
    private static final int CORR_ID_LEN   = 9;
    private static final int UNIQUE_ID_LEN = 13;

    public InteractshOobClient(String serverUrl, int pollDelayMs) {
        this.serverUrl    = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        this.pollDelayMs  = pollDelayMs;
        this.pollTimeoutMs = 15_000;
        this.correlationId = randomAlphaNum(CORR_ID_LEN);
        this.secretKey     = UUID.randomUUID().toString();
        this.serverDomain  = extractDomain(serverUrl);

        try {
            rsaKeyPair = generateRsaKeyPair();
        } catch (Exception e) {
            rsaKeyPair = null;  // will fall back to unencrypted registration
        }

        register();
    }

    // ── OobClient interface ────────────────────────────────────────────────────

    @Override
    public boolean isAvailable() { return available; }

    @Override
    public String generateHost(String label) {
        if (!available) return null;
        String uniqueId = randomAlphaNum(UNIQUE_ID_LEN);
        // subdomain format: <uniqueId>.<correlationId>.<serverDomain>
        return uniqueId + "." + correlationId + "." + serverDomain;
    }

    @Override
    public void recordInjection(String oobHost, String probeName,
                                 String endpoint, String parameter, String payload,
                                 byte[] probeRequestBytes) {
        if (oobHost == null) return;
        String uniqueId = oobHost.split("\\.")[0];
        injections.put(uniqueId, new InjectionRecord(probeName, endpoint, parameter,
                                                      payload, probeRequestBytes));
    }

    @Override
    public List<OobHit> pollAndMatch() {
        List<OobHit> hits = new ArrayList<>();
        if (!available || injections.isEmpty()) return hits;

        // Note: the poll wait (DNS TTL propagation delay) is now handled externally
        // by ActiveScanner in cancel-aware 500ms chunks. This method fetches
        // interactions immediately when called.
        try {
            List<String> interactions = fetchInteractions();
            for (String interactionJson : interactions) {
                OobHit hit = parseInteraction(interactionJson);
                if (hit != null) hits.add(hit);
            }
        } catch (Exception ignored) {}

        return hits;
    }

    @Override
    public void close() {
        // No persistent connection to close for HTTP polling
    }

    // ── Registration ──────────────────────────────────────────────────────────

    private void register() {
        try {
            String pubKeyPem = rsaKeyPair != null ? encodePem(rsaKeyPair.getPublic().getEncoded()) : "";
            String body = "{\"public-key\":\"" + pubKeyPem
                    + "\",\"secret-key\":\"" + secretKey
                    + "\",\"correlation-id\":\"" + correlationId + "\"}";

            int status = httpPost(serverUrl + "/register", body);
            available = (status == 200);
        } catch (Exception e) {
            available = false;
        }
    }

    // ── Poll ──────────────────────────────────────────────────────────────────

    private List<String> fetchInteractions() throws Exception {
        String url = serverUrl + "/poll?id=" + correlationId + "&secret=" + secretKey;
        String response = httpGet(url, pollTimeoutMs);
        if (response == null || response.isEmpty()) return List.of();

        // Parse the data array from the JSON response
        // Response format: {"data":["item1","item2",...],"aes_key":"...","extra":"..."}
        // We do minimal parsing — no library dependency
        List<String> items = new ArrayList<>();

        int aesKeyStart = response.indexOf("\"aes_key\"");
        String aesKeyB64 = null;
        if (aesKeyStart >= 0) {
            int colon = response.indexOf(':', aesKeyStart);
            int q1    = response.indexOf('"', colon);
            int q2    = response.indexOf('"', q1 + 1);
            if (q1 >= 0 && q2 > q1) aesKeyB64 = response.substring(q1 + 1, q2);
        }

        int dataStart = response.indexOf("\"data\"");
        if (dataStart < 0) return items;
        int arrStart = response.indexOf('[', dataStart);
        int arrEnd   = response.indexOf(']', arrStart);
        if (arrStart < 0 || arrEnd < 0) return items;

        String arr = response.substring(arrStart + 1, arrEnd);
        // Split on "," boundaries between quoted strings
        int i = 0;
        while (i < arr.length()) {
            int q1 = arr.indexOf('"', i);
            if (q1 < 0) break;
            int q2 = findClosingQuote(arr, q1 + 1);
            if (q2 < 0) break;
            String encoded = arr.substring(q1 + 1, q2);
            String decoded = decodeInteraction(encoded, aesKeyB64);
            if (decoded != null) items.add(decoded);
            i = q2 + 1;
        }
        return items;
    }

    // ── Decryption ────────────────────────────────────────────────────────────

    /**
     * Decrypt an interaction payload.
     * Format: "<base64-RSA-encrypted-AES-key>|<base64-AES-CFB-encrypted-JSON>"
     * If rsaKeyPair is null (no crypto), tries to base64-decode as plaintext JSON.
     */
    private String decodeInteraction(String encoded, String fallbackAesKeyB64) {
        try {
            int pipe = encoded.indexOf('|');
            if (pipe < 0) {
                // No pipe — try plain base64 JSON (some servers send unencrypted)
                return new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            }

            if (rsaKeyPair == null) return null;  // can't decrypt without key

            byte[] encryptedAesKey = Base64.getDecoder().decode(encoded.substring(0, pipe));
            byte[] encryptedData   = Base64.getDecoder().decode(encoded.substring(pipe + 1));

            // Decrypt AES key with RSA private key (OAEP)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);

            // Decrypt data with AES-256-CFB
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            // First 16 bytes of encryptedData are the IV
            byte[] iv   = Arrays.copyOfRange(encryptedData, 0, 16);
            byte[] data = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);
            Cipher aesCipher = Cipher.getInstance("AES/CFB/NoPadding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));

            return new String(aesCipher.doFinal(data), StandardCharsets.UTF_8);

        } catch (Exception e) {
            return null;
        }
    }

    // ── Interaction parsing ───────────────────────────────────────────────────

    /**
     * Parse a decrypted interaction JSON and match it to a recorded injection.
     * Interaction JSON example:
     *   {"protocol":"dns","unique-id":"abc123xyz","q-type":"A","raw-request":"...","timestamp":"..."}
     */
    private OobHit parseInteraction(String json) {
        if (json == null || json.isEmpty()) return null;

        String uniqueId = jsonField(json, "unique-id");
        if (uniqueId == null) return null;

        // The unique-id in the interaction is the first label of the triggered subdomain
        // Strip the correlation-id suffix if present
        String shortId = uniqueId.contains(".") ? uniqueId.split("\\.")[0] : uniqueId;

        InjectionRecord rec = injections.get(shortId);
        if (rec == null) return null;  // interaction not from this scan

        String protocol = jsonField(json, "protocol");
        String detail;
        if ("dns".equals(protocol)) {
            String qType = jsonField(json, "q-type");
            detail = "DNS " + (qType != null ? qType : "query") + " for " + uniqueId;
        } else if ("http".equals(protocol)) {
            String method = jsonField(json, "raw-request");
            detail = "HTTP callback" + (method != null ? ": " + method.substring(0, Math.min(60, method.length())) : "");
        } else {
            detail = protocol != null ? protocol + " interaction" : "interaction";
        }

        return new OobHit(rec.probeName, rec.endpoint, rec.parameter, rec.payload, protocol, detail,
                rec.probeRequestBytes());
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private int httpPost(String url, String body) throws Exception {
        HttpURLConnection conn = openConnection(url);
        try {
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("User-Agent", "BurpMax/1.0");
            conn.setConnectTimeout(8_000);
            conn.setReadTimeout(8_000);
            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));
            try (OutputStream os = conn.getOutputStream()) { os.write(bodyBytes); }
            return conn.getResponseCode();
        } finally {
            conn.disconnect();   // always release the connection, even on exception
        }
    }

    private String httpGet(String url, int timeoutMs) throws Exception {
        HttpURLConnection conn = openConnection(url);
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "BurpMax/1.0");
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            int status = conn.getResponseCode();
            if (status != 200) return null;   // disconnect handled by finally
            try (InputStream is = conn.getInputStream();
                 ByteArrayOutputStream buf = new ByteArrayOutputStream()) {
                // Cap response size: a malicious/compromised interactsh server could
                // send an arbitrarily large poll response, causing OOM in the Burp JVM.
                final int MAX_POLL_BYTES = 5 * 1024 * 1024;  // 5 MB hard limit
                byte[] chunk = new byte[4096];
                int n;
                while ((n = is.read(chunk)) > 0) {
                    buf.write(chunk, 0, n);
                    if (buf.size() > MAX_POLL_BYTES) {
                        throw new IOException("Poll response exceeds 5 MB size limit");
                    }
                }
                return buf.toString(StandardCharsets.UTF_8);
            }
        } finally {
            conn.disconnect();   // always release the connection, even on non-200 / exception
        }
    }

    private HttpURLConnection openConnection(String url) throws Exception {
        return (HttpURLConnection) new URL(url).openConnection();
    }

    // ── Crypto helpers ────────────────────────────────────────────────────────

    private KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private String encodePem(byte[] keyBytes) {
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    // ── JSON mini-parser (no library dep) ────────────────────────────────────

    private String jsonField(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = findClosingQuote(json, q1 + 1);
        if (q2 < 0) return null;
        return json.substring(q1 + 1, q2);
    }

    /** Find the closing '"' of a JSON string, honouring backslash escapes. */
    private static int findClosingQuote(String s, int start) {
        for (int i = start; i < s.length(); i++) {
            if (s.charAt(i) == '\\') { i++; continue; }
            if (s.charAt(i) == '"')  return i;
        }
        return -1;
    }

    // ── Misc helpers ──────────────────────────────────────────────────────────

    private static String randomAlphaNum(int len) {
        // Must use SecureRandom — correlationId and uniqueId are session identifiers
        // used to claim OOB callbacks. java.util.Random is a linear congruential
        // generator; an observer of a few generated IDs can predict future ones,
        // enabling a hostile server to pre-register interactions for our session.
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        java.security.SecureRandom rng = new java.security.SecureRandom();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(chars.charAt(rng.nextInt(chars.length())));
        return sb.toString();
    }

    private static String extractDomain(String url) {
        try {
            String host = new URL(url).getHost();
            return host;
        } catch (Exception e) {
            return url.replaceFirst("https?://", "").split("/")[0];
        }
    }

    // ── Inner record ──────────────────────────────────────────────────────────

    private record InjectionRecord(String probeName, String endpoint,
                                    String parameter, String payload,
                                    byte[] probeRequestBytes) {}
}
