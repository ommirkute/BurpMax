package com.burpmax.scanner;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

public class RequestChecker {
    private static final Pattern RE_BEARER_JWT = Pattern.compile(
        "Bearer\\s+(ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)",
        Pattern.CASE_INSENSITIVE);

    public static List<CheckResult> check(Map<String, String> reqHeaders) {
        List<CheckResult> results = new ArrayList<>();
        String auth = reqHeaders.getOrDefault("authorization", "");
        if (auth.isEmpty()) return results;
        Matcher m = RE_BEARER_JWT.matcher(auth);
        if (!m.find()) return results;
        String token = m.group(1);
        String[] parts = token.split("\\.");
        if (parts.length >= 2) {
            try {
                String payload = new String(Base64.getUrlDecoder().decode(padB64(parts[1])));
                List<String> piiFields = List.of("email","phone","ssn","dob","mobile","address");
                if (piiFields.stream().anyMatch(f -> payload.toLowerCase().contains(f))) {
                    results.add(new CheckResult("Sensitive Data in Authorization Bearer", SEV_HIGH,
                        "The JWT Bearer token in the Authorization header contains personally identifiable information (PII) such as email address, phone number, date of birth, or physical address in its payload claims.",
                        "JWT payload contains PII: " + trunc(payload, 120),
                        "- Remove all PII from JWT payload claims; store only opaque identifiers (user UUID, session reference)\n- If PII must be token-embedded, switch to JSON Web Encryption (JWE) to encrypt the payload\n- Set short token expiry (15-60 minutes for access tokens)",
                        "CWE-312"));
                }
            } catch (Exception ignored) {}
        }
        if (parts.length >= 1) {
            try {
                String header = new String(Base64.getUrlDecoder().decode(padB64(parts[0])));
                if (header.contains("\"alg\"") && header.toLowerCase().contains("\"none\"")) {
                    results.add(new CheckResult("JWT Algorithm Set to None", SEV_CRITICAL,
                        "The JWT token being transmitted uses alg=none in its JOSE header. Libraries that accept this value will validate any token as authentic regardless of its payload content.",
                        "JWT header alg=none detected in Authorization header.",
                        "- Explicitly specify and enforce the accepted algorithm(s) in your JWT library verify call\n- Reject any token where the alg header does not match your expected algorithm\n- Prefer asymmetric algorithms (RS256, ES256)",
                        "CWE-327"));
                }
            } catch (Exception ignored) {}
        }
        return results;
    }

    private static String padB64(String s) {
        return s + "=".repeat((4 - s.length() % 4) % 4);
    }
}
