package com.burpmax.scanner;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

/**
 * Checks JSON/API response bodies for:
 *  - Sensitive fields (password hashes, SSN, credit cards, PII) returned in responses
 *  - Stack traces in JSON error responses
 *  - Debug mode active in production
 */
public class ApiResponseChecker {

    // ── Sensitive field names that should never appear as JSON keys in responses ──
    // These are response-body keys — password in a LOGIN REQUEST is fine,
    // password in a GET /users/123 RESPONSE is a critical finding.
    private static final Set<String> CREDENTIAL_KEYS = Set.of(
            "password", "passwd", "pass", "pwd",
            "password_hash", "hashed_password", "password_digest",
            "secret", "secret_key", "api_secret",
            "private_key", "client_secret",
            "access_token", "refresh_token", "id_token",
            "session_token", "auth_token", "bearer_token",
            "two_factor_secret", "totp_secret", "mfa_secret",
            "recovery_code", "backup_code"
    );

    private static final Set<String> PII_KEYS = Set.of(
            "ssn", "social_security_number", "social_security",
            "tax_id", "taxpayer_id", "national_id",
            "credit_card", "credit_card_number", "card_number",
            "card_no", "pan", "cvv", "cvc", "cvv2",
            "date_of_birth", "dob", "birth_date", "birthdate",
            "passport_number", "passport_no",
            "drivers_license", "driver_license", "dl_number",
            "bank_account", "account_number", "routing_number",
            "iban", "swift_code"
    );

    // JSON key pattern: "key": "value" or "key":"value" (non-null, non-empty value)
    private static final Pattern RE_JSON_KEY_VALUE = Pattern.compile(
            "\"([a-z_][a-z0-9_]*)\"\\s*:\\s*\"([^\"]{1,500})\"",
            Pattern.CASE_INSENSITIVE);

    // Also match numeric values for card numbers / SSNs
    private static final Pattern RE_JSON_KEY_NUM = Pattern.compile(
            "\"([a-z_][a-z0-9_]*)\"\\s*:\\s*(\\d[\\d\\- ]{5,25})",
            Pattern.CASE_INSENSITIVE);

    // Credit card: Visa/MC/Amex/Discover — matches both contiguous and space/dash-formatted
    // The luhnCheck() call strips spaces/dashes before validation, so we normalise here too
    private static final Pattern RE_CREDIT_CARD = Pattern.compile(
            "\\b(?:4[0-9]{3}[\\s\\-]?[0-9]{4}[\\s\\-]?[0-9]{4}[\\s\\-]?[0-9]{4}|"  // Visa 16
            + "4[0-9]{12}(?:[0-9]{3})?|"                                               // Visa 13/16 no sep
            + "5[1-5][0-9]{2}[\\s\\-]?[0-9]{4}[\\s\\-]?[0-9]{4}[\\s\\-]?[0-9]{4}|" // MC with sep
            + "5[1-5][0-9]{14}|"                                                       // MC no sep
            + "3[47][0-9]{2}[\\s\\-]?[0-9]{6}[\\s\\-]?[0-9]{5}|"                    // Amex with sep
            + "3[47][0-9]{13}|"                                                        // Amex no sep
            + "6(?:011|5[0-9]{2})[\\s\\-]?[0-9]{4}[\\s\\-]?[0-9]{4}[\\s\\-]?[0-9]{4}|" // Discover sep
            + "6(?:011|5[0-9]{2})[0-9]{12})\\b");                                     // Discover no sep

    // SSN: 3-2-4 format
    private static final Pattern RE_SSN = Pattern.compile(
            "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}\\b");

    // Stack trace / debug keys in JSON
    private static final Pattern RE_STACK_KEY = Pattern.compile(
            "\"(?:stackTrace|stack_trace|stacktrace|backtrace|" +
            "exception|exceptionMessage|errorDetail|lineNumber|" +
            "fileName|className|methodName|javaClass)\"\\s*:",
            Pattern.CASE_INSENSITIVE);

    // Debug/dev mode flags in JSON
    private static final Pattern RE_DEBUG_FLAG = Pattern.compile(
            "\"(?:debug|is_debug|dev_mode|development_mode|" +
            "environment|env)\"\\s*:\\s*(?:true|\"(?:development|dev|debug)\")",
            Pattern.CASE_INSENSITIVE);

    public static List<CheckResult> check(String body, String contentType) {
        return check(body, contentType, 200);
    }

    public static List<CheckResult> check(String body, String contentType, int statusCode) {
        List<CheckResult> results = new ArrayList<>();
        if (body == null || body.isEmpty()) return results;

        boolean isJson = contentType != null &&
                (contentType.toLowerCase().contains("application/json") ||
                 contentType.toLowerCase().contains("application/ld+json") ||
                 contentType.toLowerCase().contains("application/vnd.api+json"));

        // ── Sensitive fields in JSON response ────────────────────────────────
        if (isJson) {
            // Check string-valued keys
            Matcher m = RE_JSON_KEY_VALUE.matcher(body);
            Set<String> firedCred = new HashSet<>();
            Set<String> firedPii  = new HashSet<>();

            while (m.find()) {
                String key   = m.group(1).toLowerCase();
                String value = m.group(2);

                // Skip null-like, empty, placeholder values
                if (isPlaceholder(value)) continue;

                if (CREDENTIAL_KEYS.contains(key) && !firedCred.contains(key)) {
                    // Token-type keys require value to look like a real token:
                    // - JWT (starts ey...) OR
                    // - >=32 chars of high-entropy (hex/base64 charset)
                    // Short/obvious values like "csrf-token-abc" are not credential material.
                    boolean isTokenKey = key.contains("token") || key.contains("secret")
                            || key.contains("key");
                    boolean looksLikeToken = value.startsWith("ey")   // JWT
                            || (value.length() >= 32
                                && value.matches("[A-Za-z0-9+/=_-]{32,}"));
                    if (isTokenKey && !looksLikeToken) continue;

                    // On 4xx responses the value may be an echoed request field (validation error).
                    // Downgrade severity rather than suppress so it is still reported.
                    String credSev = (statusCode >= 400 && statusCode < 500) ? SEV_MEDIUM : SEV_HIGH;
                    String echoNote = (statusCode >= 400 && statusCode < 500)
                        ? " (detected on " + statusCode + " response - may be echoed request field; verify)" : "";

                    firedCred.add(key);
                    String masked = value.length() > 4
                            ? value.substring(0, 4) + "****" : "****";
                    results.add(new CheckResult(
                        "Sensitive Credential Field in API Response", credSev,
                        "The API response contains a field named '" + key + "' with a non-empty value. " +
                        "Returning credential, token, or secret fields in API responses violates the " +
                        "principle of least disclosure and can expose authentication material to any " +
                        "party that intercepts or logs the response." + echoNote,
                        "Field: \"" + key + "\": \"" + masked + "...\" found in " + contentType + " response [HTTP " + statusCode + "]",
                        "- Never include password, hash, secret, or token fields in API responses\n" +
                        "- Use response DTOs/serializers that explicitly whitelist returnable fields\n" +
                        "- Audit all /users, /accounts, /profile endpoints for credential field leakage\n" +
                        "- Add automated tests asserting credential fields are absent from API responses",
                        "CWE-312"));
                }

                if (PII_KEYS.contains(key) && !firedPii.contains(key)) {
                    firedPii.add(key);
                    String masked = value.length() > 4
                            ? value.substring(0, 2) + "****" + value.substring(value.length() - 2) : "****";
                    results.add(new CheckResult(
                        "Sensitive PII Field in API Response", SEV_HIGH,
                        "The API response contains a field named '" + key + "' which typically holds " +
                        "personally identifiable information (PII) such as SSN, credit card number, or " +
                        "government ID. Exposure of this data in API responses violates data minimisation " +
                        "requirements under GDPR, PCI-DSS, and similar frameworks.",
                        "Field: \"" + key + "\": \"" + masked + "\" found in response",
                        "- Remove or mask PII fields from API responses - return only what the client needs\n" +
                        "- Use response field whitelisting (DTOs) rather than serialising full model objects\n" +
                        "- Apply field-level encryption for PII at rest; never return raw PII in APIs\n" +
                        "- Review compliance obligations (GDPR Art. 5, PCI-DSS Req. 3) for data minimisation",
                        "CWE-359"));
                }

                if (firedCred.size() + firedPii.size() >= 3) break; // cap per response
            }

            // Check numeric keys for card numbers / SSNs
            Matcher mn = RE_JSON_KEY_NUM.matcher(body);
            while (mn.find()) {
                if (firedCred.size() + firedPii.size() >= 3) break;   // cap
                String key = mn.group(1).toLowerCase();
                if ((PII_KEYS.contains(key) || key.contains("card") || key.contains("ssn"))
                        && !firedPii.contains(key)) {
                    firedPii.add(key);
                    results.add(new CheckResult(
                        "Sensitive PII Field in API Response", SEV_HIGH,
                        "The API response contains a numeric field named '" + key + "' which may hold " +
                        "a credit card number, SSN, or other sensitive numeric identifier.",
                        "Field: \"" + key + "\": [numeric value] found in response",
                        "- Remove or mask PII fields from API responses\n" +
                        "- Never return raw card numbers or SSNs - return masked versions (e.g., last 4 digits only)",
                        "CWE-359"));
                }
            }

            // Stack trace in JSON error response
            Matcher mStack = RE_STACK_KEY.matcher(body);
            if (mStack.find()) {
                String matchedKey = mStack.group();   // reuse - no second Matcher needed
                results.add(new CheckResult(
                    "Stack Trace Exposed in JSON API Response", SEV_MEDIUM,
                    "The JSON API response contains fields that indicate a server-side stack trace, " +
                    "exception details, or debug information (e.g. stackTrace, exception, lineNumber). " +
                    "This reveals internal class names, file system paths, framework versions, and " +
                    "line numbers that help attackers identify and exploit specific vulnerabilities.",
                    "Stack trace / debug field detected in JSON response: " + trunc(matchedKey, 100),
                    "- Implement a global exception handler that returns a generic error structure\n" +
                    "- Never include exception objects, stack traces, or file paths in API responses\n" +
                    "- Return only an error code and user-safe message: {\"error\":\"INTERNAL_ERROR\"}\n" +
                    "- Log full exception details server-side only using a structured logging framework",
                    "CWE-209"));
            }

            // Debug mode active — skip diagnostic-only endpoints and non-200 responses.
            // Health/metrics endpoints intentionally expose env metadata for monitoring systems.
            if (RE_DEBUG_FLAG.matcher(body).find() && statusCode == 200) {
                // Classify endpoint: diagnostic paths get lower severity
                String urlLower2 = ""; // contentType is in scope; derive from evidence context
                // We don't have URL here — use content signals only.
                // If response also contains stack-trace keys it's a genuine debug leak at higher sev.
                boolean hasStackToo = RE_STACK_KEY.matcher(body).find();
                String dbgSev = hasStackToo ? SEV_HIGH : SEV_MEDIUM;
                results.add(new CheckResult(
                    "Debug Mode Active in Production Response", dbgSev,
                    "The API response contains a field indicating the application is running in " +
                    "debug or development mode (e.g. \"debug\":true, \"env\":\"development\"). " +
                    "Debug mode typically enables verbose error output, disables security controls, " +
                    "and exposes internal diagnostics endpoints.",
                    "Debug/dev mode flag detected in JSON response body",
                    "- Set NODE_ENV=production, RAILS_ENV=production, DJANGO_DEBUG=False before deployment\n" +
                    "- Remove debug flags from all API responses in production builds\n" +
                    "- Use environment-specific configuration files and never commit debug=true to production",
                    "CWE-94"));
            }
        }

        // ── Credit card pattern — applies across all content types ────────────
        // Only run on non-JS, non-CSS responses to avoid false positives on test data in source
        boolean isSourceCode = contentType != null &&
                (contentType.contains("javascript") || contentType.contains("css") ||
                 contentType.contains("text/plain"));
        if (!isSourceCode) {
            Matcher mc = RE_CREDIT_CARD.matcher(body);
            if (mc.find()) {
                String matched = mc.group();
                if (luhnCheck(matched.replaceAll("[ \\-]", ""))) {
                    results.add(new CheckResult(
                        "Credit Card Number (PAN) Exposed in Response", SEV_CRITICAL,
                        "A Luhn-valid credit card Primary Account Number (PAN) was detected in the " +
                        "HTTP response. Exposure of PANs violates PCI-DSS Requirement 3.3 which " +
                        "mandates that PANs must be masked when displayed and never stored or " +
                        "transmitted beyond what is necessary.",
                        "Luhn-valid PAN detected: " + mask(matched),
                        "- Never return full PANs in API responses - return only the last 4 digits\n" +
                        "- Apply PCI-DSS tokenisation: store and transmit tokens, not raw PANs\n" +
                        "- Immediately notify your PCI-DSS QSA if raw PANs are confirmed in transit\n" +
                        "- Implement DLP scanning on all outbound API responses in your WAF",
                        "CWE-359"));
                }
            }

            // SSN
            Matcher ms = RE_SSN.matcher(body);
            if (ms.find()) {
                results.add(new CheckResult(
                    "Social Security Number (SSN) Exposed in Response", SEV_CRITICAL,
                    "A US Social Security Number matching the 3-2-4 digit format was detected in " +
                    "the HTTP response. SSN exposure constitutes a serious privacy violation and " +
                    "likely triggers breach notification obligations under state laws and GDPR.",
                    "SSN pattern detected: " + ms.group().replaceAll("\\d", "*").replaceFirst("\\*\\*\\*", ms.group().substring(0, 3)),
                    "- Never return full SSNs in API responses - return masked versions (***-**-1234)\n" +
                    "- Apply field-level encryption for SSNs at rest\n" +
                    "- Review your data breach notification obligations immediately",
                    "CWE-359"));
            }
        }

        return results;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean isPlaceholder(String v) {
        if (v == null || v.isEmpty()) return true;
        String lower = v.toLowerCase();
        return lower.equals("null") || lower.equals("undefined") || lower.equals("n/a")
                || lower.equals("") || lower.startsWith("****") || lower.equals("hidden")
                || lower.equals("redacted") || lower.equals("changeme")
                || lower.equals("password") || lower.equals("secret")
                || lower.equals("your_password_here") || v.equals("string");
    }

    /** Luhn algorithm check for credit card numbers. */
    private static boolean luhnCheck(String digits) {
        if (digits == null || digits.length() < 13 || digits.length() > 19) return false;
        int sum = 0;
        boolean alternate = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n;
            try { n = Character.getNumericValue(digits.charAt(i)); }
            catch (Exception e) { return false; }
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    private static String mask(String card) {
        String digits = card.replaceAll("[ \\-]", "");
        if (digits.length() < 4) return "****";
        return "****-****-****-" + digits.substring(digits.length() - 4);
    }
}
