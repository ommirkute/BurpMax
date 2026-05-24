package com.burpmax.active;

import java.util.*;

/**
 * Generates WAF-evasion encoding variants of injection payloads.
 *
 * SQL variants: comment-based spaces, case mixing, URL encoding, double URL encoding,
 * MySQL version comments, tab/newline whitespace substitution.
 *
 * XSS variants: HTML entity encoding, mixed case tags, double URL encoding,
 * null byte insertion, SVG/img event handler alternatives.
 *
 * CmdI variants: IFS-based space replacement, brace expansion, quoted char splitting,
 * empty variable insertion ($@), backslash escaping.
 */
public class WafEvasionEncoder {

    // ── SQL Injection variants ─────────────────────────────────────────────────

    public static List<String> sqlVariants(String payload) {
        List<String> variants = new ArrayList<>();
        variants.add(payload);  // original always first

        // Comment-based space replacement
        variants.add(payload.replace(" ", "/**/"));
        variants.add(payload.replace(" ", "%09"));         // tab
        variants.add(payload.replace(" ", "%0a"));         // newline
        variants.add(payload.replace(" ", "%0d%0a"));      // CRLF

        // Case mixing on SQL keywords
        variants.add(mixCase(payload));

        // URL encoding of special chars
        variants.add(urlEncodeChars(payload, new char[]{'\'', '"', ' ', '=', '<', '>'}));

        // Double URL encoding
        variants.add(doubleUrlEncode(payload, new char[]{'\'', '"'}));

        // MySQL version comment bypass (e.g. converts "UNION SELECT" to "/*!UNION*/ SELECT")
        variants.add(mysqlVersionComment(payload));

        // Inline comment between keywords
        variants.add(payload.replace("OR", "O/**/R").replace("AND", "A/**/ND"));

        return dedup(variants);
    }

    // ── XSS variants ──────────────────────────────────────────────────────────

    public static List<String> xssVariants(String payload) {
        List<String> variants = new ArrayList<>();
        variants.add(payload);

        // HTML-entity and URL-encoded variants only make sense when the probe's
        // marker survives the encoding intact. For payloads whose marker itself
        // contains '<' or '>' (e.g. "<avxss-tag>"), encoding those chars to
        // &lt;/&gt; would mean the *encoded marker* is what appears in the
        // body — and that encoded form is harmless HTML literal text, not
        // executable. The probe searches for the raw marker, so these variants
        // would silently produce zero findings on tag-shaped payloads.
        // Only generate them when the payload has no marker-side angle bracket
        // (attribute/JS/URL contexts).
        boolean markerHasAngleBrackets = payload.startsWith("<") && payload.endsWith(">")
                && !payload.contains(" ") && !payload.contains("=");

        if (!markerHasAngleBrackets) {
            // HTML entity encoding
            variants.add(payload.replace("<", "&lt;").replace(">", "&gt;"));
            variants.add(payload.replace("<", "&#x3c;").replace(">", "&#x3e;"));
            variants.add(payload.replace("<", "&#60;").replace(">", "&#62;"));
            // Double URL encoding
            variants.add(doubleUrlEncode(payload, new char[]{'<', '>', '"', '\''}));
        }

        // Mixed case tag names
        if (payload.contains("<script")) {
            variants.add(payload.replace("<script", "<ScRiPt").replace("</script>", "</ScRiPt>"));
            variants.add(payload.replace("<script", "<SCRIPT").replace("</script>", "</SCRIPT>"));
            // Null byte between tag chars (some parsers strip null bytes before WAF, not before renderer)
            variants.add(payload.replace("<script", "<scr\u0000ipt"));
        }

        // Tag-less event handler variants (when no < is needed)
        if (payload.contains("onfocus") || payload.contains("autofocus")) {
            variants.add(payload.replace("onfocus", "ONFOCUS"));
            variants.add(payload.replace("autofocus", "AUTOFOCUS"));
        }

        // SVG/event-handler vector — bypasses script-tag-specific WAF rules.
        // The variant must contain the ORIGINAL marker substring verbatim so the
        // probe's body.contains(marker) check fires after UID substitution.
        // We embed the full marker (e.g. "<avxss-tag>") inside an HTML comment
        // adjacent to the event handler. Browsers ignore the comment but the
        // marker still appears in the response body for detection.
        if (payload.contains("avxss")) {
            String marker = extractXssMarker(payload);   // e.g. "avxss-tag"
            if (!marker.isEmpty()) {
                // Choose a safe property-name token (strip any non-identifier chars).
                String prop = marker.replaceAll("[^A-Za-z0-9_]", "");
                if (prop.isEmpty()) prop = "x";
                // Each variant carries the ORIGINAL payload text verbatim so
                // payload.replace(PREFIX, PREFIX+uid) keeps the marker intact in
                // BOTH the executable handler and the embedded comment. The
                // probe searches the body for the UID-substituted marker — it
                // will be present in the reflected comment regardless of how
                // the WAF rewrites the surrounding tag.
                variants.add(payload + "<!--" + payload + "-->"
                        + "<svg/onload=window['" + prop + "']=1>");
                variants.add(payload + "<!--" + payload + "-->"
                        + "<img src=x onerror=window['" + prop + "']=1>");
                variants.add(payload + "<!--" + payload + "-->"
                        + "<details open ontoggle=window['" + prop + "']=1>");
            }
        }

        return dedup(variants);
    }

    // ── Command injection variants ─────────────────────────────────────────────

    public static List<String> cmdiVariants(String payload) {
        List<String> variants = new ArrayList<>();
        variants.add(payload);

        // IFS-based space bypass (Unix)
        variants.add(payload.replace(" ", "${IFS}"));
        variants.add(payload.replace(" ", "$IFS"));

        // Brace expansion: "nslookup HOST" → "{nslookup,HOST}"
        String[] parts = payload.trim().split(";\\s*|&\\s*|\\|\\s*", 2);
        if (parts.length == 2) {
            String sep    = payload.contains(";") ? ";" : payload.contains("&") ? "&" : "|";
            String cmd    = parts[1].trim();
            String[] args = cmd.split(" ", 2);
            if (args.length == 2) {
                variants.add(sep + "{" + args[0] + "," + args[1] + "}");
            }
        }

        // Quoted character splitting (breaks keyword detection): sl'e'ep → sleep
        variants.add(payload.replace("sleep", "sl'e'ep").replace("nslookup", "n'sl'ookup"));

        // $@ empty variable insertion
        variants.add(payload.replace("sleep", "sl$@eep").replace("curl", "cu$@rl"));

        // Backslash escaping (Unix shells ignore backslash in certain positions)
        variants.add(payload.replace("sleep", "sl\\eep").replace("curl", "cur\\l"));

        return dedup(variants);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String mixCase(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            sb.append(i % 2 == 0 ? Character.toLowerCase(c) : Character.toUpperCase(c));
        }
        return sb.toString();
    }

    private static String urlEncodeChars(String s, char[] toEncode) {
        StringBuilder sb = new StringBuilder();
        outer:
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            for (char enc : toEncode) {
                if (c == enc) {
                    sb.append(String.format("%%%02X", (int) c));
                    continue outer;
                }
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static String doubleUrlEncode(String s, char[] toEncode) {
        // Double-encode only the targeted chars in a single pass.
        // The old two-step approach (urlEncodeChars then replace "%" with "%25")
        // triple-encoded chars that were already URL-encoded in the original
        // payload (e.g. %20 → %2520 → %252520 on a second call).
        // Correct: emit %25XX directly for each targeted char.
        Set<Character> targets = new HashSet<>();
        for (char c : toEncode) targets.add(c);
        StringBuilder sb = new StringBuilder(s.length() * 2);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (targets.contains(c)) {
                // First encoding: c → %XX
                // Second encoding: % → %25, so result is %25XX
                sb.append(String.format("%%25%02X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String mysqlVersionComment(String s) {
        return s.replace("UNION", "/*!50000UNION*/")
                .replace("SELECT", "/*!50000SELECT*/")
                .replace("OR", "/*!50000OR*/");
    }

    private static String extractXssMarker(String payload) {
        // Extract the marker identifier from an avxss payload
        int idx = payload.indexOf("avxss");
        if (idx < 0) return "1";
        int end = idx;
        while (end < payload.length() && (Character.isLetterOrDigit(payload.charAt(end))
                || payload.charAt(end) == '-' || payload.charAt(end) == '_')) end++;
        return payload.substring(idx, end);
    }

    private static List<String> dedup(List<String> list) {
        // Remove duplicates while preserving order (original stays first)
        Set<String> seen = new LinkedHashSet<>(list);
        return new ArrayList<>(seen);
    }
}
