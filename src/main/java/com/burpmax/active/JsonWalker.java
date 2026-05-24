package com.burpmax.active;

import java.util.Map;

/**
 * Shared, dependency-free JSON string walker used by:
 *   - ActiveScanner.flattenJson  — flatten body into dot-notation injectable paths
 *   - RequestBuilder.replaceJsonLeaf — locate and replace a leaf value by dot-path
 *
 * This eliminates the duplicate implementations that previously existed in both
 * classes under different method names (flatSkipWS vs skipWhitespace, etc.).
 * All methods are package-private statics — no instantiation needed.
 */
class JsonWalker {

    // ── Flattening (used by ActiveScanner) ────────────────────────────────────

    static void flatten(String json, String prefix, Map<String, String> out) {
        if (json == null) return;
        json = json.trim();
        if (json.isEmpty() || json.length() > 65_536) return;
        try { flattenAt(json, 0, prefix, out, 0); } catch (Exception ignored) {}
    }

    static void flattenAt(String json, int pos, String prefix,
                           Map<String, String> out, int depth) {
        if (depth > 20 || out.size() > 200) return;
        pos = skipWS(json, pos);
        if (pos >= json.length()) return;
        char c = json.charAt(pos);

        if (c == '{') {
            pos++;
            while (pos < json.length()) {
                pos = skipWS(json, pos);
                if (pos >= json.length()) break;
                char ch = json.charAt(pos);
                if (ch == '}') break;
                if (ch == ',') { pos++; continue; }
                if (ch != '"') break;
                int[] kspan = readString(json, pos);
                if (kspan == null) return;
                String key = json.substring(pos + 1, kspan[1] - 1);
                pos = kspan[1];
                pos = skipWS(json, pos);
                if (pos >= json.length() || json.charAt(pos) != ':') return;
                pos++;
                pos = skipWS(json, pos);
                String childPath = prefix.isEmpty() ? key : prefix + "." + key;
                char valChar = pos < json.length() ? json.charAt(pos) : 0;
                if (valChar == '{' || valChar == '[') {
                    int[] vspan = skipValueSpan(json, pos);
                    if (vspan == null) return;
                    flattenAt(json.substring(pos, vspan[1]), 0, childPath, out, depth + 1);
                    pos = vspan[1];
                } else {
                    int[] vspan = scalarSpan(json, pos);
                    if (vspan == null) return;
                    String raw = json.substring(vspan[0], vspan[1]);
                    String value = isQuoted(raw) ? unescapeString(raw.substring(1, raw.length() - 1)) : raw;
                    if (!"null".equals(value)) out.put(childPath, value);
                    pos = vspan[1];
                }
            }
        } else if (c == '[') {
            pos++;
            int idx = 0;
            while (pos < json.length()) {
                pos = skipWS(json, pos);
                if (pos >= json.length()) break;
                char ch = json.charAt(pos);
                if (ch == ']') break;
                if (ch == ',') { pos++; idx++; continue; }
                String childPath = prefix.isEmpty() ? String.valueOf(idx) : prefix + "." + idx;
                char valChar = json.charAt(pos);
                if (valChar == '{' || valChar == '[') {
                    int[] vspan = skipValueSpan(json, pos);
                    if (vspan == null) return;
                    flattenAt(json.substring(pos, vspan[1]), 0, childPath, out, depth + 1);
                    pos = vspan[1];
                } else {
                    int[] vspan = scalarSpan(json, pos);
                    if (vspan == null) return;
                    String raw = json.substring(vspan[0], vspan[1]);
                    String value = isQuoted(raw) ? unescapeString(raw.substring(1, raw.length() - 1)) : raw;
                    if (!"null".equals(value)) out.put(childPath, value);
                    pos = vspan[1];
                }
            }
        }
    }

    // ── Leaf replacement (used by RequestBuilder) ────────────────────────────

    static String replaceLeaf(String json, String dotPath, String payload) {
        String[] segments = dotPath.split("\\.", -1);
        int pos = 0;
        for (int segIdx = 0; segIdx < segments.length; segIdx++) {
            String seg    = segments[segIdx];
            boolean isLast = segIdx == segments.length - 1;
            pos = skipWS(json, pos);
            if (pos >= json.length()) return null;
            char ctx = json.charAt(pos);
            if (ctx == '{') {
                int keyPos = findObjectKey(json, pos, seg);
                if (keyPos < 0) return null;
                pos = skipWS(json, keyPos);
                if (pos >= json.length()) return null;
                if (isLast) {
                    int[] span = valueSpan(json, pos);
                    if (span == null) return null;
                    return json.substring(0, span[0]) + "\"" + escapeJson(payload) + "\"" + json.substring(span[1]);
                }
            } else if (ctx == '[') {
                int arrayIndex;
                try { arrayIndex = Integer.parseInt(seg); } catch (NumberFormatException e) { return null; }
                if (arrayIndex < 0) return null;
                int elemPos = findArrayElement(json, pos, arrayIndex);
                if (elemPos < 0) return null;
                pos = skipWS(json, elemPos);
                if (pos >= json.length()) return null;
                if (isLast) {
                    int[] span = valueSpan(json, pos);
                    if (span == null) return null;
                    return json.substring(0, span[0]) + "\"" + escapeJson(payload) + "\"" + json.substring(span[1]);
                }
            } else {
                return null;
            }
        }
        return null;
    }

    // ── Shared primitives ─────────────────────────────────────────────────────

    static int skipWS(String s, int pos) {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            pos++;
        }
        return pos;
    }

    static int[] readString(String s, int pos) {
        if (pos >= s.length() || s.charAt(pos) != '"') return null;
        int i = pos + 1;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '\\') { i += 2; continue; }
            if (c == '"')  return new int[]{pos, i + 1};
            i++;
        }
        return null;
    }

    static int[] scalarSpan(String s, int pos) {
        if (pos >= s.length()) return null;
        char c = s.charAt(pos);
        if (c == '"') return readString(s, pos);
        int end = pos;
        while (end < s.length()) {
            char d = s.charAt(end);
            if (d == ',' || d == '}' || d == ']' || d == ' ' || d == '\t' || d == '\r' || d == '\n') break;
            end++;
        }
        return end > pos ? new int[]{pos, end} : null;
    }

    static int[] skipValueSpan(String s, int pos) {
        if (pos >= s.length()) return null;
        char c = s.charAt(pos);
        if (c == '"') return readString(s, pos);
        if (c == '{' || c == '[') {
            int depth = 1, i = pos + 1;
            while (i < s.length() && depth > 0) {
                char d = s.charAt(i);
                if (d == '"') { int[] sp = readString(s, i); if (sp == null) return null; i = sp[1]; continue; }
                if (d == '{' || d == '[') depth++;
                if (d == '}' || d == ']') depth--;
                i++;
            }
            return depth == 0 ? new int[]{pos, i} : null;
        }
        return scalarSpan(s, pos);
    }

    static int[] valueSpan(String s, int pos) {
        if (pos >= s.length()) return null;
        char c = s.charAt(pos);
        if (c == '"') return readString(s, pos);
        if (c == 't' && s.startsWith("true",  pos)) return new int[]{pos, pos + 4};
        if (c == 'f' && s.startsWith("false", pos)) return new int[]{pos, pos + 5};
        if (c == 'n' && s.startsWith("null",  pos)) return new int[]{pos, pos + 4};
        if (c == '-' || (c >= '0' && c <= '9')) {
            int end = pos + 1;
            while (end < s.length()) {
                char d = s.charAt(end);
                if (d == ',' || d == '}' || d == ']' || d == ' ' || d == '\t' || d == '\r' || d == '\n') break;
                end++;
            }
            return new int[]{pos, end};
        }
        return null;
    }

    private static int findObjectKey(String json, int objStart, String key) {
        int i = objStart + 1, depth = 0, len = json.length();
        while (i < len) {
            char c = json.charAt(i);
            if (c == '{' || c == '[') { depth++; i++; continue; }
            if (c == '}' || c == ']') { if (depth == 0) return -1; depth--; i++; continue; }
            if (c == '"' && depth == 0) {
                int[] strSpan = readString(json, i);
                if (strSpan == null) return -1;
                String foundKey = json.substring(i + 1, strSpan[1] - 1);
                i = strSpan[1];
                i = skipWS(json, i);
                if (i >= len || json.charAt(i) != ':') continue;
                i++;
                i = skipWS(json, i);
                if (foundKey.equals(key)) return i;
                i = skipValue(json, i);
                if (i < 0) return -1;
                i = skipWS(json, i);
                if (i < len && json.charAt(i) == ',') i++;
                continue;
            }
            if (c == '"') { int[] span = readString(json, i); if (span == null) return -1; i = span[1]; continue; }
            i++;
        }
        return -1;
    }

    private static int findArrayElement(String json, int arrStart, int index) {
        int i = skipWS(json, arrStart + 1), len = json.length(), elem = 0;
        if (i >= len || json.charAt(i) == ']') return -1;
        while (i < len) {
            if (elem == index) return i;
            i = skipValue(json, i);
            if (i < 0) return -1;
            i = skipWS(json, i);
            if (i >= len) return -1;
            char c = json.charAt(i);
            if (c == ']') return -1;
            if (c == ',') { i++; i = skipWS(json, i); elem++; }
        }
        return -1;
    }

    private static int skipValue(String json, int pos) {
        if (pos >= json.length()) return -1;
        char c = json.charAt(pos);
        if (c == '"') { int[] span = readString(json, pos); return span != null ? span[1] : -1; }
        if (c == '{' || c == '[') {
            int depth = 1, i = pos + 1;
            while (i < json.length() && depth > 0) {
                char d = json.charAt(i);
                if (d == '"') { int[] span = readString(json, i); if (span == null) return -1; i = span[1]; continue; }
                if (d == '{' || d == '[') depth++;
                if (d == '}' || d == ']') depth--;
                i++;
            }
            return depth == 0 ? i : -1;
        }
        int i = pos;
        while (i < json.length()) {
            char d = json.charAt(i);
            if (d == ',' || d == '}' || d == ']' || d == ' ' || d == '\t' || d == '\r' || d == '\n') break;
            i++;
        }
        return i > pos ? i : -1;
    }

    private static boolean isQuoted(String s) {
        return s != null && s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"");
    }

    static String unescapeString(String s) {
        if (!s.contains("\\")) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char e = s.charAt(++i);
                switch (e) {
                    case '"'  -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/'  -> sb.append('/');
                    case 'n'  -> sb.append('\n');
                    case 'r'  -> sb.append('\r');
                    case 't'  -> sb.append('\t');
                    default   -> { sb.append('\\'); sb.append(e); }
                }
            } else { sb.append(c); }
        }
        return sb.toString();
    }

    static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"'  -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> { if (c < 0x20) sb.append(String.format("\\u%04x",(int)c)); else sb.append(c); }
            }
        }
        return sb.toString();
    }
}
