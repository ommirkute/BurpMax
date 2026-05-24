package com.burpmax.active;

import java.util.*;

/**
 * Lightweight XML body parser that flattens XML element text content into
 * dot-notation paths for injection, and replaces leaf values in-place for probing.
 *
 * Handles:
 *   - Simple elements:    <user>alice</user>          → {"user": "alice"}
 *   - Nested elements:    <a><b>x</b></a>             → {"a.b": "x"}
 *   - Repeated elements:  <item>a</item><item>b</item>→ {"item.0":"a","item.1":"b"}
 *   - Attributes:         <tag attr="val"/>            → {"tag@attr": "val"}
 *   - CDATA:              <x><![CDATA[foo]]></x>       → {"x": "foo"}
 *   - SOAP bodies:        walks through envelope/body wrappers transparently
 *
 * Does NOT use a DOM/SAX library to avoid dependencies. Uses a simple
 * tag-oriented character scan that is robust enough for well-formed XML
 * encountered in real API traffic.
 *
 * For injection, replaceXmlLeaf() walks the original body string and replaces
 * the text content between matching open/close tags, preserving all surrounding
 * structure, namespace prefixes, and whitespace exactly.
 */
public class XmlBodyParser {

    // ── Flattening ────────────────────────────────────────────────────────────

    /**
     * Flatten XML body into dot-notation path → value entries.
     *
     * @param xml   raw XML body string
     * @param out   map to populate (path → text content)
     */
    public static void flatten(String xml, Map<String, String> out) {
        if (xml == null || xml.isBlank() || xml.length() > 65_536) return;
        xml = xml.trim();
        if (!xml.startsWith("<")) return;

        try {
            flattenFrom(xml, 0, "", out, new int[]{0});
        } catch (Exception ignored) {}
    }

    /**
     * Recursive walker. Returns position after the element that was processed.
     * @param counter shared counter tracking duplicate sibling element indices
     */
    private static int flattenFrom(String xml, int pos, String prefix,
                                    Map<String, String> out, int[] depthGuard) {
        if (++depthGuard[0] > 50 || out.size() > 300) return xml.length();
        int len = xml.length();

        // Track sibling element name counts for repeated-element indexing
        Map<String, Integer> siblingCount = new LinkedHashMap<>();

        while (pos < len) {
            pos = skipWhitespace(xml, pos);
            if (pos >= len) break;

            // Processing instruction or comment — skip
            if (xml.startsWith("<?", pos)) {
                int end = xml.indexOf("?>", pos);
                pos = end < 0 ? len : end + 2;
                continue;
            }
            if (xml.startsWith("<!--", pos)) {
                int end = xml.indexOf("-->", pos);
                pos = end < 0 ? len : end + 3;
                continue;
            }
            // DOCTYPE — skip
            if (xml.startsWith("<!", pos)) {
                int end = xml.indexOf('>', pos);
                pos = end < 0 ? len : end + 1;
                continue;
            }
            // Closing tag — signals end of parent element
            if (xml.startsWith("</", pos)) break;

            // Opening tag
            if (xml.charAt(pos) != '<') break;
            int tagStart = pos + 1;
            int tagEnd   = findTagEnd(xml, tagStart);
            if (tagEnd < 0) break;

            String tagContent = xml.substring(tagStart, tagEnd);
            boolean selfClose = tagContent.endsWith("/");
            if (selfClose) tagContent = tagContent.substring(0, tagContent.length() - 1).stripTrailing();

            // Extract local name (strip namespace prefix)
            String tagName = extractLocalName(tagContent.split("\\s", 2)[0]);
            if (tagName.isEmpty()) { pos = tagEnd + 1; continue; }

            // Build child path — handle repeated sibling elements.
            // All occurrences of a repeated tag must use 0-based index paths so
            // XmlBodyParser.replaceXmlLeaf() can locate them unambiguously.
            // When the second occurrence is found (count==2), retroactively re-key
            // the first occurrence from "tag" to "tag.0" in the output map.
            int count = siblingCount.merge(tagName, 1, Integer::sum);
            String childPath;
            if (count == 1) {
                // First occurrence — use unindexed path provisionally.
                // May be re-keyed to "tag.0" when/if a sibling is found later.
                childPath = prefix.isEmpty() ? tagName : prefix + "." + tagName;
            } else {
                if (count == 2) {
                    // Second occurrence found — retroactively re-key the first entry
                    // from "tag" (or "parent.tag") to "tag.0" (or "parent.tag.0").
                    String firstKey = prefix.isEmpty() ? tagName : prefix + "." + tagName;
                    String firstIndexed = firstKey + ".0";
                    if (out.containsKey(firstKey)) {
                        out.put(firstIndexed, out.remove(firstKey));
                    }
                }
                // Current occurrence uses (count-1) as its 0-based index
                String base = prefix.isEmpty() ? tagName : prefix + "." + tagName;
                childPath = base + "." + (count - 1);
            }

            pos = tagEnd + 1;
            if (selfClose) {
                // Extract attributes as @attr paths
                flattenAttributes(tagContent, childPath, out);
                continue;
            }

            // Collect attributes
            flattenAttributes(tagContent, childPath, out);

            // Find matching close tag, handling CDATA and nested same-name elements
            int[] contentEnd = findCloseTag(xml, pos, tagName);
            if (contentEnd == null) break;

            String inner = xml.substring(pos, contentEnd[0]);
            String innerTrimmed = inner.strip();

            if (isCdata(innerTrimmed)) {
                // CDATA section — extract text
                String text = innerTrimmed.substring(9, innerTrimmed.length() - 3);
                if (!text.isBlank() && out.size() < 300) out.put(childPath, text);
            } else if (innerTrimmed.startsWith("<")) {
                // Child elements — recurse
                int[] dg = {depthGuard[0]};
                flattenFrom(inner, 0, childPath, out, dg);
                depthGuard[0] = dg[0];
            } else {
                // Text leaf
                String text = decodeXmlEntities(innerTrimmed);
                if (!text.isBlank() && out.size() < 300) out.put(childPath, text);
            }

            pos = contentEnd[1];  // position after </tagName>
        }

        depthGuard[0]--;
        return pos;
    }

    private static void flattenAttributes(String tagContent, String path, Map<String, String> out) {
        // tagContent is everything between < and > (excluding the tag name prefix)
        int spaceIdx = tagContent.indexOf(' ');
        if (spaceIdx < 0) return;
        String attrStr = tagContent.substring(spaceIdx + 1);
        // Simple attribute parser: name="value" or name='value'
        int i = 0;
        while (i < attrStr.length()) {
            i = skipWS(attrStr, i);
            if (i >= attrStr.length()) break;
            int eq = attrStr.indexOf('=', i);
            if (eq < 0) break;
            String attrName = extractLocalName(attrStr.substring(i, eq).strip());
            if (attrName.isEmpty()) { i = eq + 1; continue; }
            i = eq + 1;
            if (i >= attrStr.length()) break;
            char q = attrStr.charAt(i++);
            if (q != '"' && q != '\'') continue;
            int close = attrStr.indexOf(q, i);
            if (close < 0) break;
            String val = attrStr.substring(i, close);
            if (!val.isBlank() && out.size() < 300)
                out.put(path + "@" + attrName, decodeXmlEntities(val));
            i = close + 1;
        }
    }

    // ── Leaf replacement ──────────────────────────────────────────────────────

    /**
     * Replace the text content of the leaf element identified by dotPath.
     * dotPath uses the same notation as flatten() — e.g. "a.b" replaces the
     * text inside &lt;b&gt; nested within &lt;a&gt;.
     * Attribute paths (containing "@") are not supported for injection.
     *
     * @return modified XML string, or null if the path was not found
     */
    public static String replaceXmlLeaf(String xml, String dotPath, String payload) {
        if (xml == null || dotPath == null || dotPath.contains("@")) return null;
        String[] segments = dotPath.split("\\.", -1);
        return replaceSegment(xml, 0, segments, 0, payload);
    }

    /**
     * Recursively walks XML following path segments.
     * @param xml     the XML string to search within
     * @param xmlOff  absolute offset of xml's start within the full document (for return values)
     * @param segs    path segments
     * @param segIdx  current segment index
     * @param payload replacement value (will be XML-escaped)
     * @return modified full XML string, or null
     */
    private static String replaceSegment(String xml, int xmlOff,
                                          String[] segs, int segIdx, String payload) {
        if (segIdx >= segs.length) return null;
        String seg     = segs[segIdx];
        boolean isLast = (segIdx == segs.length - 1);

        // Parse seg: may be "name" or "name.N" (indexed repeated sibling)
        String targetName;
        int    targetIndex = 0;   // 0-based index within repeated siblings (0 = first/only)
        if (seg.matches(".*\\.\\d+$")) {
            int dot = seg.lastIndexOf('.');
            targetName  = seg.substring(0, dot);
            targetIndex = Integer.parseInt(seg.substring(dot + 1));
        } else {
            targetName = seg;
        }

        int pos = 0;
        int len = xml.length();
        int occurrence = 0;

        while (pos < len) {
            pos = skipWhitespace(xml, pos);
            if (pos >= len || xml.charAt(pos) != '<') break;
            if (xml.startsWith("</", pos) || xml.startsWith("<?", pos)
                    || xml.startsWith("<!--", pos) || xml.startsWith("<!", pos)) {
                int end = xml.indexOf('>', pos);
                pos = end < 0 ? len : end + 1;
                continue;
            }

            int tagEnd = findTagEnd(xml, pos + 1);
            if (tagEnd < 0) break;
            String tagContent = xml.substring(pos + 1, tagEnd);
            boolean selfClose = tagContent.endsWith("/");
            if (selfClose) tagContent = tagContent.substring(0, tagContent.length() - 1).stripTrailing();
            String tagName = extractLocalName(tagContent.split("\\s", 2)[0]);

            if (tagName.equals(targetName)) {
                if (occurrence == targetIndex) {
                    // This is the target element occurrence
                    int innerStart = tagEnd + 1;

                    if (selfClose) {
                        // Cannot replace content of self-closing tag
                        return null;
                    }

                    int[] closeTag = findCloseTag(xml, innerStart, tagName);
                    if (closeTag == null) return null;
                    String inner = xml.substring(innerStart, closeTag[0]);

                    if (isLast) {
                        // Replace text content
                        String escapedPayload = escapeXml(payload);
                        return xml.substring(0, innerStart) + escapedPayload + xml.substring(closeTag[0]);
                    } else {
                        // Recurse into children
                        String replaced = replaceSegment(inner, 0, segs, segIdx + 1, payload);
                        if (replaced == null) return null;
                        return xml.substring(0, innerStart) + replaced + xml.substring(closeTag[0]);
                    }
                }
                occurrence++;
                // Skip this occurrence
                int innerStart = tagEnd + 1;
                if (!selfClose) {
                    int[] closeTag = findCloseTag(xml, innerStart, tagName);
                    if (closeTag == null) break;
                    pos = closeTag[1];
                } else {
                    pos = tagEnd + 1;
                }
                continue;
            }

            // Non-matching element — skip it entirely
            int innerStart = tagEnd + 1;
            if (!selfClose) {
                int[] closeTag = findCloseTag(xml, innerStart, tagName);
                if (closeTag == null) break;
                pos = closeTag[1];
            } else {
                pos = tagEnd + 1;
            }
        }
        return null;
    }

    // ── String-level XML helpers ───────────────────────────────────────────────

    /**
     * Find the position of the '>' that closes the current open tag,
     * respecting attribute values (which may contain '>').
     * @return index of '>', or -1
     */
    private static int findTagEnd(String xml, int pos) {
        boolean inDq = false, inSq = false;
        for (int i = pos; i < xml.length(); i++) {
            char c = xml.charAt(i);
            if (c == '"'  && !inSq) inDq = !inDq;
            if (c == '\'' && !inDq) inSq = !inSq;
            if (c == '>'  && !inDq && !inSq) return i;
        }
        return -1;
    }

    /**
     * Find the position of the matching </tagName> close tag,
     * tracking nesting depth for same-name elements.
     *
     * @return int[]{contentEnd, afterClose} or null if not found
     */
    private static int[] findCloseTag(String xml, int pos, String tagName) {
        String open  = "<"  + tagName;
        String close = "</" + tagName;
        int depth = 1;
        int i = pos;

        while (i < xml.length()) {
            int nextOpen  = indexOfTag(xml, open,  i);
            int nextClose = indexOfTag(xml, close, i);

            if (nextClose < 0) return null;

            if (nextOpen >= 0 && nextOpen < nextClose) {
                // A same-name opening tag comes first — increase depth
                // Only if it's an open tag (not a self-close)
                int te = findTagEnd(xml, nextOpen + 1);
                if (te >= 0 && !xml.substring(nextOpen + 1, te).stripTrailing().endsWith("/")) {
                    depth++;
                }
                i = te >= 0 ? te + 1 : nextOpen + open.length();
            } else {
                depth--;
                if (depth == 0) {
                    int closeEnd = xml.indexOf('>', nextClose);
                    if (closeEnd < 0) return null;
                    return new int[]{nextClose, closeEnd + 1};
                }
                i = nextClose + close.length();
            }
        }
        return null;
    }

    /**
     * Find tag starting with prefix at or after pos, ensuring it's followed by
     * a space, '/', or '>' (not a longer tag name, e.g. "item" should not match "items")
     */
    private static int indexOfTag(String xml, String tagPrefix, int pos) {
        int i = pos;
        while (i < xml.length()) {
            int idx = xml.indexOf(tagPrefix, i);
            if (idx < 0) return -1;
            int after = idx + tagPrefix.length();
            if (after >= xml.length()) return -1;
            char next = xml.charAt(after);
            if (next == '>' || next == ' ' || next == '\t' || next == '\r'
                    || next == '\n' || next == '/' || next == ':') {
                return idx;
            }
            i = idx + 1;
        }
        return -1;
    }

    private static String extractLocalName(String qname) {
        int colon = qname.lastIndexOf(':');
        return colon >= 0 ? qname.substring(colon + 1) : qname;
    }

    private static boolean isCdata(String s) {
        return s.startsWith("<![CDATA[") && s.endsWith("]]>");
    }

    private static int skipWhitespace(String s, int pos) {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            pos++;
        }
        return pos;
    }

    private static int skipWS(String s, int pos) { return skipWhitespace(s, pos); }

    private static String decodeXmlEntities(String s) {
        return s.replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'");
    }

    public static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;");
    }
}
