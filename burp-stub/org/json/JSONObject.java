package org.json;
import java.util.*;

/** Minimal JSONObject — covers the subset used by BurpMax. */
public class JSONObject {
    private static final int MAX_DEPTH = 32;   // prevent stack overflow DoS

    private final Map<String,Object> map = new LinkedHashMap<>();
    public static final Object NULL = new Object() {
        public String toString() { return "null"; }
    };

    public JSONObject() {}
    public JSONObject(String json) { parse(json); }

    public JSONObject put(String k, Object v)  { map.put(k, v); return this; }
    public JSONObject put(String k, int v)     { map.put(k, v); return this; }
    public JSONObject put(String k, boolean v) { map.put(k, v); return this; }
    public JSONObject put(String k, long v)    { map.put(k, v); return this; }
    public JSONObject put(String k, double v)  { map.put(k, v); return this; }

    public boolean has(String k)     { return map.containsKey(k); }
    public boolean isNull(String k)  { Object v=map.get(k); return v==null||v==NULL; }

    public String  optString(String k, String def)   { Object v=map.get(k); return v!=null&&v!=NULL ? v.toString() : def; }
    public int     optInt(String k, int def)          { Object v=map.get(k); if(v==null||v==NULL) return def; try{return Integer.parseInt(v.toString());}catch(Exception e){return def;} }
    public long    optLong(String k, long def)        { Object v=map.get(k); if(v==null||v==NULL) return def; try{return Long.parseLong(v.toString());}catch(Exception e){return def;} }
    public boolean optBoolean(String k, boolean def)  { Object v=map.get(k); if(v==null||v==NULL) return def; return Boolean.parseBoolean(v.toString()); }
    public double  optDouble(String k, double def)    { Object v=map.get(k); if(v==null||v==NULL) return def; try{return Double.parseDouble(v.toString());}catch(Exception e){return def;} }
    public JSONArray optJSONArray(String k)           { Object v=map.get(k); return v instanceof JSONArray ? (JSONArray)v : null; }
    public JSONObject optJSONObject(String k)         { Object v=map.get(k); return v instanceof JSONObject ? (JSONObject)v : null; }

    public String toString(int indent) { return toJsonString(0, indent); }
    public String toString()           { return toJsonString(0, 0); }

    private String toJsonString(int depth, int indent) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String,Object> e : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            if (indent > 0) sb.append("\n").append("  ".repeat(depth+1));
            sb.append("\"").append(escStr(e.getKey())).append("\":");
            if (indent > 0) sb.append(" ");
            sb.append(valueStr(e.getValue(), depth+1, indent));
        }
        if (indent > 0 && !map.isEmpty()) sb.append("\n").append("  ".repeat(depth));
        sb.append("}");
        return sb.toString();
    }

    static String valueStr(Object v, int depth, int indent) {
        if (v == null || v == NULL) return "null";
        if (v instanceof Boolean || v instanceof Number) return v.toString();
        if (v instanceof JSONObject) return ((JSONObject)v).toJsonString(depth, indent);
        if (v instanceof JSONArray)  return ((JSONArray)v).toJsonString(depth, indent);
        return "\"" + escStr(v.toString()) + "\"";
    }

    static String escStr(String s) {
        return s.replace("\\","\\\\").replace("\"","\\\"")
                .replace("\n","\\n").replace("\r","\\r").replace("\t","\\t");
    }

    /** Very minimal JSON parser — handles the subset we write ourselves. */
    private void parse(String json) {
        json = json.trim();
        if (!json.startsWith("{")) return;
        parseObject(json.toCharArray(), new int[]{1}, 0);
    }

    private void parseObject(char[] s, int[] pos, int depth) {
        if (depth > MAX_DEPTH) return;
        skipWS(s, pos);
        while (pos[0] < s.length && s[pos[0]] != '}') {
            skipWS(s, pos);
            if (s[pos[0]] == ',') { pos[0]++; skipWS(s, pos); }
            if (s[pos[0]] == '}') break;
            String key = parseString(s, pos);
            skipWS(s, pos);
            if (pos[0] < s.length && s[pos[0]] == ':') pos[0]++;
            skipWS(s, pos);
            Object val = parseValue(s, pos, depth + 1);
            map.put(key, val);
            skipWS(s, pos);
        }
        if (pos[0] < s.length) pos[0]++; // skip '}'
    }

    static Object parseValue(char[] s, int[] pos, int depth) {
        skipWS(s, pos);
        if (pos[0] >= s.length) return NULL;
        if (depth > MAX_DEPTH) return NULL;
        char c = s[pos[0]];
        if (c == '"')  return parseString(s, pos);
        if (c == '{')  { pos[0]++; JSONObject o=new JSONObject(); o.parseObject(s, pos, depth+1); return o; }
        if (c == '[')  { pos[0]++; return JSONArray.parseArray(s, pos, depth+1); }
        if (c == 't')  { pos[0]+=4; return Boolean.TRUE; }
        if (c == 'f')  { pos[0]+=5; return Boolean.FALSE; }
        if (c == 'n')  { pos[0]+=4; return NULL; }
        // number
        int start=pos[0];
        while (pos[0]<s.length && "-0123456789.eE+".indexOf(s[pos[0]])>=0) pos[0]++;
        String num = new String(s,start,pos[0]-start);
        try { return num.contains(".")||num.contains("e")||num.contains("E") ? Double.parseDouble(num) : Long.parseLong(num); }
        catch(Exception e) { return num; }
    }

    static String parseString(char[] s, int[] pos) {
        if (s[pos[0]] == '"') pos[0]++;
        StringBuilder sb = new StringBuilder();
        while (pos[0] < s.length && s[pos[0]] != '"') {
            if (s[pos[0]] == '\\') {
                pos[0]++;
                if (pos[0] < s.length) {
                    char e = s[pos[0]++];
                    switch(e) {
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        default:  sb.append(e);
                    }
                }
            } else sb.append(s[pos[0]++]);
        }
        if (pos[0] < s.length) pos[0]++; // skip closing "
        return sb.toString();
    }

    static void skipWS(char[] s, int[] pos) {
        while (pos[0] < s.length && Character.isWhitespace(s[pos[0]])) pos[0]++;
    }
}
