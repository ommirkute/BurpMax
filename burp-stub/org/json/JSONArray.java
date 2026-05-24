package org.json;
import java.util.*;

public class JSONArray {
    private final List<Object> list = new ArrayList<>();

    public JSONArray() {}
    public JSONArray put(Object v) { list.add(v); return this; }
    public int length()             { return list.size(); }
    public JSONObject optJSONObject(int i) { Object v=list.get(i); return v instanceof JSONObject?(JSONObject)v:null; }
    public JSONObject getJSONObject(int i) { return (JSONObject) list.get(i); }
    public Object get(int i)         { return list.get(i); }

    static JSONArray parseArray(char[] s, int[] pos, int depth) {
        JSONArray arr = new JSONArray();
        JSONObject.skipWS(s, pos);
        while (pos[0] < s.length && s[pos[0]] != ']') {
            JSONObject.skipWS(s, pos);
            if (s[pos[0]] == ',') { pos[0]++; JSONObject.skipWS(s, pos); }
            if (s[pos[0]] == ']') break;
            arr.put(JSONObject.parseValue(s, pos, depth + 1));
            JSONObject.skipWS(s, pos);
        }
        if (pos[0] < s.length) pos[0]++; // skip ']'
        return arr;
    }

    String toJsonString(int depth, int indent) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            if (indent > 0) sb.append("\n").append("  ".repeat(depth+1));
            sb.append(JSONObject.valueStr(list.get(i), depth+1, indent));
        }
        if (indent > 0 && !list.isEmpty()) sb.append("\n").append("  ".repeat(depth));
        sb.append("]");
        return sb.toString();
    }

    public String toString() { return toJsonString(0,0); }
}
