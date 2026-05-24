package com.burpmax.active;

import burp.IHttpService;

import java.util.*;

/**
 * Carries all information needed to probe a single endpoint.
 * Constructed from a passive scan request/response pair.
 *
 * Parameter sets:
 *   queryParams  — URL query-string parameters   (?foo=bar)
 *   bodyParams   — form-encoded body parameters  (application/x-www-form-urlencoded)
 *   jsonParams   — JSON body leaf nodes, keyed by dot-notation path
 *                  e.g. {"user.name":"alice","user.age":"30","tags.0":"x"}
 *                  Only populated when Content-Type is application/json.
 *
 * allParamNames() returns all injectable names from all three sets so probes
 * can iterate without caring which set a parameter came from.
 * isQueryParam() / isBodyParam() / isJsonParam() let RequestBuilder route the
 * injection to the correct serialisation strategy.
 */
public class ProbeContext {

    public final IHttpService    service;
    public final byte[]          originalRequest;
    public final byte[]          originalResponse;
    public final String          url;
    public final String          method;
    public final String          host;
    public final boolean         isHttps;
    public final Map<String, String> queryParams;  // name → value
    public final Map<String, String> bodyParams;   // name → value (form-encoded)
    public final Map<String, String> jsonParams;   // dot-path → value (JSON body leaf nodes)
    public final Map<String, String> xmlParams;    // dot-path → value (XML body leaf nodes)
    public final String          bodyRaw;          // raw request body
    public final String          contentType;      // request Content-Type
    public final Map<String, String> reqHeaders;   // lowercase name → value

    public ProbeContext(IHttpService service,
                        byte[] originalRequest, byte[] originalResponse,
                        String url, String method, String host, boolean isHttps,
                        Map<String, String> queryParams, Map<String, String> bodyParams,
                        Map<String, String> jsonParams,
                        Map<String, String> xmlParams,
                        String bodyRaw, String contentType, Map<String, String> reqHeaders) {
        this.service          = service;
        this.originalRequest  = originalRequest;
        this.originalResponse = originalResponse;
        this.url              = url;
        this.method           = method;
        this.host             = host;
        this.isHttps          = isHttps;
        this.queryParams      = queryParams;
        this.bodyParams       = bodyParams;
        this.jsonParams       = jsonParams;
        this.xmlParams        = xmlParams;
        this.bodyRaw          = bodyRaw;
        this.contentType      = contentType;
        this.reqHeaders       = reqHeaders;
    }

    /** Returns true if there are any injectable parameters to fuzz. */
    public boolean hasParameters() {
        return !queryParams.isEmpty() || !bodyParams.isEmpty()
                || !jsonParams.isEmpty() || !xmlParams.isEmpty();
    }

    /**
     * All injectable parameter names — query + form body + JSON dot-paths.
     * Order: query params first, then body params, then JSON paths.
     * Using LinkedHashSet preserves insertion order and deduplicates.
     */
    public Set<String> allParamNames() {
        Set<String> all = new LinkedHashSet<>(queryParams.keySet());
        all.addAll(bodyParams.keySet());
        all.addAll(jsonParams.keySet());
        all.addAll(xmlParams.keySet());
        return all;
    }

    /**
     * Value of a parameter (query → body → JSON, first match wins).
     * For JSON params the value is the string-serialised leaf value.
     */
    public String paramValue(String name) {
        if (queryParams.containsKey(name)) return queryParams.get(name);
        if (bodyParams.containsKey(name))  return bodyParams.get(name);
        if (jsonParams.containsKey(name))  return jsonParams.get(name);
        return xmlParams.getOrDefault(name, "");
    }

    /** True if parameter is in the URL query string. */
    public boolean isQueryParam(String name) {
        return queryParams.containsKey(name);
    }

    /** True if parameter is in a form-encoded body. */
    public boolean isBodyParam(String name) {
        return bodyParams.containsKey(name);
    }

    /**
     * True if parameter is a JSON body leaf node (dot-notation path).
     * Dot-paths may reference nested objects ("user.address.city")
     * or array elements ("items.0.name").
     */
    public boolean isJsonParam(String name) {
        return jsonParams.containsKey(name);
    }

    /** True if parameter is an XML body leaf node (dot-notation path). */
    public boolean isXmlParam(String name) {
        return xmlParams.containsKey(name);
    }
}
