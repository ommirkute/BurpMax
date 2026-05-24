package com.burpmax.scanner;

import com.burpmax.model.Finding;

import java.util.*;

/**
 * Coordinates all check modules and converts CheckResults into Finding objects.
 */
public class Dispatcher {

    public static List<Finding> dispatch(
            Map<String, String> reqHeaders,
            Map<String, String> respHeaders,
            List<String>        setCookies,
            String              body,
            String              contentType,
            String              method,
            String              host,
            String              url,
            int                 statusCode,
            String              reqBody,
            byte[]              rawRequest,
            byte[]              rawResponse,
            Object              httpService) {

        List<CheckResult> raw = new ArrayList<>();

        // Existing checks
        raw.addAll(HeaderChecker.check(respHeaders, reqHeaders, statusCode));
        raw.addAll(CookieChecker.check(setCookies));
        raw.addAll(VersionChecker.check(body, respHeaders));
        raw.addAll(BodyChecker.check(body, contentType));
        raw.addAll(HtmlChecker.check(body, contentType));
        raw.addAll(RequestChecker.check(reqHeaders));
        raw.addAll(MethodChecker.check(respHeaders));
        raw.addAll(SecretChecker.check(body));

        // New Tier-1 checks
        raw.addAll(ApiResponseChecker.check(body, contentType, statusCode));
        raw.addAll(CacheControlChecker.check(respHeaders, setCookies, url));
        raw.addAll(CloudMetadataChecker.check(body));
        raw.addAll(RateLimitChecker.check(respHeaders, method, url, statusCode, body));
        raw.addAll(CleartextCredentialChecker.check(reqHeaders, reqBody, url, method));

        List<Finding> findings = new ArrayList<>();
        for (CheckResult r : raw) {
            findings.add(new Finding(
                    r.name, r.severity, r.description,
                    r.evidence, r.remediation, r.cwe,
                    host, url, statusCode,
                    rawRequest, rawResponse, httpService));
        }
        return findings;
    }
}
