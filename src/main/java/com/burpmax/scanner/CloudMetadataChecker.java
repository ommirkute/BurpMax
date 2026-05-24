package com.burpmax.scanner;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

/**
 * Detects cloud metadata service URLs and responses in HTTP response bodies.
 *
 * 169.254.169.254 is the AWS/GCP/Azure Instance Metadata Service (IMDS) IP.
 * Its presence in an application response indicates either:
 *  (a) A confirmed SSRF vulnerability where the IMDS was queried and its output returned, or
 *  (b) An accidental metadata leak from server-side logging or debugging.
 *
 * In either case this is a High finding. False positive rate is near zero because
 * 169.254.169.254 is a link-local address with no legitimate use in application responses.
 */
public class CloudMetadataChecker {

    // AWS/GCP/Azure IMDS IP — link-local, should NEVER appear in application responses
    private static final String IMDS_IP = "169.254.169.254";

    // AWS IMDS response patterns — confirms actual SSRF exploitation
    private static final Pattern RE_IMDS_RESPONSE = Pattern.compile(
            "(?:ami-id|instance-id|instance-type|local-ipv4|" +
            "security-credentials|iam/info|latest/meta-data|" +
            "latest/dynamic/instance-identity)",
            Pattern.CASE_INSENSITIVE);

    // Azure IMDS endpoint
    private static final Pattern RE_AZURE_IMDS = Pattern.compile(
            "169\\.254\\.169\\.254/metadata/instance",
            Pattern.CASE_INSENSITIVE);

    // GCP metadata server
    private static final Pattern RE_GCP_METADATA = Pattern.compile(
            "(?:169\\.254\\.169\\.254|metadata\\.google\\.internal)" +
            "/computeMetadata",
            Pattern.CASE_INSENSITIVE);

    // AWS credentials in response body (from IMDS /iam/security-credentials)
    private static final Pattern RE_IMDS_CREDS = Pattern.compile(
            "\"(?:AccessKeyId|SecretAccessKey|Token|Expiration)\"\\s*:\\s*\"[^\"]+\"",
            Pattern.CASE_INSENSITIVE);

    public static List<CheckResult> check(String body) {
        List<CheckResult> results = new ArrayList<>();
        if (body == null || body.isEmpty()) return results;

        // Check for IMDS IP in body
        if (!body.contains(IMDS_IP)) return results;

        // PROBE-REFLECTION FALSE POSITIVE GUARD:
        // The active SSRF probe injects "http://169.254.169.254/latest/meta-data/" as a
        // parameter value. If the server reflects the injected input back in its response
        // (e.g. in a validation error, echo endpoint, or 400/500 body), the probe URL
        // appears in the response and would trigger this checker — a false positive.
        // Real IMDS exploitation returns actual metadata field names (ami-id, instance-id
        // etc.), not the verbatim injected URL. Strip probe URL strings before matching
        // so only genuine IMDS data patterns can trigger findings.
        String sanitised = body
            .replaceAll("(?i)https?://169\\.254\\.169\\.254[^\\s\"'<>]*", "")
            .replaceAll("(?i)http://metadata\\.google\\.internal[^\\s\"'<>]*", "");

        // If the IMDS IP is gone after stripping injected probe URLs, it was purely
        // a reflection — abort to avoid false positive.
        if (!sanitised.contains(IMDS_IP)) return results;

        // Determine severity based on what else is present
        boolean hasImdsResponse    = RE_IMDS_RESPONSE.matcher(sanitised).find();
        boolean hasImdsCredentials = RE_IMDS_CREDS.matcher(sanitised).find();

        if (hasImdsCredentials) {
            // Worst case: actual IAM credentials from IMDS returned in response
            Matcher m = RE_IMDS_CREDS.matcher(body);
            String field = m.find() ? m.group() : IMDS_IP;
            results.add(new CheckResult(
                "SSRF: AWS IAM Credentials Exposed via IMDS", SEV_CRITICAL,
                "The HTTP response contains AWS IAM credential fields (AccessKeyId, SecretAccessKey, Token) " +
                "that originate from the AWS Instance Metadata Service (IMDS) at 169.254.169.254. " +
                "This is a confirmed Server-Side Request Forgery (SSRF) vulnerability where the " +
                "attacker can retrieve temporary IAM credentials granting access to all AWS services " +
                "the instance role is permitted to use - including S3, EC2, RDS, Lambda, and Secrets Manager.",
                "IMDS credentials detected: " + trunc(field, 120),
                "- Rotate the exposed IAM role credentials immediately via AWS IAM\n" +
                "- Enable IMDSv2 (token-based) to prevent unauthenticated metadata access: " +
                "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required\n" +
                "- Block 169.254.169.254 at the application level and via security group egress rules\n" +
                "- Audit the SSRF vector - identify and fix the server-side HTTP request that can be redirected",
                "CWE-918"));

        } else if (hasImdsResponse) {
            // IMDS endpoint paths or metadata field names present — strong SSRF indicator
            Matcher m = RE_IMDS_RESPONSE.matcher(body);
            String field = m.find() ? m.group() : IMDS_IP;
            results.add(new CheckResult(
                "SSRF: Cloud Instance Metadata Service (IMDS) Response Detected", SEV_HIGH,
                "The HTTP response contains content that matches AWS/GCP/Azure Instance Metadata " +
                "Service (IMDS) response patterns alongside the IMDS IP address 169.254.169.254. " +
                "This strongly indicates a Server-Side Request Forgery (SSRF) vulnerability where " +
                "the application is forwarding attacker-controlled requests to the internal metadata " +
                "service. IMDS access can lead to cloud credential theft and full infrastructure compromise.",
                "IMDS IP (169.254.169.254) + metadata field detected: " + trunc(field, 100),
                "- Enable IMDSv2 (token-based) immediately to require a PUT request before GET\n" +
                "- Identify the SSRF vector: look for URL parameters, headers, or body fields that " +
                "accept user-supplied URLs or IPs\n" +
                "- Block outbound requests to 169.254.169.254 at the egress firewall and security groups\n" +
                "- Apply an allowlist of permitted outbound destinations in your HTTP client",
                "CWE-918"));

        } else {
            // Just the IP present — lower confidence but still warrants investigation
            results.add(new CheckResult(
                "Cloud Metadata Service IP (169.254.169.254) Disclosed in Response", SEV_MEDIUM,
                "The IP address 169.254.169.254 - used by AWS, GCP, and Azure as the Instance " +
                "Metadata Service (IMDS) endpoint - was found in the HTTP response body. " +
                "This IP is a link-local address that has no legitimate use in application responses. " +
                "Its presence may indicate an SSRF vulnerability, a server-side error message revealing " +
                "failed internal requests, or misconfigured diagnostic output.",
                "169.254.169.254 found in response body",
                "- Audit all server-side HTTP client calls: grep the codebase for fetch(, HttpClient, RestTemplate, " +
                "requests.get, urllib.request, curl_exec and trace any that accept user-supplied URLs or redirect targets\n" +
                "- Reproduce by injecting http://169.254.169.254/latest/meta-data/ into every URL-accepting parameter, " +
                "header (X-Forwarded-Host, Referer), and JSON field to identify the exact SSRF source\n" +
                "- Once the source is identified, enforce a strict server-side allowlist of permitted schemes " +
                "(https only), hostnames, and ports; deny all others by default\n" +
                "- Block outbound requests to 169.254.169.254, 169.254.0.0/16, and all RFC-1918 ranges " +
                "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) at both the application HTTP client and the egress firewall\n" +
                "- Enable IMDSv2 (token-based) as defence-in-depth: " +
                "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required\n" +
                "- Validate the resolved IP after DNS lookup (re-check post-resolution) to prevent DNS rebinding bypasses\n" +
                "- If this originates from an error message: configure a global exception handler to suppress " +
                "raw exception output including internal IPs and paths",
                "CWE-918"));
        }

        return results;
    }
}
