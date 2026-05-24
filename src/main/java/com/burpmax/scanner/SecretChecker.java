package com.burpmax.scanner;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

public class SecretChecker {

    record SecretPattern(String label, Pattern pattern, String severity, String cwe,
                         String description, String remediation) {}

    private static final List<SecretPattern> PATTERNS = List.of(
        new SecretPattern("AWS Access Key ID", Pattern.compile("(?:AKIA|AIPA|ASIA|AROA)[0-9A-Z]{16}"), SEV_CRITICAL, "CWE-798", "An AWS Access Key ID was found in the response.", "Rotate the key immediately in AWS IAM. Never embed credentials in code or responses."),
        // Tightened S3 URL: require at least 3 chars after the bucket path separator
        new SecretPattern("AWS S3 Bucket URL", Pattern.compile("s3[.\\-](?:[a-z0-9\\-]+\\.)?amazonaws\\.com/[a-zA-Z0-9._\\-]{3,}[a-zA-Z0-9._\\-/]*"), SEV_MEDIUM, "CWE-200", "An S3 bucket URL was found in the response.", "Remove the S3 URL from the response immediately - exposure reveals bucket names enabling enumeration and direct access attempts. Audit the bucket ACL and bucket policy (aws s3api get-bucket-acl; aws s3api get-bucket-policy) and remove any public grants. Block public access at the account level: aws s3control put-public-access-block --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true. Serve private content via pre-signed URLs with short expiry (S3.generate_presigned_url) or CloudFront signed URLs with OAC origin access control. Enable S3 server access logging and CloudTrail S3 data events to detect unauthorised access."),
        new SecretPattern("Google API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"), SEV_CRITICAL, "CWE-798", "A Google API key was found exposed in the response.", "Restrict the key to specific APIs and referrers in the Google Cloud Console. Rotate the key."),
        new SecretPattern("Google OAuth Client Secret", Pattern.compile("GOCSPX-[0-9A-Za-z\\-_]{28}"), SEV_CRITICAL, "CWE-798", "A Google OAuth client secret was found in the response.", "Regenerate the secret in Google Cloud Console. Store it server-side only."),
        new SecretPattern("GitHub Personal Access Token", Pattern.compile("gh[pousr]_[A-Za-z0-9]{36,100}"), SEV_CRITICAL, "CWE-798", "A GitHub Personal Access Token (PAT) was found.", "Revoke the token immediately at github.com/settings/tokens."),
        new SecretPattern("GitHub App Token", Pattern.compile("(ghs|ghu|ghr)_[A-Za-z0-9]{36}"), SEV_CRITICAL, "CWE-798", "A GitHub App installation or user token was found.", "Revoke the token and audit GitHub App permissions."),
        new SecretPattern("GitLab Personal Access Token", Pattern.compile("glpat-[A-Za-z0-9\\-_]{20}"), SEV_CRITICAL, "CWE-798", "A GitLab Personal Access Token was found.", "Revoke the token in GitLab profile settings."),
        new SecretPattern("Stripe Secret Key", Pattern.compile("sk_(live|test)_[0-9a-zA-Z]{24,128}"), SEV_CRITICAL, "CWE-798", "A Stripe secret key was found.", "Roll the key immediately in the Stripe dashboard."),
        new SecretPattern("Stripe Publishable Key", Pattern.compile("pk_(live|test)_[0-9a-zA-Z]{24,128}"), SEV_LOW, "CWE-200", "A Stripe publishable key was found.", "Monitor for unexpected usage in the Stripe dashboard."),
        new SecretPattern("Slack Bot Token", Pattern.compile("xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"), SEV_HIGH, "CWE-798", "A Slack Bot token was found.", "Revoke the token at api.slack.com/apps."),
        new SecretPattern("Slack User Token", Pattern.compile("xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}"), SEV_HIGH, "CWE-798", "A Slack User OAuth token was found.", "Revoke immediately at api.slack.com."),
        new SecretPattern("Slack Webhook URL", Pattern.compile("https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"), SEV_MEDIUM, "CWE-200", "A Slack Incoming Webhook URL was found.", "Rotate the webhook URL in Slack app settings."),
        new SecretPattern("SendGrid API Key", Pattern.compile("SG\\.[A-Za-z0-9\\-_]{22}\\.[A-Za-z0-9\\-_]{40,}"), SEV_HIGH, "CWE-798", "A SendGrid API key was found.", "Revoke the key in SendGrid settings."),
        new SecretPattern("Azure Storage Connection String", Pattern.compile("DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"), SEV_CRITICAL, "CWE-798", "An Azure Storage connection string was found.", "Regenerate both storage account keys immediately in Azure Portal (Storage Account > Access keys > Rotate key) - treat the exposed key as fully compromised. Remove the connection string from all application responses, source code, and config files; use environment variables or Azure Key Vault references instead. Replace shared key authentication with Azure Managed Identity: assign the app a managed identity and grant it the Storage Blob Data Reader/Contributor role on the storage account - this eliminates static credentials entirely. Restrict the storage account firewall to known service CIDRs and enable soft delete and versioning to recover from any malicious writes. Review Azure Monitor storage logs for access using the exposed key."),
        new SecretPattern("RSA Private Key", Pattern.compile("-----BEGIN RSA PRIVATE KEY-----"), SEV_CRITICAL, "CWE-321", "An RSA private key header was found in the response.", "Remove the private key from all server responses immediately and rotate the key pair - the exposed private key must be treated as fully compromised. Audit how the key reached a response: check for path traversal vulnerabilities serving files from the server filesystem, misconfigured static file roots exposing /etc/ssl or .ssh directories, or debug endpoints returning raw file contents. Revoke any certificates signed by this key (notify your CA if a TLS certificate is involved). Generate a new key pair and update all dependent services. Store private keys exclusively in secrets managers (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) and never in the web root or any directory accessible to the web server."),
        new SecretPattern("Generic Private Key", Pattern.compile("-----BEGIN (?:EC|DSA|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY-----"), SEV_CRITICAL, "CWE-321", "A private key was found in the response.", "Remove the private key from all server responses immediately and treat it as compromised. Identify the source: check for path traversal, misconfigured static file serving, or debug endpoints that read arbitrary files. Revoke associated certificates with your CA if a TLS cert is involved. Generate a new key pair, update all services consuming it, and store the replacement exclusively in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Audit web server and application configuration to ensure the web root and static file directories cannot serve .pem, .key, .pfx, or .p12 files."),
        new SecretPattern("Generic Database Connection String", Pattern.compile("(?i)(mysql|postgresql|mongodb|mssql|oracle|jdbc)[+:]?://[^:\\s@]+:[^@\\s]+@[^\\s\"']+"), SEV_CRITICAL, "CWE-798", "A database connection string with embedded credentials was found.", "Remove all connection strings from responses. Use environment variables and secrets management."),
        new SecretPattern("Databricks Personal Access Token", Pattern.compile("dapi[A-Za-z0-9]{32}"), SEV_CRITICAL, "CWE-798", "A Databricks Personal Access Token was found.", "Revoke in Databricks workspace settings."),
        new SecretPattern("HashiCorp Vault Token", Pattern.compile("hvs\\.[A-Za-z0-9]{24,256}"), SEV_CRITICAL, "CWE-798", "A HashiCorp Vault token was found.", "Revoke the token using vault token revoke.")
    );

    // Labels of patterns that need post-match validation before firing
    private static final Set<String> NEEDS_VALIDATION = Set.of(
            "AWS S3 Bucket URL", "Generic Database Connection String");

    // Common CDN/public S3 hostnames — not secret, these are public assets
    private static final Set<String> S3_CDN_HOSTNAMES = Set.of(
            "s3.amazonaws.com", "s3-us-east-1.amazonaws.com", "s3-us-west-2.amazonaws.com",
            "s3-eu-west-1.amazonaws.com", "s3-ap-southeast-1.amazonaws.com");

    // Placeholder passwords commonly used in documentation and tutorials
    private static final Pattern RE_PLACEHOLDER_PWD = Pattern.compile(
            "(?i)^(password|passwd|pass|secret|changeme|yourpassword|" +
            "xxxx+|\\*+|<password>|\\[password\\]|example|test|demo|sample)$");

    public static List<CheckResult> check(String body) {
        List<CheckResult> results = new ArrayList<>();
        if (body == null || body.isEmpty()) return results;
        Set<String> seen = new HashSet<>();
        for (SecretPattern sp : PATTERNS) {
            if (seen.contains(sp.label())) continue;
            Matcher m = sp.pattern().matcher(body);
            if (!m.find()) continue;

            // Post-match validation for noisy patterns
            if (NEEDS_VALIDATION.contains(sp.label())) {
                if (!isValidMatch(sp.label(), m, body)) continue;
            }

            seen.add(sp.label());
            String matched = m.group(0);
            // Expose only the first 3 characters — enough for type identification
            // (e.g. "ghp" for GitHub PAT, "sk_" for Stripe) without providing
            // a meaningful prefix for brute-force against structured token formats.
            int visibleLen = Math.min(3, matched.length());
            String visible = matched.substring(0, visibleLen);
            String masked  = visible + "*".repeat(Math.min(matched.length() - visibleLen, 20));
            int start = Math.max(0, m.start() - 30);
            int end   = Math.min(body.length(), m.end() + 30);
            String ctx      = body.substring(start, end).replace("\n", " ").replace("\r", "");
            String ctxMasked = ctx.replace(matched, masked);
            String evidence = "Pattern matched: " + masked + "  |  Context: ..." + trunc(ctxMasked, 80) + "...";
            results.add(new CheckResult("Secret Detected: " + sp.label(),
                sp.severity(), sp.description(), evidence, sp.remediation(), sp.cwe()));
        }
        return results;
    }

    private static boolean isValidMatch(String label, Matcher m, String body) {
        String matched = m.group(0);
        switch (label) {
            case "AWS S3 Bucket URL" -> {
                // Skip if the matched URL is a well-known public CDN S3 hostname with no bucket path
                // that looks like a static asset (image, font, js, css)
                String lower = matched.toLowerCase();
                if (lower.matches(".*\\.(jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|eot|css|js|map).*"))
                    return false;
                // Skip known public CDN patterns like s3.amazonaws.com/bucket/public/
                for (String cdn : S3_CDN_HOSTNAMES) {
                    if (lower.startsWith(cdn) && lower.contains("/public/"))
                        return false;
                }
                return true;
            }
            case "Generic Database Connection String" -> {
                // Extract the password segment (between : and @)
                // Pattern: scheme://user:password@host
                java.util.regex.Matcher pwdM = Pattern.compile(
                    "://[^:@\\s]+:([^@\\s\"']+)@").matcher(matched);
                if (pwdM.find()) {
                    String password = pwdM.group(1);
                    // Skip placeholder/example passwords
                    if (RE_PLACEHOLDER_PWD.matcher(password).matches()) return false;
                    // Skip if password is suspiciously short (1-3 chars — likely a stub)
                    if (password.length() < 4) return false;
                }
                return true;
            }
            default -> { return true; }
        }
    }
}
