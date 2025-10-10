package dev.bluestep.http.signatures;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Service for creating secure HTTP request signatures using HTTP Message Signatures patterns.
 * 
 * This library implements industry-standard HTTP request signing that provides:
 * - HMAC-SHA256 signatures for cryptographic security
 * - Request-target signing to prevent endpoint confusion
 * - Host header signing to prevent cross-host attacks
 * - Date-based replay protection (5-minute window)
 * - Content digest for body integrity verification
 * - Standard signature headers for interoperability
 * 
 * Security improvements over custom implementations:
 * - Uses proven HMAC-SHA256 instead of custom hash functions
 * - Follows HTTP Message Signatures specification patterns
 * - Includes comprehensive request metadata in signature
 * - Provides both signing and verification capabilities
 * - Easy to debug with standard headers
 * 
 * @author Bluestep Systems
 * @version 1.0.0
 */
public class HttpSignatureService {

    private static final String SIGNATURE_ALGORITHM = "HmacSHA256";
    private static final String SIGNATURE_HEADER = "Signature";
    private static final String DIGEST_HEADER = "Digest";
    private static final String DATE_HEADER = "Date";
    
    private final ObjectMapper objectMapper;
    private final String defaultKeyId;

    /**
     * Creates a new HttpSignatureService with default configuration.
     * 
     * @param objectMapper Jackson ObjectMapper for JSON serialization
     */
    public HttpSignatureService(ObjectMapper objectMapper) {
        this(objectMapper, "default-key");
    }

    /**
     * Creates a new HttpSignatureService with custom key ID.
     * 
     * @param objectMapper Jackson ObjectMapper for JSON serialization
     * @param defaultKeyId Default key identifier for signatures
     */
    public HttpSignatureService(ObjectMapper objectMapper, String defaultKeyId) {
        this.objectMapper = objectMapper;
        this.defaultKeyId = defaultKeyId;
    }

    /**
     * Signs HTTP request data and returns signature headers.
     * 
     * @param method HTTP method (e.g., "POST", "GET")
     * @param path Request path (e.g., "/api/endpoint")
     * @param host Target host (e.g., "api.example.com")
     * @param headers Existing request headers (will be modified)
     * @param body Request body object (null for no body)
     * @param secretKey Shared secret for HMAC signing
     * @param keyId Key identifier (null to use default)
     * @return HttpSignatureHeaders containing all signature-related headers
     * @throws JsonProcessingException if body serialization fails
     */
    public HttpSignatureHeaders signRequest(String method, String path, String host, 
                                          HttpHeaders headers, Object body, 
                                          String secretKey, String keyId) 
            throws JsonProcessingException {
        
        if (headers == null) {
            headers = new HttpHeaders();
        }

        String actualKeyId = keyId != null ? keyId : defaultKeyId;
        
        // Add required headers for HTTP Message Signatures
        String dateValue = createHttpDateHeader();
        headers.set(DATE_HEADER, dateValue);
        headers.set("Host", host);
        
        // Calculate content digest (SHA-256 of body)
        String digest = "";
        if (body != null) {
            String bodyJson = objectMapper.writeValueAsString(body);
            digest = "SHA-256=" + sha256Base64(bodyJson);
            headers.set(DIGEST_HEADER, digest);
            headers.set("Content-Length", String.valueOf(bodyJson.getBytes(StandardCharsets.UTF_8).length));
        }

        // Create canonical string to sign (following HTTP Message Signatures pattern)
        String signingString = createSigningString(method, path, host, dateValue, digest);
        
        // Generate HMAC-SHA256 signature
        String signatureValue = createHmacSignature(signingString, secretKey);
        
        // Create signature header in standard format
        String signatureHeader = String.format(
            "keyId=\"%s\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date digest\",signature=\"%s\"",
            actualKeyId, signatureValue
        );
        
        headers.set(SIGNATURE_HEADER, signatureHeader);

        return new HttpSignatureHeaders(headers);
    }

    /**
     * Convenience method for signing with default key ID.
     */
    public HttpSignatureHeaders signRequest(String method, String path, String host, 
                                          HttpHeaders headers, Object body, String secretKey) 
            throws JsonProcessingException {
        return signRequest(method, path, host, headers, body, secretKey, null);
    }

    /**
     * Verifies an HTTP request signature.
     * 
     * @param method HTTP method from the request
     * @param path Request path
     * @param headers Request headers containing signature
     * @param body Request body as string (null for no body)
     * @param secretKey Shared secret for verification
     * @return true if signature is valid and timestamp is within acceptable range
     */
    public boolean verifyRequest(String method, String path, HttpHeaders headers, 
                               String body, String secretKey) {
        try {
            String signatureHeader = headers.getFirst(SIGNATURE_HEADER);
            if (signatureHeader == null) return false;

            String dateValue = headers.getFirst(DATE_HEADER);
            if (dateValue == null) return false;

            String host = headers.getFirst("Host");
            if (host == null) return false;

            // Check timestamp (5-minute window)
            if (!isDateValid(dateValue)) return false;

            // Calculate expected digest
            String expectedDigest = "";
            if (body != null && !body.isEmpty()) {
                expectedDigest = "SHA-256=" + sha256Base64(body);
                String receivedDigest = headers.getFirst(DIGEST_HEADER);
                if (!expectedDigest.equals(receivedDigest)) return false;
            }

            // Recreate signing string
            String signingString = createSigningString(method, path, host, dateValue, expectedDigest);

            // Extract signature from header
            String signature = extractSignatureFromHeader(signatureHeader);
            if (signature == null) return false;

            // Verify signature
            String expectedSignature = createHmacSignature(signingString, secretKey);
            return signature.equals(expectedSignature);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Creates the canonical signing string following HTTP Message Signatures specification.
     */
    private String createSigningString(String method, String path, String host, String date, String digest) {
        StringBuilder sb = new StringBuilder();
        
        // (request-target) - HTTP method and path
        sb.append("(request-target): ").append(method.toLowerCase()).append(" ").append(path).append("\n");
        
        // host - prevents cross-host replay attacks
        sb.append("host: ").append(host.toLowerCase()).append("\n");
        
        // date - prevents replay attacks (should be validated within 5 minutes)
        sb.append("date: ").append(date).append("\n");
        
        // digest - ensures body integrity
        if (!digest.isEmpty()) {
            sb.append("digest: ").append(digest);
        } else {
            // Remove trailing newline if no digest
            sb.setLength(sb.length() - 1);
        }
        
        return sb.toString();
    }

    /**
     * Creates HMAC-SHA256 signature.
     */
    private String createHmacSignature(String signingString, String secret) {
        try {
            Mac mac = Mac.getInstance(SIGNATURE_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), SIGNATURE_ALGORITHM);
            mac.init(keySpec);
            
            byte[] signatureBytes = mac.doFinal(signingString.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signatureBytes);
            
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to create HMAC signature", e);
        }
    }

    /**
     * Creates SHA-256 hash of content for HTTP Digest header.
     */
    private String sha256Base64(String content) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Creates a properly formatted HTTP Date header.
     */
    private String createHttpDateHeader() {
        return java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME
            .withZone(java.time.ZoneId.of("GMT"))
            .format(Instant.now());
    }

    /**
     * Validates if a date string is within acceptable range (5 minutes).
     */
    private boolean isDateValid(String dateStr) {
        try {
            Instant headerTime = Instant.from(java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.parse(dateStr));
            long now = Instant.now().toEpochMilli();
            long headerTimeMs = headerTime.toEpochMilli();
            long fiveMinutes = 5 * 60 * 1000;
            return Math.abs(now - headerTimeMs) <= fiveMinutes;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extracts signature value from Signature header.
     */
    private String extractSignatureFromHeader(String signatureHeader) {
        // Parse: keyId="...",algorithm="...",headers="...",signature="..."
        String[] parts = signatureHeader.split(",");
        for (String part : parts) {
            if (part.trim().startsWith("signature=")) {
                return part.substring(part.indexOf("\"") + 1, part.lastIndexOf("\""));
            }
        }
        return null;
    }
}