package dev.bluestep.http.signatures;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import tools.jackson.databind.ObjectMapper;

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
 * <p>
 * <strong>Sign the bytes you send.</strong> The {@code Digest} header is a SHA-256 over the body's
 * UTF-8 bytes, and the verifier digests the raw body it received. Prefer the {@code String}-body
 * {@code signRequest} overloads, which digest exactly the string the caller then sends. The
 * {@code Object}-body overloads serialize with this service's Jackson 3 {@link ObjectMapper}; they
 * are only correct when the caller sends that same serialization (not one produced again by an
 * HTTP client's own message converter, whose mapper may order properties differently).
 * 
 * @author Bluestep Systems
 * @version 2.0.0
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
     * @param objectMapper Jackson 3 ObjectMapper used by the {@code Object}-body {@code signRequest}
     *                     overloads to serialize the body
     */
    public HttpSignatureService(final ObjectMapper objectMapper) {
        this(objectMapper, "default-key");
    }

    /**
     * Creates a new HttpSignatureService with custom key ID.
     * 
     * @param objectMapper Jackson 3 ObjectMapper used by the {@code Object}-body {@code signRequest}
     *                     overloads to serialize the body
     * @param defaultKeyId Default key identifier for signatures
     */
    public HttpSignatureService(final ObjectMapper objectMapper, final String defaultKeyId) {
        this.objectMapper = objectMapper;
        this.defaultKeyId = defaultKeyId;
    }

    /**
     * Signs an HTTP request whose body is already serialized, and returns the signature headers.
     * <p>
     * The {@code Digest} header is the SHA-256 of exactly the UTF-8 bytes of {@code serializedBody},
     * and {@code Content-Length} is that byte count. No serializer is involved: <strong>the caller
     * MUST send exactly this string, encoded as UTF-8, as the request body</strong>. Any other bytes
     * (a re-serialization, a different charset, added whitespace) fail verification.
     * <p>
     * A {@code null} or empty body is signed as a request without a body: no {@code Digest} or
     * {@code Content-Length} header is set and the signing string omits the digest line, which is
     * how {@link #verifyRequest} treats a {@code null} or empty received body.
     * <p>
     * An argument whose static type is {@code String} binds to this overload, so it is signed
     * verbatim rather than serialized as a JSON string value.
     *
     * @param method HTTP method (e.g., "POST", "GET")
     * @param path Request path (e.g., "/api/endpoint")
     * @param host Target host (e.g., "api.example.com")
     * @param headers Existing request headers (will be modified; null to start empty)
     * @param serializedBody The exact request body that will be sent (null or empty for no body)
     * @param secretKey Shared secret for HMAC signing
     * @param keyId Key identifier (null to use default)
     * @return HttpSignatureHeaders containing all signature-related headers
     */
    public HttpSignatureHeaders signRequest(final String method, final String path, final String host,
                                          HttpHeaders headers, final String serializedBody,
                                          final String secretKey, final String keyId) {

        if (headers == null) {
            headers = new HttpHeaders();
        }

        final String actualKeyId = keyId != null ? keyId : defaultKeyId;
        
        // Add required headers for HTTP Message Signatures
        final String dateValue = createHttpDateHeader();
        headers.set(DATE_HEADER, dateValue);
        headers.set("Host", host);
        
        // Calculate content digest (SHA-256 of the exact body bytes)
        String digest = "";
        if (serializedBody != null && !serializedBody.isEmpty()) {
            final byte[] bodyBytes = serializedBody.getBytes(StandardCharsets.UTF_8);
            digest = "SHA-256=" + sha256Base64(bodyBytes);
            headers.set(DIGEST_HEADER, digest);
            headers.set("Content-Length", String.valueOf(bodyBytes.length));
        }

        // Create canonical string to sign (following HTTP Message Signatures pattern)
        final String signingString = createSigningString(method, path, host, dateValue, digest);
        
        // Generate HMAC-SHA256 signature
        final String signatureValue = createHmacSignature(signingString, secretKey);
        
        // Create signature header in standard format
        final String signatureHeader = String.format(
            "keyId=\"%s\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date digest\",signature=\"%s\"",
            actualKeyId, signatureValue
        );
        
        headers.set(SIGNATURE_HEADER, signatureHeader);

        return new HttpSignatureHeaders(headers);
    }

    /**
     * Signs an already-serialized request body with the default key ID.
     * <p>
     * See {@link #signRequest(String, String, String, HttpHeaders, String, String, String)}:
     * <strong>the caller MUST send exactly {@code serializedBody}</strong>, UTF-8 encoded.
     *
     * @param method HTTP method (e.g., "POST", "GET")
     * @param path Request path (e.g., "/api/endpoint")
     * @param host Target host (e.g., "api.example.com")
     * @param headers Existing request headers (will be modified; null to start empty)
     * @param serializedBody The exact request body that will be sent (null or empty for no body)
     * @param secretKey Shared secret for HMAC signing
     * @return HttpSignatureHeaders containing all signature-related headers
     */
    public HttpSignatureHeaders signRequest(final String method, final String path, final String host,
                                          final HttpHeaders headers, final String serializedBody,
                                          final String secretKey) {
        return signRequest(method, path, host, headers, serializedBody, secretKey, null);
    }

    /**
     * Convenience: serializes {@code body} with this service's {@link ObjectMapper} and signs the
     * result via {@link #signRequest(String, String, String, HttpHeaders, String, String, String)}.
     * <p>
     * The digest covers {@code objectMapper.writeValueAsString(body)}, so the caller must send that
     * same JSON. If an HTTP client will serialize {@code body} itself, serialize it once instead and
     * use the {@code String} overload, sending the string it signed.
     *
     * @param method HTTP method (e.g., "POST", "GET")
     * @param path Request path (e.g., "/api/endpoint")
     * @param host Target host (e.g., "api.example.com")
     * @param headers Existing request headers (will be modified; null to start empty)
     * @param body Request body object (null for no body)
     * @param secretKey Shared secret for HMAC signing
     * @param keyId Key identifier (null to use default)
     * @return HttpSignatureHeaders containing all signature-related headers
     * @throws tools.jackson.core.JacksonException (unchecked) if body serialization fails
     */
    public HttpSignatureHeaders signRequest(final String method, final String path, final String host,
                                          final HttpHeaders headers, final Object body,
                                          final String secretKey, final String keyId) {
        final String serializedBody = body != null ? objectMapper.writeValueAsString(body) : null;
        return signRequest(method, path, host, headers, serializedBody, secretKey, keyId);
    }

    /**
     * Convenience: serializes {@code body} with this service's {@link ObjectMapper} and signs the
     * result with the default key ID. The caller must send that same JSON; see
     * {@link #signRequest(String, String, String, HttpHeaders, Object, String, String)}.
     *
     * @param method HTTP method (e.g., "POST", "GET")
     * @param path Request path (e.g., "/api/endpoint")
     * @param host Target host (e.g., "api.example.com")
     * @param headers Existing request headers (will be modified; null to start empty)
     * @param body Request body object (null for no body)
     * @param secretKey Shared secret for HMAC signing
     * @return HttpSignatureHeaders containing all signature-related headers
     * @throws tools.jackson.core.JacksonException (unchecked) if body serialization fails
     */
    public HttpSignatureHeaders signRequest(final String method, final String path, final String host,
                                          final HttpHeaders headers, final Object body, final String secretKey) {
        return signRequest(method, path, host, headers, body, secretKey, null);
    }

    /**
     * Verifies an HTTP request signature.
     * <p>
     * The digest is computed over the UTF-8 bytes of {@code body} exactly as given; nothing is
     * re-serialized, so pass the raw body as received. Fail-safe: any failed check or exception
     * yields {@code false}. Signature and digest comparisons are constant-time.
     * 
     * @param method HTTP method from the request
     * @param path Request path
     * @param headers Request headers containing signature
     * @param body Raw request body as received (null or empty for no body)
     * @param secretKey Shared secret for verification
     * @return true if signature is valid and timestamp is within acceptable range
     */
    public boolean verifyRequest(final String method, final String path, final HttpHeaders headers, 
                               final String body, final String secretKey) {
        try {
            final String signatureHeader = headers.getFirst(SIGNATURE_HEADER);
            if (signatureHeader == null) {
                return false;
            }

            final String dateValue = headers.getFirst(DATE_HEADER);
            if (dateValue == null) {
                return false;
            }

            final String host = headers.getFirst("Host");
            if (host == null) {
                return false;
            }

            // Check timestamp (5-minute window)
            if (!isDateValid(dateValue)) {
                return false;
            }

            // Calculate expected digest over the raw received bytes
            String expectedDigest = "";
            if (body != null && !body.isEmpty()) {
                expectedDigest = "SHA-256=" + sha256Base64(body.getBytes(StandardCharsets.UTF_8));
                final String receivedDigest = headers.getFirst(DIGEST_HEADER);
                if (receivedDigest == null || !constantTimeEquals(expectedDigest, receivedDigest)) {
                    return false;
                }
            }

            // Recreate signing string
            final String signingString = createSigningString(method, path, host, dateValue, expectedDigest);

            // Extract signature from header
            final String signature = extractSignatureFromHeader(signatureHeader);
            if (signature == null) {
                return false;
            }

            // Verify signature
            final String expectedSignature = createHmacSignature(signingString, secretKey);
            return constantTimeEquals(expectedSignature, signature);

        } catch (final Exception e) {
            return false;
        }
    }

    /**
     * Compares two strings in constant time (over their UTF-8 bytes) to prevent timing attacks.
     */
    private static boolean constantTimeEquals(final String expected, final String actual) {
        return MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            actual.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Creates the canonical signing string following HTTP Message Signatures specification.
     */
    private String createSigningString(final String method, final String path, final String host, final String date, final String digest) {
        final StringBuilder sb = new StringBuilder();
        
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
    private String createHmacSignature(final String signingString, final String secret) {
        try {
            final Mac mac = Mac.getInstance(SIGNATURE_ALGORITHM);
            final SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), SIGNATURE_ALGORITHM);
            mac.init(keySpec);
            
            final byte[] signatureBytes = mac.doFinal(signingString.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signatureBytes);
            
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to create HMAC signature", e);
        }
    }

    /**
     * Creates the Base64 SHA-256 hash of the exact body bytes for the HTTP Digest header.
     */
    private String sha256Base64(final byte[] content) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hashBytes = digest.digest(content);
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (final NoSuchAlgorithmException e) {
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
    private boolean isDateValid(final String dateStr) {
        try {
            final Instant headerTime = Instant.from(java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.parse(dateStr));
            final long now = Instant.now().toEpochMilli();
            final long headerTimeMs = headerTime.toEpochMilli();
            final long fiveMinutes = 5 * 60 * 1000;
            return Math.abs(now - headerTimeMs) <= fiveMinutes;
        } catch (final Exception e) {
            return false;
        }
    }

    /**
     * Extracts signature value from Signature header.
     */
    private String extractSignatureFromHeader(final String signatureHeader) {
        // Parse: keyId="...",algorithm="...",headers="...",signature="..."
        final String[] parts = signatureHeader.split(",");
        for (final String part : parts) {
            if (part.trim().startsWith("signature=")) {
                return part.substring(part.indexOf("\"") + 1, part.lastIndexOf("\""));
            }
        }
        return null;
    }

    //#region Query Parameter Signature Methods

    /**
     * Default maximum age for query parameter signatures (5 minutes).
     */
    private static final Duration DEFAULT_MAX_SIGNATURE_AGE = Duration.ofMinutes(5);

    /**
     * Signs query parameters for secure URL generation.
     * <p>
     * This method creates an HMAC-SHA256 signature over the provided parameters
     * plus a timestamp. The signature prevents tampering and the timestamp
     * prevents replay attacks.
     * <p>
     * Usage example:
     * <pre>{@code
     * Map<String, String> params = Map.of(
     *     "host", "example.com",
     *     "destUrl", "/callback",
     *     "userToken", "abc123"
     * );
     * QueryParameterSignature signed = service.signQueryParameters(params, secretKey);
     * String url = signed.toUrl("https://oauth.example.com/initiate");
     * // Result: https://oauth.example.com/initiate?host=example.com&destUrl=%2Fcallback&userToken=abc123&_sig_ts=1234567890&_sig=...
     * }</pre>
     *
     * @param parameters The parameters to sign (will not be modified)
     * @param secretKey  The shared secret for HMAC signing
     * @return QueryParameterSignature containing original params plus signature metadata
     */
    public QueryParameterSignature signQueryParameters(final Map<String, String> parameters, final String secretKey) {
        final long timestamp = Instant.now().toEpochMilli();
        final String signingString = createQuerySigningString(parameters, timestamp);
        final String signature = createHmacSignatureUrlSafe(signingString, secretKey);
        return new QueryParameterSignature(parameters, timestamp, signature);
    }

    /**
     * Verifies a query parameter signature.
     * <p>
     * This method validates that:
     * <ul>
     *   <li>The timestamp is within the acceptable window (default: 5 minutes)</li>
     *   <li>The signature matches the expected HMAC-SHA256 value</li>
     * </ul>
     * <p>
     * Constant-time comparison is used to prevent timing attacks.
     *
     * @param parameters The parameters to verify (including _sig_ts and _sig)
     * @param secretKey  The shared secret for verification
     * @return QuerySignatureVerificationResult indicating success or failure with reason
     */
    public QuerySignatureVerificationResult verifyQueryParameters(final Map<String, String> parameters, final String secretKey) {
        return verifyQueryParameters(parameters, secretKey, DEFAULT_MAX_SIGNATURE_AGE);
    }

    /**
     * Verifies a query parameter signature with custom max age.
     *
     * @param parameters The parameters to verify (including _sig_ts and _sig)
     * @param secretKey  The shared secret for verification
     * @param maxAge     Maximum allowed age for the signature
     * @return QuerySignatureVerificationResult indicating success or failure with reason
     */
    public QuerySignatureVerificationResult verifyQueryParameters(final Map<String, String> parameters, final String secretKey, final Duration maxAge) {

        // Extract signature metadata
        final String timestampStr = parameters.get(QueryParameterSignature.TIMESTAMP_PARAM);
        final String signature = parameters.get(QueryParameterSignature.SIGNATURE_PARAM);

        if (timestampStr == null || timestampStr.isEmpty()) {
            return QuerySignatureVerificationResult.failure("Missing timestamp parameter");
        }

        if (signature == null || signature.isEmpty()) {
            return QuerySignatureVerificationResult.failure("Missing signature parameter");
        }

        // Parse timestamp
        final long timestamp;
        try {
            timestamp = Long.parseLong(timestampStr);
        } catch (final NumberFormatException e) {
            return QuerySignatureVerificationResult.failure("Invalid timestamp format");
        }

        // Validate timestamp is within acceptable window
        final Instant requestTime = Instant.ofEpochMilli(timestamp);
        final Instant now = Instant.now();
        final Duration age = Duration.between(requestTime, now);

        if (age.isNegative()) {
            // Request is from the future - allow small clock skew (1 minute)
            if (age.abs().compareTo(Duration.ofMinutes(1)) > 0) {
                return QuerySignatureVerificationResult.failure("Timestamp is in the future");
            }
        } else if (age.compareTo(maxAge) > 0) {
            return QuerySignatureVerificationResult.failure("Signature has expired");
        }

        // Extract original parameters (without signature metadata)
        final Map<String, String> originalParams = new LinkedHashMap<>();
        for (final var entry : parameters.entrySet()) {
            final String key = entry.getKey();
            if (!QueryParameterSignature.TIMESTAMP_PARAM.equals(key)
                    && !QueryParameterSignature.SIGNATURE_PARAM.equals(key)) {
                originalParams.put(key, entry.getValue());
            }
        }

        // Compute expected signature
        final String signingString = createQuerySigningString(originalParams, timestamp);
        final String expectedSignature = createHmacSignatureUrlSafe(signingString, secretKey);

        // Constant-time comparison to prevent timing attacks
        if (!MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8))) {
            return QuerySignatureVerificationResult.failure("Invalid signature");
        }

        return QuerySignatureVerificationResult.success(originalParams);
    }

    /**
     * Creates the canonical signing string for query parameters.
     * <p>
     * Parameters are sorted alphabetically by key, then concatenated as
     * {@code key=value} pairs joined by {@code &}. The timestamp is appended last.
     * <p>
     * This ensures consistent ordering regardless of how parameters were provided.
     */
    private String createQuerySigningString(final Map<String, String> parameters, final long timestamp) {
        // Sort parameters alphabetically for consistent signing
        final TreeMap<String, String> sorted = new TreeMap<>(parameters);

        final StringBuilder sb = new StringBuilder();
        for (final var entry : sorted.entrySet()) {
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }
        sb.append("&").append(QueryParameterSignature.TIMESTAMP_PARAM).append("=").append(timestamp);

        return sb.toString();
    }

    /**
     * Creates HMAC-SHA256 signature with URL-safe Base64 encoding (no padding).
     */
    private String createHmacSignatureUrlSafe(final String signingString, final String secret) {
        try {
            final Mac mac = Mac.getInstance(SIGNATURE_ALGORITHM);
            final SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), SIGNATURE_ALGORITHM);
            mac.init(keySpec);

            final byte[] signatureBytes = mac.doFinal(signingString.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to create HMAC signature", e);
        }
    }

    /**
     * Result of query parameter signature verification.
     *
     * @param valid        whether the signature verified
     * @param errorMessage why verification failed, or null on success
     * @param parameters   the verified original parameters (without signature metadata), or null on failure
     */
    public record QuerySignatureVerificationResult(boolean valid, String errorMessage, Map<String, String> parameters) {

        /**
         * Creates a successful verification result.
         *
         * @param parameters The verified original parameters (without signature metadata)
         * @return Successful result
         */
        public static QuerySignatureVerificationResult success(final Map<String, String> parameters) {
            return new QuerySignatureVerificationResult(true, null, new LinkedHashMap<>(parameters));
        }

        /**
         * Creates a failed verification result.
         *
         * @param message Description of why verification failed
         * @return Failed result
         */
        public static QuerySignatureVerificationResult failure(final String message) {
            return new QuerySignatureVerificationResult(false, message, null);
        }
    }
	//#endregion
}