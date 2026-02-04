package dev.bluestep.http.signatures;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite for HttpSignatureService.
 * Tests signing, verification, security validations, and edge cases.
 */
class HttpSignatureServiceTest {

    private HttpSignatureService service;
    private ObjectMapper objectMapper;
    private static final String TEST_SECRET = "test-secret-key-12345";
    private static final String TEST_HOST = "api.example.com";
    private static final String TEST_PATH = "/api/test";
    private static final String TEST_METHOD = "POST";

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        service = new HttpSignatureService(objectMapper);
    }

    // ========== Signing Tests ==========

    @Test
    @DisplayName("Should sign request with all required headers")
    void testSignRequest_CreatesAllRequiredHeaders() throws Exception {
        Map<String, String> body = Map.of("key", "value");
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders result = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, body, TEST_SECRET
        );

        assertNotNull(result.getSignature(), "Signature header should be present");
        assertNotNull(result.getDate(), "Date header should be present");
        assertNotNull(result.getHost(), "Host header should be present");
        assertNotNull(result.getDigest(), "Digest header should be present");
    }

    @Test
    @DisplayName("Should create signature header with correct format")
    void testSignRequest_SignatureHeaderFormat() throws Exception {
        Map<String, String> body = Map.of("test", "data");
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders result = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, body, TEST_SECRET
        );

        String signature = result.getSignature();
        assertTrue(signature.contains("keyId="), "Should contain keyId");
        assertTrue(signature.contains("algorithm=\"hmac-sha256\""), "Should specify algorithm");
        assertTrue(signature.contains("headers=\"(request-target) host date digest\""), "Should list signed headers");
        assertTrue(signature.contains("signature="), "Should contain signature value");
    }

    @Test
    @DisplayName("Should use custom key ID when provided")
    void testSignRequest_CustomKeyId() throws Exception {
        String customKeyId = "custom-key-123";
        HttpSignatureService customService = new HttpSignatureService(objectMapper, customKeyId);

        HttpHeaders headers = new HttpHeaders();
        HttpSignatureHeaders result = customService.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
        );

        assertTrue(result.getSignature().contains("keyId=\"" + customKeyId + "\""),
            "Should use custom key ID");
    }

    @Test
    @DisplayName("Should create valid Date header in RFC 1123 format")
    void testSignRequest_DateHeaderFormat() throws Exception {
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders result = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
        );

        String dateHeader = result.getDate();
        assertNotNull(dateHeader);

        // Should be parseable as RFC 1123 date
        assertDoesNotThrow(() ->
            DateTimeFormatter.RFC_1123_DATE_TIME.parse(dateHeader),
            "Date should be in RFC 1123 format"
        );
    }

    @Test
    @DisplayName("Should create SHA-256 digest for request body")
    void testSignRequest_DigestCreation() throws Exception {
        Map<String, String> body = Map.of("key", "value");
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders result = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, body, TEST_SECRET
        );

        String digest = result.getDigest();
        assertNotNull(digest);
        assertTrue(digest.startsWith("SHA-256="), "Digest should start with SHA-256=");
        assertTrue(digest.length() > 15, "Digest should contain base64 hash");
    }

    @Test
    @DisplayName("Should handle null body without digest")
    void testSignRequest_NullBody() throws Exception {
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders result = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
        );

        assertNotNull(result.getSignature(), "Should still create signature");
        assertNull(result.getDigest(), "Should not create digest for null body");
    }

    @Test
    @DisplayName("Should handle null headers parameter")
    void testSignRequest_NullHeaders() throws Exception {
        HttpSignatureHeaders result = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, null, null, TEST_SECRET
        );

        assertNotNull(result.getSignature(), "Should create signature with null headers");
    }

    @Test
    @DisplayName("Should add Content-Length header when body present")
    void testSignRequest_ContentLength() throws Exception {
        Map<String, String> body = Map.of("key", "value");
        HttpHeaders headers = new HttpHeaders();

        service.signRequest(TEST_METHOD, TEST_PATH, TEST_HOST, headers, body, TEST_SECRET);

        assertNotNull(headers.getFirst("Content-Length"), "Should set Content-Length");
        assertTrue(Integer.parseInt(headers.getFirst("Content-Length")) > 0);
    }

    // ========== Verification Tests ==========

    @Test
    @DisplayName("Should verify valid signature successfully")
    void testVerifyRequest_ValidSignature() throws Exception {
        Map<String, String> body = Map.of("key", "value");
        String bodyJson = objectMapper.writeValueAsString(body);
        HttpHeaders headers = new HttpHeaders();

        // Sign the request
        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, body, TEST_SECRET
        );

        // Verify the signature
        boolean valid = service.verifyRequest(
            TEST_METHOD, TEST_PATH, signedHeaders.getAllHeaders(), bodyJson, TEST_SECRET
        );

        assertTrue(valid, "Valid signature should verify successfully");
    }

    @Test
    @DisplayName("Should reject request with missing Signature header")
    void testVerifyRequest_MissingSignature() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Date", createRFC1123Date());
        headers.set("Host", TEST_HOST);

        boolean valid = service.verifyRequest(TEST_METHOD, TEST_PATH, headers, null, TEST_SECRET);

        assertFalse(valid, "Should reject request without Signature header");
    }

    @Test
    @DisplayName("Should reject request with missing Date header")
    void testVerifyRequest_MissingDate() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Signature", "keyId=\"test\",algorithm=\"hmac-sha256\",signature=\"abc\"");
        headers.set("Host", TEST_HOST);

        boolean valid = service.verifyRequest(TEST_METHOD, TEST_PATH, headers, null, TEST_SECRET);

        assertFalse(valid, "Should reject request without Date header");
    }

    @Test
    @DisplayName("Should reject request with missing Host header")
    void testVerifyRequest_MissingHost() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Signature", "keyId=\"test\",algorithm=\"hmac-sha256\",signature=\"abc\"");
        headers.set("Date", createRFC1123Date());

        boolean valid = service.verifyRequest(TEST_METHOD, TEST_PATH, headers, null, TEST_SECRET);

        assertFalse(valid, "Should reject request without Host header");
    }

    @Test
    @DisplayName("Should reject request with incorrect secret")
    void testVerifyRequest_WrongSecret() throws Exception {
        Map<String, String> body = Map.of("key", "value");
        String bodyJson = objectMapper.writeValueAsString(body);
        HttpHeaders headers = new HttpHeaders();

        // Sign with one secret
        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, body, TEST_SECRET
        );

        // Verify with different secret
        boolean valid = service.verifyRequest(
            TEST_METHOD, TEST_PATH, signedHeaders.getAllHeaders(), bodyJson, "wrong-secret"
        );

        assertFalse(valid, "Should reject signature with wrong secret");
    }

    @Test
    @DisplayName("Should reject request with modified body")
    void testVerifyRequest_TamperedBody() throws Exception {
        Map<String, String> originalBody = Map.of("key", "value");
        Map<String, String> tamperedBody = Map.of("key", "tampered");
        String tamperedJson = objectMapper.writeValueAsString(tamperedBody);
        HttpHeaders headers = new HttpHeaders();

        // Sign original body
        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, originalBody, TEST_SECRET
        );

        // Verify with tampered body
        boolean valid = service.verifyRequest(
            TEST_METHOD, TEST_PATH, signedHeaders.getAllHeaders(), tamperedJson, TEST_SECRET
        );

        assertFalse(valid, "Should reject request with modified body");
    }

    @Test
    @DisplayName("Should reject request with modified path")
    void testVerifyRequest_ModifiedPath() throws Exception {
        HttpHeaders headers = new HttpHeaders();

        // Sign with original path
        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
        );

        // Verify with different path
        boolean valid = service.verifyRequest(
            TEST_METHOD, "/different/path", signedHeaders.getAllHeaders(), null, TEST_SECRET
        );

        assertFalse(valid, "Should reject request with modified path");
    }

    @Test
    @DisplayName("Should reject request with modified method")
    void testVerifyRequest_ModifiedMethod() throws Exception {
        HttpHeaders headers = new HttpHeaders();

        // Sign with POST
        HttpSignatureHeaders signedHeaders = service.signRequest(
            "POST", TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
        );

        // Verify with GET
        boolean valid = service.verifyRequest(
            "GET", TEST_PATH, signedHeaders.getAllHeaders(), null, TEST_SECRET
        );

        assertFalse(valid, "Should reject request with modified HTTP method");
    }

    @Test
    @DisplayName("Should reject request with modified host")
    void testVerifyRequest_ModifiedHost() throws Exception {
        HttpHeaders headers = new HttpHeaders();

        // Sign with original host
        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
        );

        // Modify host header
        signedHeaders.getAllHeaders().set("Host", "evil.example.com");

        // Verify
        boolean valid = service.verifyRequest(
            TEST_METHOD, TEST_PATH, signedHeaders.getAllHeaders(), null, TEST_SECRET
        );

        assertFalse(valid, "Should reject request with modified host");
    }

    // ========== Replay Protection Tests ==========

    @Test
    @DisplayName("Should accept request with current timestamp")
    void testVerifyRequest_CurrentTimestamp() throws Exception {
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
        );

        boolean valid = service.verifyRequest(
            TEST_METHOD, TEST_PATH, signedHeaders.getAllHeaders(), null, TEST_SECRET
        );

        assertTrue(valid, "Should accept request with current timestamp");
    }

    @Test
    @DisplayName("Should reject request with expired timestamp")
    void testVerifyRequest_ExpiredTimestamp() {
        HttpHeaders headers = new HttpHeaders();

        // Create date 10 minutes in the past (outside 5-minute window)
        Instant tenMinutesAgo = Instant.now().minusSeconds(10 * 60);
        String expiredDate = DateTimeFormatter.RFC_1123_DATE_TIME
            .withZone(ZoneId.of("GMT"))
            .format(tenMinutesAgo);

        headers.set("Date", expiredDate);
        headers.set("Host", TEST_HOST);
        headers.set("Signature", "keyId=\"test\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date digest\",signature=\"abc123\"");

        boolean valid = service.verifyRequest(TEST_METHOD, TEST_PATH, headers, null, TEST_SECRET);

        assertFalse(valid, "Should reject request with expired timestamp");
    }

    @Test
    @DisplayName("Should reject request with future timestamp")
    void testVerifyRequest_FutureTimestamp() {
        HttpHeaders headers = new HttpHeaders();

        // Create date 10 minutes in the future (outside 5-minute window)
        Instant tenMinutesLater = Instant.now().plusSeconds(10 * 60);
        String futureDate = DateTimeFormatter.RFC_1123_DATE_TIME
            .withZone(ZoneId.of("GMT"))
            .format(tenMinutesLater);

        headers.set("Date", futureDate);
        headers.set("Host", TEST_HOST);
        headers.set("Signature", "keyId=\"test\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date digest\",signature=\"abc123\"");

        boolean valid = service.verifyRequest(TEST_METHOD, TEST_PATH, headers, null, TEST_SECRET);

        assertFalse(valid, "Should reject request with future timestamp");
    }

    @Test
    @DisplayName("Should reject request with invalid date format")
    void testVerifyRequest_InvalidDateFormat() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Date", "not-a-valid-date");
        headers.set("Host", TEST_HOST);
        headers.set("Signature", "keyId=\"test\",algorithm=\"hmac-sha256\",signature=\"abc\"");

        boolean valid = service.verifyRequest(TEST_METHOD, TEST_PATH, headers, null, TEST_SECRET);

        assertFalse(valid, "Should reject request with invalid date format");
    }

    // ========== Edge Cases and Security Tests ==========

    @Test
    @DisplayName("Should handle empty body string")
    void testVerifyRequest_EmptyBodyString() throws Exception {
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
        );

        boolean valid = service.verifyRequest(
            TEST_METHOD, TEST_PATH, signedHeaders.getAllHeaders(), "", TEST_SECRET
        );

        assertTrue(valid, "Should handle empty body string");
    }

    @Test
    @DisplayName("Should reject malformed signature header")
    void testVerifyRequest_MalformedSignatureHeader() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Date", createRFC1123Date());
        headers.set("Host", TEST_HOST);
        headers.set("Signature", "malformed-signature-header");

        boolean valid = service.verifyRequest(TEST_METHOD, TEST_PATH, headers, null, TEST_SECRET);

        assertFalse(valid, "Should reject malformed signature header");
    }

    @Test
    @DisplayName("Should handle case-insensitive header names")
    void testVerifyRequest_CaseInsensitiveHeaders() throws Exception {
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
        );

        // Headers should be case-insensitive
        assertTrue(signedHeaders.getAllHeaders().containsKey("signature"));
        assertTrue(signedHeaders.getAllHeaders().containsKey("date"));
        assertTrue(signedHeaders.getAllHeaders().containsKey("host"));
    }

    @Test
    @DisplayName("Should handle different HTTP methods correctly")
    void testSignAndVerify_DifferentMethods() throws Exception {
        String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH"};

        for (String method : methods) {
            HttpHeaders headers = new HttpHeaders();
            HttpSignatureHeaders signedHeaders = service.signRequest(
                method, TEST_PATH, TEST_HOST, headers, null, TEST_SECRET
            );

            boolean valid = service.verifyRequest(
                method, TEST_PATH, signedHeaders.getAllHeaders(), null, TEST_SECRET
            );

            assertTrue(valid, "Should handle " + method + " method correctly");
        }
    }

    @Test
    @DisplayName("Should handle complex JSON body")
    void testSignAndVerify_ComplexBody() throws Exception {
        Map<String, Object> complexBody = new HashMap<>();
        complexBody.put("string", "value");
        complexBody.put("number", 123);
        complexBody.put("boolean", true);
        complexBody.put("nested", Map.of("key", "nested-value"));
        complexBody.put("array", new String[]{"a", "b", "c"});

        String bodyJson = objectMapper.writeValueAsString(complexBody);
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, complexBody, TEST_SECRET
        );

        boolean valid = service.verifyRequest(
            TEST_METHOD, TEST_PATH, signedHeaders.getAllHeaders(), bodyJson, TEST_SECRET
        );

        assertTrue(valid, "Should handle complex JSON body");
    }

    @Test
    @DisplayName("Should handle path with query parameters")
    void testSignAndVerify_PathWithQueryParams() throws Exception {
        String pathWithQuery = "/api/test?param1=value1&param2=value2";
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders signedHeaders = service.signRequest(
            "GET", pathWithQuery, TEST_HOST, headers, null, TEST_SECRET
        );

        boolean valid = service.verifyRequest(
            "GET", pathWithQuery, signedHeaders.getAllHeaders(), null, TEST_SECRET
        );

        assertTrue(valid, "Should handle path with query parameters");
    }

    @Test
    @DisplayName("Should handle special characters in body")
    void testSignAndVerify_SpecialCharacters() throws Exception {
        Map<String, String> body = Map.of(
            "unicode", "日本語 émojis 🎉",
            "special", "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        );

        String bodyJson = objectMapper.writeValueAsString(body);
        HttpHeaders headers = new HttpHeaders();

        HttpSignatureHeaders signedHeaders = service.signRequest(
            TEST_METHOD, TEST_PATH, TEST_HOST, headers, body, TEST_SECRET
        );

        boolean valid = service.verifyRequest(
            TEST_METHOD, TEST_PATH, signedHeaders.getAllHeaders(), bodyJson, TEST_SECRET
        );

        assertTrue(valid, "Should handle special characters in body");
    }

    // ========== Helper Methods ==========

    private String createRFC1123Date() {
        return DateTimeFormatter.RFC_1123_DATE_TIME
            .withZone(ZoneId.of("GMT"))
            .format(Instant.now());
    }

    // ========== Query Parameter Signature Tests ==========

    @Test
    @DisplayName("Should sign query parameters successfully")
    void testSignQueryParameters_Success() {
        Map<String, String> params = Map.of(
            "host", "example.bluestep.net",
            "destUrl", "/callback",
            "userToken", "abc123"
        );

        QueryParameterSignature result = service.signQueryParameters(params, TEST_SECRET);

        assertNotNull(result, "Should return signature result");
        assertEquals(params, result.getParameters(), "Should preserve original parameters");
        assertTrue(result.getTimestamp() > 0, "Should have valid timestamp");
        assertNotNull(result.getSignature(), "Should have signature");
        assertFalse(result.getSignature().isEmpty(), "Signature should not be empty");
    }

    @Test
    @DisplayName("Should include all parameters in getAllParameters")
    void testSignQueryParameters_AllParameters() {
        Map<String, String> params = Map.of("key", "value");

        QueryParameterSignature result = service.signQueryParameters(params, TEST_SECRET);
        Map<String, String> allParams = result.getAllParameters();

        assertTrue(allParams.containsKey("key"), "Should contain original param");
        assertTrue(allParams.containsKey(QueryParameterSignature.TIMESTAMP_PARAM), "Should contain timestamp");
        assertTrue(allParams.containsKey(QueryParameterSignature.SIGNATURE_PARAM), "Should contain signature");
    }

    @Test
    @DisplayName("Should generate valid query string")
    void testSignQueryParameters_QueryString() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature result = service.signQueryParameters(params, TEST_SECRET);
        String queryString = result.toQueryString();

        assertTrue(queryString.contains("host=example.com"), "Should contain original param");
        assertTrue(queryString.contains("_sig_ts="), "Should contain timestamp param");
        assertTrue(queryString.contains("_sig="), "Should contain signature param");
    }

    @Test
    @DisplayName("Should generate valid URL")
    void testSignQueryParameters_ToUrl() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature result = service.signQueryParameters(params, TEST_SECRET);
        String url = result.toUrl("https://oauth.example.com/initiate");

        assertTrue(url.startsWith("https://oauth.example.com/initiate?"), "Should append query string");
        assertTrue(url.contains("host=example.com"), "Should contain parameters");
    }

    @Test
    @DisplayName("Should append to URL with existing query params")
    void testSignQueryParameters_ToUrlWithExistingParams() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature result = service.signQueryParameters(params, TEST_SECRET);
        String url = result.toUrl("https://oauth.example.com/initiate?existing=param");

        assertTrue(url.contains("existing=param"), "Should preserve existing params");
        assertTrue(url.contains("&host="), "Should append with &");
    }

    @Test
    @DisplayName("Should verify valid query parameter signature")
    void testVerifyQueryParameters_Valid() {
        Map<String, String> params = Map.of(
            "host", "example.bluestep.net",
            "destUrl", "/callback",
            "userToken", "abc123"
        );

        // Sign
        QueryParameterSignature signed = service.signQueryParameters(params, TEST_SECRET);

        // Verify
        var result = service.verifyQueryParameters(signed.getAllParameters(), TEST_SECRET);

        assertTrue(result.valid(), "Should verify successfully");
        assertNull(result.errorMessage(), "Should have no error message");
        assertEquals(params, result.parameters(), "Should return original parameters");
    }

    @Test
    @DisplayName("Should reject missing timestamp")
    void testVerifyQueryParameters_MissingTimestamp() {
        Map<String, String> params = Map.of(
            "host", "example.com",
            QueryParameterSignature.SIGNATURE_PARAM, "somesig"
        );

        var result = service.verifyQueryParameters(params, TEST_SECRET);

        assertFalse(result.valid(), "Should reject");
        assertEquals("Missing timestamp parameter", result.errorMessage());
    }

    @Test
    @DisplayName("Should reject missing signature")
    void testVerifyQueryParameters_MissingSignature() {
        Map<String, String> params = Map.of(
            "host", "example.com",
            QueryParameterSignature.TIMESTAMP_PARAM, String.valueOf(Instant.now().toEpochMilli())
        );

        var result = service.verifyQueryParameters(params, TEST_SECRET);

        assertFalse(result.valid(), "Should reject");
        assertEquals("Missing signature parameter", result.errorMessage());
    }

    @Test
    @DisplayName("Should reject invalid timestamp format")
    void testVerifyQueryParameters_InvalidTimestamp() {
        Map<String, String> params = Map.of(
            "host", "example.com",
            QueryParameterSignature.TIMESTAMP_PARAM, "not-a-number",
            QueryParameterSignature.SIGNATURE_PARAM, "somesig"
        );

        var result = service.verifyQueryParameters(params, TEST_SECRET);

        assertFalse(result.valid(), "Should reject");
        assertEquals("Invalid timestamp format", result.errorMessage());
    }

    @Test
    @DisplayName("Should reject expired signature")
    void testVerifyQueryParameters_Expired() {
        Map<String, String> params = Map.of("host", "example.com");

        // Sign
        QueryParameterSignature signed = service.signQueryParameters(params, TEST_SECRET);

        // Create params with old timestamp
        Map<String, String> expiredParams = new HashMap<>(signed.getAllParameters());
        long tenMinutesAgo = Instant.now().minusSeconds(10 * 60).toEpochMilli();
        expiredParams.put(QueryParameterSignature.TIMESTAMP_PARAM, String.valueOf(tenMinutesAgo));

        var result = service.verifyQueryParameters(expiredParams, TEST_SECRET);

        assertFalse(result.valid(), "Should reject expired signature");
        assertEquals("Signature has expired", result.errorMessage());
    }

    @Test
    @DisplayName("Should reject future timestamp beyond clock skew")
    void testVerifyQueryParameters_FutureTimestamp() {
        Map<String, String> params = Map.of("host", "example.com");

        // Sign
        QueryParameterSignature signed = service.signQueryParameters(params, TEST_SECRET);

        // Create params with future timestamp
        Map<String, String> futureParams = new HashMap<>(signed.getAllParameters());
        long tenMinutesLater = Instant.now().plusSeconds(10 * 60).toEpochMilli();
        futureParams.put(QueryParameterSignature.TIMESTAMP_PARAM, String.valueOf(tenMinutesLater));

        var result = service.verifyQueryParameters(futureParams, TEST_SECRET);

        assertFalse(result.valid(), "Should reject future timestamp");
        assertEquals("Timestamp is in the future", result.errorMessage());
    }

    @Test
    @DisplayName("Should reject tampered parameters")
    void testVerifyQueryParameters_Tampered() {
        Map<String, String> params = Map.of(
            "host", "example.bluestep.net",
            "destUrl", "/callback"
        );

        // Sign
        QueryParameterSignature signed = service.signQueryParameters(params, TEST_SECRET);

        // Tamper with host
        Map<String, String> tamperedParams = new HashMap<>(signed.getAllParameters());
        tamperedParams.put("host", "attacker.com");

        var result = service.verifyQueryParameters(tamperedParams, TEST_SECRET);

        assertFalse(result.valid(), "Should reject tampered parameters");
        assertEquals("Invalid signature", result.errorMessage());
    }

    @Test
    @DisplayName("Should reject wrong secret")
    void testVerifyQueryParameters_WrongSecret() {
        Map<String, String> params = Map.of("host", "example.com");

        // Sign with one secret
        QueryParameterSignature signed = service.signQueryParameters(params, TEST_SECRET);

        // Verify with different secret
        var result = service.verifyQueryParameters(signed.getAllParameters(), "wrong-secret");

        assertFalse(result.valid(), "Should reject wrong secret");
        assertEquals("Invalid signature", result.errorMessage());
    }

    @Test
    @DisplayName("Should handle URL-encoded special characters")
    void testSignQueryParameters_SpecialCharacters() {
        Map<String, String> params = Map.of(
            "destUrl", "/path?foo=bar&baz=qux",
            "userToken", "token+with/special=chars"
        );

        // Sign
        QueryParameterSignature signed = service.signQueryParameters(params, TEST_SECRET);

        // Verify
        var result = service.verifyQueryParameters(signed.getAllParameters(), TEST_SECRET);

        assertTrue(result.valid(), "Should handle special characters");
        assertEquals(params, result.parameters(), "Should preserve original values");
    }

    @Test
    @DisplayName("Should produce consistent signatures for same input")
    void testSignQueryParameters_Deterministic() {
        Map<String, String> params = Map.of(
            "b", "2",
            "a", "1",
            "c", "3"
        );

        // The signing string should sort parameters alphabetically
        // so different ordering of the same params should produce same signature
        // (when timestamp is the same)

        QueryParameterSignature signed1 = service.signQueryParameters(params, TEST_SECRET);

        // Verify with same params in different order
        Map<String, String> reorderedParams = new HashMap<>();
        reorderedParams.put("c", "3");
        reorderedParams.put("a", "1");
        reorderedParams.put("b", "2");
        reorderedParams.put(QueryParameterSignature.TIMESTAMP_PARAM, String.valueOf(signed1.getTimestamp()));
        reorderedParams.put(QueryParameterSignature.SIGNATURE_PARAM, signed1.getSignature());

        var result = service.verifyQueryParameters(reorderedParams, TEST_SECRET);

        assertTrue(result.valid(), "Should verify regardless of parameter order");
    }

    @Test
    @DisplayName("Should handle empty parameters map")
    void testSignQueryParameters_EmptyParams() {
        Map<String, String> params = Map.of();

        QueryParameterSignature signed = service.signQueryParameters(params, TEST_SECRET);
        var result = service.verifyQueryParameters(signed.getAllParameters(), TEST_SECRET);

        assertTrue(result.valid(), "Should handle empty parameters");
        assertTrue(result.parameters().isEmpty(), "Should return empty parameters");
    }
}
