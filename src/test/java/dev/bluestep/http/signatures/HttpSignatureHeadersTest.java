package dev.bluestep.http.signatures;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for HttpSignatureHeaders class.
 * Tests wrapper functionality for signature-related headers.
 */
class HttpSignatureHeadersTest {

    private HttpHeaders baseHeaders;
    private HttpSignatureHeaders signatureHeaders;

    @BeforeEach
    void setUp() {
        baseHeaders = new HttpHeaders();
        signatureHeaders = new HttpSignatureHeaders(baseHeaders);
    }

    // ========== Constructor Tests ==========

    @Test
    @DisplayName("Should create instance with HttpHeaders")
    void testConstructor() {
        assertNotNull(signatureHeaders);
        assertNotNull(signatureHeaders.getAllHeaders());
    }

    @Test
    @DisplayName("Should wrap existing headers")
    void testWrapExistingHeaders() {
        baseHeaders.set("Signature", "test-signature");
        baseHeaders.set("Date", "Mon, 01 Jan 2024 00:00:00 GMT");

        HttpSignatureHeaders wrapper = new HttpSignatureHeaders(baseHeaders);

        assertEquals("test-signature", wrapper.getSignature());
        assertEquals("Mon, 01 Jan 2024 00:00:00 GMT", wrapper.getDate());
    }

    // ========== Signature Header Tests ==========

    @Test
    @DisplayName("Should get Signature header")
    void testGetSignature() {
        String signature = "keyId=\"test\",algorithm=\"hmac-sha256\",signature=\"abc123\"";
        baseHeaders.set("Signature", signature);

        assertEquals(signature, signatureHeaders.getSignature());
    }

    @Test
    @DisplayName("Should return null for missing Signature header")
    void testGetSignatureMissing() {
        assertNull(signatureHeaders.getSignature());
    }

    @Test
    @DisplayName("Should handle case-insensitive Signature header")
    void testGetSignatureCaseInsensitive() {
        baseHeaders.set("SIGNATURE", "test-value");

        assertEquals("test-value", signatureHeaders.getSignature());
    }

    // ========== Date Header Tests ==========

    @Test
    @DisplayName("Should get Date header")
    void testGetDate() {
        String date = "Mon, 01 Jan 2024 00:00:00 GMT";
        baseHeaders.set("Date", date);

        assertEquals(date, signatureHeaders.getDate());
    }

    @Test
    @DisplayName("Should return null for missing Date header")
    void testGetDateMissing() {
        assertNull(signatureHeaders.getDate());
    }

    @Test
    @DisplayName("Should handle case-insensitive Date header")
    void testGetDateCaseInsensitive() {
        baseHeaders.set("DATE", "Mon, 01 Jan 2024 00:00:00 GMT");

        assertEquals("Mon, 01 Jan 2024 00:00:00 GMT", signatureHeaders.getDate());
    }

    // ========== Digest Header Tests ==========

    @Test
    @DisplayName("Should get Digest header")
    void testGetDigest() {
        String digest = "SHA-256=abc123def456";
        baseHeaders.set("Digest", digest);

        assertEquals(digest, signatureHeaders.getDigest());
    }

    @Test
    @DisplayName("Should return null for missing Digest header")
    void testGetDigestMissing() {
        assertNull(signatureHeaders.getDigest());
    }

    @Test
    @DisplayName("Should handle case-insensitive Digest header")
    void testGetDigestCaseInsensitive() {
        baseHeaders.set("DIGEST", "SHA-256=test");

        assertEquals("SHA-256=test", signatureHeaders.getDigest());
    }

    // ========== Host Header Tests ==========

    @Test
    @DisplayName("Should get Host header")
    void testGetHost() {
        String host = "api.example.com";
        baseHeaders.set("Host", host);

        assertEquals(host, signatureHeaders.getHost());
    }

    @Test
    @DisplayName("Should return null for missing Host header")
    void testGetHostMissing() {
        assertNull(signatureHeaders.getHost());
    }

    @Test
    @DisplayName("Should handle case-insensitive Host header")
    void testGetHostCaseInsensitive() {
        baseHeaders.set("HOST", "api.example.com");

        assertEquals("api.example.com", signatureHeaders.getHost());
    }

    // ========== GetAllHeaders Tests ==========

    @Test
    @DisplayName("Should return all headers")
    void testGetAllHeaders() {
        baseHeaders.set("Signature", "sig-value");
        baseHeaders.set("Date", "Mon, 01 Jan 2024 00:00:00 GMT");
        baseHeaders.set("Host", "example.com");
        baseHeaders.set("Digest", "SHA-256=abc");
        baseHeaders.set("Custom-Header", "custom-value");

        HttpHeaders allHeaders = signatureHeaders.getAllHeaders();

        assertNotNull(allHeaders);
        assertEquals("sig-value", allHeaders.getFirst("Signature"));
        assertEquals("Mon, 01 Jan 2024 00:00:00 GMT", allHeaders.getFirst("Date"));
        assertEquals("example.com", allHeaders.getFirst("Host"));
        assertEquals("SHA-256=abc", allHeaders.getFirst("Digest"));
        assertEquals("custom-value", allHeaders.getFirst("Custom-Header"));
    }

    @Test
    @DisplayName("Should return same HttpHeaders instance")
    void testGetAllHeadersReturnsSameInstance() {
        HttpHeaders retrieved = signatureHeaders.getAllHeaders();

        assertSame(baseHeaders, retrieved);
    }

    // ========== Complete Signature Headers Tests ==========

    @Test
    @DisplayName("Should handle all signature headers together")
    void testCompleteSignatureHeaders() {
        baseHeaders.set("Signature", "keyId=\"test\",algorithm=\"hmac-sha256\",signature=\"xyz\"");
        baseHeaders.set("Date", "Mon, 01 Jan 2024 00:00:00 GMT");
        baseHeaders.set("Host", "api.example.com");
        baseHeaders.set("Digest", "SHA-256=abc123");

        assertEquals("keyId=\"test\",algorithm=\"hmac-sha256\",signature=\"xyz\"",
            signatureHeaders.getSignature());
        assertEquals("Mon, 01 Jan 2024 00:00:00 GMT", signatureHeaders.getDate());
        assertEquals("api.example.com", signatureHeaders.getHost());
        assertEquals("SHA-256=abc123", signatureHeaders.getDigest());
    }

    @Test
    @DisplayName("Should handle partial signature headers")
    void testPartialSignatureHeaders() {
        baseHeaders.set("Signature", "test-sig");
        baseHeaders.set("Date", "Mon, 01 Jan 2024 00:00:00 GMT");
        // Missing Host and Digest

        assertEquals("test-sig", signatureHeaders.getSignature());
        assertEquals("Mon, 01 Jan 2024 00:00:00 GMT", signatureHeaders.getDate());
        assertNull(signatureHeaders.getHost());
        assertNull(signatureHeaders.getDigest());
    }

    @Test
    @DisplayName("Should handle empty signature headers")
    void testEmptySignatureHeaders() {
        assertNull(signatureHeaders.getSignature());
        assertNull(signatureHeaders.getDate());
        assertNull(signatureHeaders.getHost());
        assertNull(signatureHeaders.getDigest());
    }

    // ========== Edge Cases ==========

    @Test
    @DisplayName("Should handle empty string values")
    void testEmptyStringValues() {
        baseHeaders.set("Signature", "");
        baseHeaders.set("Date", "");
        baseHeaders.set("Host", "");
        baseHeaders.set("Digest", "");

        assertEquals("", signatureHeaders.getSignature());
        assertEquals("", signatureHeaders.getDate());
        assertEquals("", signatureHeaders.getHost());
        assertEquals("", signatureHeaders.getDigest());
    }

    @Test
    @DisplayName("Should handle whitespace values")
    void testWhitespaceValues() {
        baseHeaders.set("Signature", "   ");
        baseHeaders.set("Date", "\t");
        baseHeaders.set("Host", "\n");

        assertEquals("   ", signatureHeaders.getSignature());
        assertEquals("\t", signatureHeaders.getDate());
        assertEquals("\n", signatureHeaders.getHost());
    }

    @Test
    @DisplayName("Should handle special characters in header values")
    void testSpecialCharactersInValues() {
        String complexSignature = "keyId=\"my-key\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date digest\",signature=\"AbC123+/==\"";
        baseHeaders.set("Signature", complexSignature);
        baseHeaders.set("Host", "sub.domain.example.com:8080");
        baseHeaders.set("Digest", "SHA-256=AbCdEf123456+/==");

        assertEquals(complexSignature, signatureHeaders.getSignature());
        assertEquals("sub.domain.example.com:8080", signatureHeaders.getHost());
        assertEquals("SHA-256=AbCdEf123456+/==", signatureHeaders.getDigest());
    }

    @Test
    @DisplayName("Should handle very long header values")
    void testLongHeaderValues() {
        String longSignature = "keyId=\"key\",algorithm=\"hmac-sha256\",signature=\"" + "A".repeat(500) + "\"";
        baseHeaders.set("Signature", longSignature);

        assertEquals(longSignature, signatureHeaders.getSignature());
    }

    // ========== Integration Tests ==========

    @Test
    @DisplayName("Should work with headers modified after wrapper creation")
    void testModificationAfterCreation() {
        // Create wrapper first
        HttpSignatureHeaders wrapper = new HttpSignatureHeaders(baseHeaders);

        // Then modify headers
        baseHeaders.set("Signature", "new-signature");
        baseHeaders.set("Date", "Tue, 02 Jan 2024 00:00:00 GMT");

        // Wrapper should reflect changes
        assertEquals("new-signature", wrapper.getSignature());
        assertEquals("Tue, 02 Jan 2024 00:00:00 GMT", wrapper.getDate());
    }

    @Test
    @DisplayName("Should handle mixed standard and custom headers")
    void testMixedHeaders() {
        baseHeaders.set("Signature", "sig-value");
        baseHeaders.set("Date", "Mon, 01 Jan 2024 00:00:00 GMT");
        baseHeaders.set("X-Custom-Header", "custom-value");
        baseHeaders.set("Authorization", "Bearer token");
        baseHeaders.set("Host", "example.com");
        baseHeaders.set("Content-Type", "application/json");
        baseHeaders.set("Digest", "SHA-256=abc");

        // Signature methods should only return signature-related headers
        assertEquals("sig-value", signatureHeaders.getSignature());
        assertEquals("Mon, 01 Jan 2024 00:00:00 GMT", signatureHeaders.getDate());
        assertEquals("example.com", signatureHeaders.getHost());
        assertEquals("SHA-256=abc", signatureHeaders.getDigest());

        // But getAllHeaders should return everything
        HttpHeaders all = signatureHeaders.getAllHeaders();
        assertEquals("custom-value", all.getFirst("X-Custom-Header"));
        assertEquals("Bearer token", all.getFirst("Authorization"));
        assertEquals("application/json", all.getFirst("Content-Type"));
    }

    @Test
    @DisplayName("Should handle headers from real signing scenario")
    void testRealSigningScenario() {
        // Simulate headers created by HttpSignatureService
        baseHeaders.set("Signature",
            "keyId=\"default-key\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date digest\",signature=\"YXJhbmRvbWJhc2U2NGVuY29kZWRzdHJpbmc=\"");
        baseHeaders.set("Date", "Thu, 10 Oct 2024 15:30:45 GMT");
        baseHeaders.set("Host", "api.example.com");
        baseHeaders.set("Digest", "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
        baseHeaders.set("Content-Type", "application/json");
        baseHeaders.set("Content-Length", "123");

        HttpSignatureHeaders wrapper = new HttpSignatureHeaders(baseHeaders);

        // Verify all signature headers are accessible
        assertNotNull(wrapper.getSignature());
        assertNotNull(wrapper.getDate());
        assertNotNull(wrapper.getHost());
        assertNotNull(wrapper.getDigest());

        // Verify signature format
        assertTrue(wrapper.getSignature().contains("keyId="));
        assertTrue(wrapper.getSignature().contains("algorithm="));
        assertTrue(wrapper.getSignature().contains("signature="));

        // Verify other headers are still accessible
        assertEquals("application/json", wrapper.getAllHeaders().getFirst("Content-Type"));
        assertEquals("123", wrapper.getAllHeaders().getFirst("Content-Length"));
    }
}
