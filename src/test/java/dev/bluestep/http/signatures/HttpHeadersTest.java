package dev.bluestep.http.signatures;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for HttpHeaders class.
 * Tests case-insensitive header storage and retrieval.
 */
class HttpHeadersTest {

    private HttpHeaders headers;

    @BeforeEach
    void setUp() {
        headers = new HttpHeaders();
    }

    // ========== Basic Operations ==========

    @Test
    @DisplayName("Should set and retrieve header value")
    void testSetAndGet() {
        headers.set("Content-Type", "application/json");

        assertEquals("application/json", headers.getFirst("Content-Type"));
    }

    @Test
    @DisplayName("Should return null for non-existent header")
    void testGetNonExistent() {
        assertNull(headers.getFirst("Non-Existent-Header"));
    }

    @Test
    @DisplayName("Should overwrite existing header value")
    void testSetOverwrites() {
        headers.set("Authorization", "Bearer token1");
        headers.set("Authorization", "Bearer token2");

        assertEquals("Bearer token2", headers.getFirst("Authorization"));
    }

    // ========== Case Insensitivity ==========

    @Test
    @DisplayName("Should be case-insensitive when setting headers")
    void testCaseInsensitiveSet() {
        headers.set("Content-Type", "text/html");

        assertEquals("text/html", headers.getFirst("content-type"));
        assertEquals("text/html", headers.getFirst("CONTENT-TYPE"));
        assertEquals("text/html", headers.getFirst("Content-Type"));
    }

    @Test
    @DisplayName("Should normalize header names to lowercase")
    void testHeaderNameNormalization() {
        headers.set("X-Custom-Header", "value1");
        headers.set("x-custom-header", "value2");

        // Should only have one entry (lowercase)
        assertEquals("value2", headers.getFirst("X-Custom-Header"));
    }

    @Test
    @DisplayName("Should handle mixed case in getFirst")
    void testGetFirstCaseInsensitive() {
        headers.set("Authorization", "Bearer token");

        assertEquals("Bearer token", headers.getFirst("authorization"));
        assertEquals("Bearer token", headers.getFirst("AUTHORIZATION"));
        assertEquals("Bearer token", headers.getFirst("AuThOrIzAtIoN"));
    }

    @Test
    @DisplayName("Should handle mixed case in containsKey")
    void testContainsKeyCaseInsensitive() {
        headers.set("Content-Length", "123");

        assertTrue(headers.containsKey("content-length"));
        assertTrue(headers.containsKey("CONTENT-LENGTH"));
        assertTrue(headers.containsKey("Content-Length"));
    }

    // ========== Add Method ==========

    @Test
    @DisplayName("Should add header using add method")
    void testAddMethod() {
        headers.add("Accept", "application/json");

        assertEquals("application/json", headers.getFirst("Accept"));
    }

    @Test
    @DisplayName("Add method should overwrite existing value")
    void testAddOverwrites() {
        headers.add("Host", "example.com");
        headers.add("Host", "newhost.com");

        assertEquals("newhost.com", headers.getFirst("Host"));
    }

    // ========== SetAll Method ==========

    @Test
    @DisplayName("Should set all headers from map")
    void testSetAll() {
        Map<String, String> headerMap = Map.of(
            "Content-Type", "application/json",
            "Authorization", "Bearer token",
            "Accept", "text/html"
        );

        headers.setAll(headerMap);

        assertEquals("application/json", headers.getFirst("Content-Type"));
        assertEquals("Bearer token", headers.getFirst("Authorization"));
        assertEquals("text/html", headers.getFirst("Accept"));
    }

    @Test
    @DisplayName("Should normalize keys when setting all headers")
    void testSetAllNormalizesKeys() {
        Map<String, String> headerMap = Map.of(
            "Content-Type", "application/json",
            "AUTHORIZATION", "Bearer token"
        );

        headers.setAll(headerMap);

        assertTrue(headers.containsKey("content-type"));
        assertTrue(headers.containsKey("authorization"));
    }

    @Test
    @DisplayName("Should handle empty map in setAll")
    void testSetAllEmptyMap() {
        headers.set("Existing", "value");
        headers.setAll(Map.of());

        // Existing header should still be there
        assertEquals("value", headers.getFirst("Existing"));
    }

    // ========== ToMap Method ==========

    @Test
    @DisplayName("Should convert headers to map")
    void testToMap() {
        headers.set("Content-Type", "application/json");
        headers.set("Authorization", "Bearer token");

        Map<String, String> map = headers.toMap();

        assertEquals(2, map.size());
        assertEquals("application/json", map.get("content-type"));
        assertEquals("Bearer token", map.get("authorization"));
    }

    @Test
    @DisplayName("Should return lowercase keys in toMap")
    void testToMapLowercaseKeys() {
        headers.set("Content-Type", "application/json");
        headers.set("AUTHORIZATION", "Bearer token");

        Map<String, String> map = headers.toMap();

        assertTrue(map.containsKey("content-type"));
        assertTrue(map.containsKey("authorization"));
        assertFalse(map.containsKey("Content-Type"));
        assertFalse(map.containsKey("AUTHORIZATION"));
    }

    @Test
    @DisplayName("Should return empty map when no headers")
    void testToMapEmpty() {
        Map<String, String> map = headers.toMap();

        assertNotNull(map);
        assertTrue(map.isEmpty());
    }

    @Test
    @DisplayName("Should return independent copy in toMap")
    void testToMapReturnsCopy() {
        headers.set("Content-Type", "application/json");

        Map<String, String> map = headers.toMap();
        map.put("new-header", "new-value");

        // Original headers should not be affected
        assertNull(headers.getFirst("new-header"));
    }

    // ========== ContainsKey Method ==========

    @Test
    @DisplayName("Should check if header exists")
    void testContainsKey() {
        headers.set("Content-Type", "application/json");

        assertTrue(headers.containsKey("Content-Type"));
        assertFalse(headers.containsKey("Authorization"));
    }

    @Test
    @DisplayName("ContainsKey should be case-insensitive")
    void testContainsKeyMultipleCases() {
        headers.set("X-Custom-Header", "value");

        assertTrue(headers.containsKey("x-custom-header"));
        assertTrue(headers.containsKey("X-CUSTOM-HEADER"));
        assertTrue(headers.containsKey("X-Custom-Header"));
    }

    // ========== Edge Cases ==========

    @Test
    @DisplayName("Should handle null value in set")
    void testSetNullValue() {
        assertDoesNotThrow(() -> headers.set("Content-Type", null));
        assertNull(headers.getFirst("Content-Type"));
    }

    @Test
    @DisplayName("Should handle empty string value")
    void testSetEmptyValue() {
        headers.set("Custom-Header", "");

        assertEquals("", headers.getFirst("Custom-Header"));
    }

    @Test
    @DisplayName("Should handle special characters in header name")
    void testSpecialCharactersInName() {
        headers.set("X-Custom-Header-123", "value");

        assertEquals("value", headers.getFirst("X-Custom-Header-123"));
    }

    @Test
    @DisplayName("Should handle special characters in header value")
    void testSpecialCharactersInValue() {
        String specialValue = "value with spaces, commas, and símböls! 🎉";
        headers.set("Custom-Header", specialValue);

        assertEquals(specialValue, headers.getFirst("Custom-Header"));
    }

    @Test
    @DisplayName("Should handle multiple operations on same header")
    void testMultipleOperations() {
        headers.set("Test-Header", "value1");
        assertEquals("value1", headers.getFirst("Test-Header"));

        headers.add("Test-Header", "value2");
        assertEquals("value2", headers.getFirst("Test-Header"));

        headers.set("test-header", "value3");
        assertEquals("value3", headers.getFirst("TEST-HEADER"));
    }

    @Test
    @DisplayName("Should handle standard HTTP headers")
    void testStandardHeaders() {
        headers.set("Content-Type", "application/json");
        headers.set("Content-Length", "123");
        headers.set("Authorization", "Bearer token");
        headers.set("Host", "example.com");
        headers.set("Date", "Mon, 01 Jan 2024 00:00:00 GMT");
        headers.set("Signature", "signature-value");
        headers.set("Digest", "SHA-256=abc123");

        assertEquals(7, headers.toMap().size());
        assertTrue(headers.containsKey("Content-Type"));
        assertTrue(headers.containsKey("content-length"));
        assertTrue(headers.containsKey("AUTHORIZATION"));
        assertTrue(headers.containsKey("host"));
        assertTrue(headers.containsKey("Date"));
        assertTrue(headers.containsKey("signature"));
        assertTrue(headers.containsKey("digest"));
    }
}
