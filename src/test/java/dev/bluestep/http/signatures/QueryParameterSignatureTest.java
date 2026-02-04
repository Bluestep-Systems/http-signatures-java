package dev.bluestep.http.signatures;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for QueryParameterSignature class.
 * Tests signed query parameter container functionality.
 */
class QueryParameterSignatureTest {

    private static final long TEST_TIMESTAMP = 1704067200000L; // 2024-01-01 00:00:00 UTC
    private static final String TEST_SIGNATURE = "dGVzdC1zaWduYXR1cmUtdmFsdWU";

    // ========== Constructor Tests ==========

    @Test
    @DisplayName("Should create instance with parameters, timestamp, and signature")
    void testConstructor() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        assertNotNull(qps);
        assertEquals(TEST_TIMESTAMP, qps.getTimestamp());
        assertEquals(TEST_SIGNATURE, qps.getSignature());
    }

    @Test
    @DisplayName("Should handle empty parameters map")
    void testConstructorEmptyParams() {
        QueryParameterSignature qps = new QueryParameterSignature(Map.of(), TEST_TIMESTAMP, TEST_SIGNATURE);

        assertNotNull(qps);
        assertTrue(qps.getParameters().isEmpty());
    }

    @Test
    @DisplayName("Should create defensive copy of parameters")
    void testConstructorDefensiveCopy() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("key", "value");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        // Modify original map
        params.put("new", "param");

        // QPS should not be affected
        assertFalse(qps.getParameters().containsKey("new"));
    }

    // ========== GetParameters Tests ==========

    @Test
    @DisplayName("Should return original parameters")
    void testGetParameters() {
        Map<String, String> params = Map.of(
            "host", "example.com",
            "destUrl", "/callback",
            "userToken", "abc123"
        );

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        Map<String, String> retrieved = qps.getParameters();

        assertEquals(3, retrieved.size());
        assertEquals("example.com", retrieved.get("host"));
        assertEquals("/callback", retrieved.get("destUrl"));
        assertEquals("abc123", retrieved.get("userToken"));
    }

    @Test
    @DisplayName("Should return defensive copy from getParameters")
    void testGetParametersReturnsCopy() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        Map<String, String> retrieved = qps.getParameters();
        retrieved.put("injected", "value");

        // Original should not be affected
        assertFalse(qps.getParameters().containsKey("injected"));
    }

    @Test
    @DisplayName("Should not include signature metadata in getParameters")
    void testGetParametersExcludesMetadata() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        Map<String, String> retrieved = qps.getParameters();

        assertFalse(retrieved.containsKey(QueryParameterSignature.TIMESTAMP_PARAM));
        assertFalse(retrieved.containsKey(QueryParameterSignature.SIGNATURE_PARAM));
    }

    // ========== GetTimestamp Tests ==========

    @Test
    @DisplayName("Should return timestamp")
    void testGetTimestamp() {
        QueryParameterSignature qps = new QueryParameterSignature(Map.of(), TEST_TIMESTAMP, TEST_SIGNATURE);

        assertEquals(TEST_TIMESTAMP, qps.getTimestamp());
    }

    @Test
    @DisplayName("Should handle zero timestamp")
    void testGetTimestampZero() {
        QueryParameterSignature qps = new QueryParameterSignature(Map.of(), 0L, TEST_SIGNATURE);

        assertEquals(0L, qps.getTimestamp());
    }

    @Test
    @DisplayName("Should handle negative timestamp")
    void testGetTimestampNegative() {
        QueryParameterSignature qps = new QueryParameterSignature(Map.of(), -1L, TEST_SIGNATURE);

        assertEquals(-1L, qps.getTimestamp());
    }

    // ========== GetSignature Tests ==========

    @Test
    @DisplayName("Should return signature")
    void testGetSignature() {
        QueryParameterSignature qps = new QueryParameterSignature(Map.of(), TEST_TIMESTAMP, TEST_SIGNATURE);

        assertEquals(TEST_SIGNATURE, qps.getSignature());
    }

    @Test
    @DisplayName("Should handle empty signature")
    void testGetSignatureEmpty() {
        QueryParameterSignature qps = new QueryParameterSignature(Map.of(), TEST_TIMESTAMP, "");

        assertEquals("", qps.getSignature());
    }

    @Test
    @DisplayName("Should handle null signature")
    void testGetSignatureNull() {
        QueryParameterSignature qps = new QueryParameterSignature(Map.of(), TEST_TIMESTAMP, null);

        assertNull(qps.getSignature());
    }

    // ========== GetAllParameters Tests ==========

    @Test
    @DisplayName("Should return all parameters including signature metadata")
    void testGetAllParameters() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        Map<String, String> all = qps.getAllParameters();

        assertEquals(3, all.size());
        assertEquals("example.com", all.get("host"));
        assertEquals(String.valueOf(TEST_TIMESTAMP), all.get(QueryParameterSignature.TIMESTAMP_PARAM));
        assertEquals(TEST_SIGNATURE, all.get(QueryParameterSignature.SIGNATURE_PARAM));
    }

    @Test
    @DisplayName("Should return defensive copy from getAllParameters")
    void testGetAllParametersReturnsCopy() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        Map<String, String> all = qps.getAllParameters();
        all.put("injected", "value");

        // Original should not be affected
        assertFalse(qps.getAllParameters().containsKey("injected"));
    }

    @Test
    @DisplayName("Should include timestamp and signature param names correctly")
    void testGetAllParametersParamNames() {
        QueryParameterSignature qps = new QueryParameterSignature(Map.of(), TEST_TIMESTAMP, TEST_SIGNATURE);

        Map<String, String> all = qps.getAllParameters();

        assertTrue(all.containsKey("_sig_ts"));
        assertTrue(all.containsKey("_sig"));
    }

    // ========== ToQueryString Tests ==========

    @Test
    @DisplayName("Should generate valid query string")
    void testToQueryString() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        String queryString = qps.toQueryString();

        assertTrue(queryString.contains("host=example.com"));
        assertTrue(queryString.contains("_sig_ts=" + TEST_TIMESTAMP));
        assertTrue(queryString.contains("_sig=" + TEST_SIGNATURE));
    }

    @Test
    @DisplayName("Should URL-encode special characters in query string")
    void testToQueryStringUrlEncoding() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("destUrl", "/path?foo=bar&baz=qux");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        String queryString = qps.toQueryString();

        // Should contain URL-encoded characters
        assertTrue(queryString.contains("destUrl=%2Fpath%3Ffoo%3Dbar%26baz%3Dqux"));
    }

    @Test
    @DisplayName("Should URL-encode spaces")
    void testToQueryStringSpaces() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("name", "John Doe");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        String queryString = qps.toQueryString();

        assertTrue(queryString.contains("name=John+Doe") || queryString.contains("name=John%20Doe"));
    }

    @Test
    @DisplayName("Should join parameters with &")
    void testToQueryStringDelimiter() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("a", "1");
        params.put("b", "2");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        String queryString = qps.toQueryString();

        // Count & occurrences (should be 3 for 4 parameters: a, b, _sig_ts, _sig)
        long ampCount = queryString.chars().filter(ch -> ch == '&').count();
        assertEquals(3, ampCount);
    }

    @Test
    @DisplayName("Should not have leading ?")
    void testToQueryStringNoLeadingQuestionMark() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        String queryString = qps.toQueryString();

        assertFalse(queryString.startsWith("?"));
    }

    // ========== ToUrl Tests ==========

    @Test
    @DisplayName("Should append query string to URL without existing params")
    void testToUrl() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        String url = qps.toUrl("https://oauth.example.com/initiate");

        assertTrue(url.startsWith("https://oauth.example.com/initiate?"));
        assertTrue(url.contains("host=example.com"));
        assertTrue(url.contains("_sig="));
    }

    @Test
    @DisplayName("Should append to URL with existing query params using &")
    void testToUrlWithExistingParams() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        String url = qps.toUrl("https://oauth.example.com/initiate?existing=param");

        assertTrue(url.contains("existing=param"));
        assertTrue(url.contains("&host="));
        assertFalse(url.contains("??"));
    }

    @Test
    @DisplayName("Should handle URL ending with ?")
    void testToUrlEndingWithQuestionMark() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        String url = qps.toUrl("https://oauth.example.com/initiate?");

        // Should use & since ? is already present
        assertTrue(url.contains("?&") || url.contains("?host="));
    }

    @Test
    @DisplayName("Should handle empty base URL")
    void testToUrlEmptyBase() {
        Map<String, String> params = Map.of("host", "example.com");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        String url = qps.toUrl("");

        assertTrue(url.startsWith("?"));
    }

    // ========== Constant Values Tests ==========

    @Test
    @DisplayName("Should have correct TIMESTAMP_PARAM constant")
    void testTimestampParamConstant() {
        assertEquals("_sig_ts", QueryParameterSignature.TIMESTAMP_PARAM);
    }

    @Test
    @DisplayName("Should have correct SIGNATURE_PARAM constant")
    void testSignatureParamConstant() {
        assertEquals("_sig", QueryParameterSignature.SIGNATURE_PARAM);
    }

    // ========== Edge Cases ==========

    @Test
    @DisplayName("Should handle parameter with empty value")
    void testEmptyParameterValue() {
        Map<String, String> params = Map.of("empty", "");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        assertEquals("", qps.getParameters().get("empty"));
        assertTrue(qps.toQueryString().contains("empty="));
    }

    @Test
    @DisplayName("Should handle parameter with special characters in key")
    void testSpecialCharactersInKey() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("param-with-dash", "value");
        params.put("param_with_underscore", "value");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        Map<String, String> retrieved = qps.getParameters();

        assertEquals("value", retrieved.get("param-with-dash"));
        assertEquals("value", retrieved.get("param_with_underscore"));
    }

    @Test
    @DisplayName("Should handle unicode in parameter values")
    void testUnicodeValues() {
        Map<String, String> params = Map.of("name", "日本語 émojis");

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        assertEquals("日本語 émojis", qps.getParameters().get("name"));
    }

    @Test
    @DisplayName("Should handle very long parameter values")
    void testLongParameterValues() {
        String longValue = "A".repeat(10000);
        Map<String, String> params = Map.of("long", longValue);

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        assertEquals(longValue, qps.getParameters().get("long"));
    }

    @Test
    @DisplayName("Should handle many parameters")
    void testManyParameters() {
        Map<String, String> params = new LinkedHashMap<>();
        for (int i = 0; i < 100; i++) {
            params.put("param" + i, "value" + i);
        }

        QueryParameterSignature qps = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        assertEquals(100, qps.getParameters().size());
        // getAllParameters should have 102 (100 + timestamp + signature)
        assertEquals(102, qps.getAllParameters().size());
    }

    @Test
    @DisplayName("Should handle max long timestamp")
    void testMaxLongTimestamp() {
        QueryParameterSignature qps = new QueryParameterSignature(Map.of(), Long.MAX_VALUE, TEST_SIGNATURE);

        assertEquals(Long.MAX_VALUE, qps.getTimestamp());
        assertTrue(qps.getAllParameters().get(QueryParameterSignature.TIMESTAMP_PARAM)
            .equals(String.valueOf(Long.MAX_VALUE)));
    }

    // ========== Integration Tests ==========

    @Test
    @DisplayName("Should produce consistent output for same input")
    void testConsistentOutput() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("host", "example.com");
        params.put("destUrl", "/callback");

        QueryParameterSignature qps1 = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);
        QueryParameterSignature qps2 = new QueryParameterSignature(params, TEST_TIMESTAMP, TEST_SIGNATURE);

        assertEquals(qps1.toQueryString(), qps2.toQueryString());
        assertEquals(qps1.toUrl("https://test.com"), qps2.toUrl("https://test.com"));
    }

    @Test
    @DisplayName("Should work with typical OAuth proxy parameters")
    void testTypicalOAuthProxyParameters() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("host", "customer.bluestep.net");
        params.put("destUrl", "/quickbooks/callback?returnUrl=/dashboard");
        params.put("userToken", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test");
        params.put("state", "abc123xyz");

        long timestamp = System.currentTimeMillis();
        String signature = "dGVzdC1zaWduYXR1cmU";

        QueryParameterSignature qps = new QueryParameterSignature(params, timestamp, signature);

        // Verify all parameters preserved
        assertEquals("customer.bluestep.net", qps.getParameters().get("host"));
        assertEquals("/quickbooks/callback?returnUrl=/dashboard", qps.getParameters().get("destUrl"));
        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test", qps.getParameters().get("userToken"));
        assertEquals("abc123xyz", qps.getParameters().get("state"));

        // Verify URL generation
        String url = qps.toUrl("https://oauth2.myassn.com/v1/proxy/quickbooks/initiate");
        assertTrue(url.startsWith("https://oauth2.myassn.com/v1/proxy/quickbooks/initiate?"));
        assertTrue(url.contains("host=customer.bluestep.net"));
        assertTrue(url.contains("_sig_ts="));
        assertTrue(url.contains("_sig="));
    }
}
