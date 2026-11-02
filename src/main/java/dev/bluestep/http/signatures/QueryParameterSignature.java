package dev.bluestep.http.signatures;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Container for signed query parameters.
 * <p>
 * This class holds the original parameters plus the signature metadata
 * (timestamp and signature) needed for verification.
 * <p>
 * The signature covers all original parameters plus the timestamp,
 * preventing tampering and replay attacks.
 */
public class QueryParameterSignature {

    /** Query parameter name for the signature timestamp (milliseconds since epoch). */
    public static final String TIMESTAMP_PARAM = "_sig_ts";

    /** Query parameter name for the HMAC signature. */
    public static final String SIGNATURE_PARAM = "_sig";

    /**
     * Query parameter name for the signing-format version. Absent means version 1, whose signing string
     * joins raw values and so cannot tell a literal {@code &} or {@code =} inside a value from a parameter
     * boundary; version 2 percent-encodes every key and value. Excluded from the signed payload and from
     * {@link #getParameters()}, like the other signature metadata.
     */
    public static final String VERSION_PARAM = "_sig_v";

    /** The signing-format version {@link HttpSignatureService#signQueryParameters} produces. */
    public static final String CURRENT_VERSION = "2";

    private final Map<String, String> parameters;
    private final long timestamp;
    private final String signature;

    /**
     * Creates a new QueryParameterSignature.
     *
     * @param parameters The original parameters (without signature metadata)
     * @param timestamp  The signature timestamp (milliseconds since epoch)
     * @param signature  The HMAC-SHA256 signature (Base64 URL-encoded), computed under {@link #CURRENT_VERSION}
     */
    public QueryParameterSignature(final Map<String, String> parameters, final long timestamp, final String signature) {
        this.parameters = new LinkedHashMap<>(parameters);
        this.timestamp = timestamp;
        this.signature = signature;
    }

    /**
     * Gets the original parameters (without signature metadata).
     *
     * @return A copy of the original parameters
     */
    public Map<String, String> getParameters() {
        return new LinkedHashMap<>(parameters);
    }

    /**
     * Gets the signature timestamp.
     *
     * @return Timestamp in milliseconds since epoch
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Gets the HMAC signature.
     *
     * @return Base64 URL-encoded signature
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Gets all parameters including signature metadata.
     *
     * @return Map containing original parameters plus _sig_ts, _sig_v and _sig
     */
    public Map<String, String> getAllParameters() {
        final Map<String, String> all = new LinkedHashMap<>(parameters);
        all.put(TIMESTAMP_PARAM, String.valueOf(timestamp));
        all.put(VERSION_PARAM, CURRENT_VERSION);
        all.put(SIGNATURE_PARAM, signature);
        return all;
    }

    /**
     * Builds a query string from all parameters (including signature).
     * <p>
     * Parameters are URL-encoded and joined with {@code &}.
     *
     * @return URL-encoded query string (without leading {@code ?})
     */
    public String toQueryString() {
        return getAllParameters().entrySet().stream()
                .map(e -> urlEncode(e.getKey()) + "=" + urlEncode(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    /**
     * Builds a full URL with the signed query parameters.
     *
     * @param baseUrl The base URL (may or may not include existing query params)
     * @return Full URL with signed query parameters appended
     */
    public String toUrl(final String baseUrl) {
        final String separator = baseUrl.contains("?") ? "&" : "?";
        return baseUrl + separator + toQueryString();
    }

    private static String urlEncode(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
