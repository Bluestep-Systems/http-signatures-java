package dev.bluestep.http.signatures;

/**
 * Container for HTTP signature-related headers.
 * Provides easy access to the headers needed for signed HTTP requests.
 */
public class HttpSignatureHeaders {

    private final HttpHeaders headers;

    /**
     * Creates a new HttpSignatureHeaders wrapper.
     *
     * @param headers the underlying HttpHeaders instance to wrap
     */
    public HttpSignatureHeaders(final HttpHeaders headers) {
        this.headers = headers;
    }

    /**
     * Gets the Signature header value.
     *
     * @return the Signature header value, or null if not present
     */
    public String getSignature() {
        return headers.getFirst("Signature");
    }

    /**
     * Gets the Date header value.
     *
     * @return the Date header value, or null if not present
     */
    public String getDate() {
        return headers.getFirst("Date");
    }

    /**
     * Gets the Digest header value.
     *
     * @return the Digest header value, or null if not present
     */
    public String getDigest() {
        return headers.getFirst("Digest");
    }

    /**
     * Gets the Host header value.
     *
     * @return the Host header value, or null if not present
     */
    public String getHost() {
        return headers.getFirst("Host");
    }

    /**
     * Gets all headers including signature-related and other headers.
     *
     * @return the underlying HttpHeaders instance containing all headers
     */
    public HttpHeaders getAllHeaders() {
        return headers;
    }

    /**
     * Adds these signature headers to an existing Spring HttpHeaders object.
     * This method is only available when Spring is on the classpath.
     *
     * @param springHeaders a Spring Framework HttpHeaders object to add headers to
     */
    public void addToSpringHeaders(final Object springHeaders) {
        if (springHeaders instanceof final org.springframework.http.HttpHeaders springHttpHeaders) {
            headers.toMap().forEach(springHttpHeaders::set);
        }
    }
}