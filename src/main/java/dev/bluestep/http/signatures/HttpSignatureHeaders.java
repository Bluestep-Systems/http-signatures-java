package dev.bluestep.http.signatures;

/**
 * Container for HTTP signature-related headers.
 * Provides easy access to the headers needed for signed HTTP requests.
 */
public class HttpSignatureHeaders {
    
    private final HttpHeaders headers;
    
    public HttpSignatureHeaders(final HttpHeaders headers) {
        this.headers = headers;
    }
    
    /**
     * Gets the Signature header value.
     */
    public String getSignature() {
        return headers.getFirst("Signature");
    }
    
    /**
     * Gets the Date header value.
     */
    public String getDate() {
        return headers.getFirst("Date");
    }
    
    /**
     * Gets the Digest header value.
     */
    public String getDigest() {
        return headers.getFirst("Digest");
    }
    
    /**
     * Gets the Host header value.
     */
    public String getHost() {
        return headers.getFirst("Host");
    }
    
    /**
     * Gets all headers as a map.
     */
    public HttpHeaders getAllHeaders() {
        return headers;
    }
    
    /**
     * Adds these signature headers to an existing Spring HttpHeaders object.
     * This method is only available when Spring is on the classpath.
     */
    public void addToSpringHeaders(final Object springHeaders) {
        if (springHeaders instanceof org.springframework.http.HttpHeaders) {
            final org.springframework.http.HttpHeaders springHttpHeaders = (org.springframework.http.HttpHeaders) springHeaders;
            headers.toMap().forEach(springHttpHeaders::set);
        }
    }
}