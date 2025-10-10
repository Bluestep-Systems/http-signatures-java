package dev.bluestep.http.signatures;

import java.util.HashMap;
import java.util.Map;

/**
 * Simple HTTP headers container for the signature library.
 * Provides basic header operations without external dependencies.
 * All header names are stored in lowercase for case-insensitive operations.
 */
public class HttpHeaders {

    private final Map<String, String> headers = new HashMap<>();

    /**
     * Creates a new HttpHeaders instance.
     */
    public HttpHeaders() {
        // Default constructor
    }

    /**
     * Sets a header value, replacing any existing value.
     * Header names are normalized to lowercase for case-insensitive storage.
     *
     * @param name the header name (will be converted to lowercase)
     * @param value the header value
     */
    public void set(final String name, final String value) {
        headers.put(name.toLowerCase(), value);
    }

    /**
     * Gets the first value for the specified header name.
     * Header name lookup is case-insensitive.
     *
     * @param name the header name (case-insensitive)
     * @return the header value, or null if not found
     */
    public String getFirst(final String name) {
        return headers.get(name.toLowerCase());
    }

    /**
     * Adds a header value. In this simple implementation, this overwrites any existing value.
     * Header names are normalized to lowercase for case-insensitive storage.
     *
     * @param name the header name (will be converted to lowercase)
     * @param value the header value
     */
    public void add(final String name, final String value) {
        set(name, value); // Simple implementation - overwrites existing
    }

    /**
     * Sets multiple headers from a map.
     * All header names will be normalized to lowercase.
     *
     * @param headerMap map of header names to values
     */
    public void setAll(final Map<String, String> headerMap) {
        headerMap.forEach(this::set);
    }

    /**
     * Returns a copy of all headers as a map.
     * All keys in the returned map are lowercase.
     *
     * @return a new map containing all headers with lowercase keys
     */
    public Map<String, String> toMap() {
        return new HashMap<>(headers);
    }

    /**
     * Checks if a header with the specified name exists.
     * Header name lookup is case-insensitive.
     *
     * @param name the header name to check (case-insensitive)
     * @return true if the header exists, false otherwise
     */
    public boolean containsKey(final String name) {
        return headers.containsKey(name.toLowerCase());
    }
}