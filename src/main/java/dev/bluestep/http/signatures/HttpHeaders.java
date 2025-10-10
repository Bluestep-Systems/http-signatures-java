package dev.bluestep.http.signatures;

import java.util.HashMap;
import java.util.Map;

/**
 * Simple HTTP headers container for the signature library.
 * Provides basic header operations without external dependencies.
 */
public class HttpHeaders {

    private final Map<String, String> headers = new HashMap<>();

    public void set(final String name, final String value) {
        headers.put(name.toLowerCase(), value);
    }

    public String getFirst(final String name) {
        return headers.get(name.toLowerCase());
    }

    public void add(final String name, final String value) {
        set(name, value); // Simple implementation - overwrites existing
    }

    public void setAll(final Map<String, String> headerMap) {
        headerMap.forEach(this::set);
    }

    public Map<String, String> toMap() {
        return new HashMap<>(headers);
    }

    public boolean containsKey(final String name) {
        return headers.containsKey(name.toLowerCase());
    }
}