# HTTP Message Signatures Library for Java

A secure, standards-compliant HTTP Message Signatures library implementing RFC-like patterns for request authentication.

## Features

- ✅ **HMAC-SHA256 signatures** - Industry standard cryptography
- ✅ **HTTP Message Signatures patterns** - Follows RFC best practices  
- ✅ **Replay attack prevention** - Includes request-target, host, and date
- ✅ **Body integrity** - SHA-256 content digest verification
- ✅ **Cross-host protection** - Host header signing
- ✅ **Spring Boot integration** - Easy @Service integration
- ✅ **Lightweight** - No external dependencies beyond Jackson 3 (Spring integration optional)

## Security Improvements over Custom Implementations

- **Standard headers**: Uses `Signature`, `Date`, `Host`, `Digest` headers
- **Canonical signing**: Prevents signature manipulation
- **Timestamp validation**: 5-minute replay protection window
- **Content integrity**: SHA-256 digest of request body
- **Method/path signing**: Prevents endpoint confusion attacks

## Usage

### Maven
```xml
<dependency>
    <groupId>dev.bluestep</groupId>
    <artifactId>http-signatures</artifactId>
    <version>2.0.0</version>
</dependency>
```

### Gradle
```gradle
implementation 'dev.bluestep:http-signatures:2.0.0'
```

### Spring Boot Configuration
```java
import tools.jackson.databind.ObjectMapper; // Jackson 3

@Configuration
public class HttpSignatureConfiguration {
    
    @Bean
    public HttpSignatureService httpSignatureService(ObjectMapper objectMapper) {
        return new HttpSignatureService(objectMapper);
    }
}
```

### Signing Requests (Client Side)

The `Digest` header covers the exact UTF-8 bytes of the body, and the verifier digests the raw
body it receives. Serialize the body **once**, sign that string, and send that same string:

```java
@Service
public class ApiClient {
    
    private final HttpSignatureService signatureService;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;
    
    @Value("${api.agent.token}")
    private String agentToken;
    
    public ResponseEntity<String> makeSecureRequest(RequestData data, String host, String path) {
        final String json = objectMapper.writeValueAsString(data);

        // Sign exactly the string that will be sent
        final HttpSignatureHeaders signed = signatureService.signRequest(
            "POST", path, host, new dev.bluestep.http.signatures.HttpHeaders(), json, agentToken
        );

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        signed.addToSpringHeaders(headers);

        // A String body is written verbatim by StringHttpMessageConverter; do not hand the
        // original object to RestTemplate, whose own mapper may serialize it differently.
        return restTemplate.postForEntity("https://" + host + path, new HttpEntity<>(json, headers), String.class);
    }
}
```

The `Object`-body `signRequest` overloads are a convenience: they serialize with the service's
`ObjectMapper` and delegate to the `String` overload, so they are only correct if you then send
`objectMapper.writeValueAsString(body)` yourself.

### Verifying Requests (Server Side)
```java
@RestController
public class SecureController {
    
    private final HttpSignatureService signatureService;
    
    @Value("${api.agent.token}")
    private String agentToken;
    
    @PostMapping("/api/secure-endpoint")
    public ResponseEntity<?> handleSecureRequest(
            @RequestBody RequestData data, 
            HttpServletRequest request) throws IOException {
        
        // Extract headers
        HttpHeaders headers = new HttpHeaders();
        request.getHeaderNames().asIterator().forEachRemaining(name -> 
            headers.add(name, request.getHeader(name))
        );
        
        // Get request body as string (you'll need to buffer this in a filter)
        String requestBody = getRequestBodyAsString(request);
        
        // Verify signature
        boolean valid = signatureService.verifyRequest(
            headers, 
            request.getMethod(), 
            request.getRequestURI(),
            requestBody, 
            agentToken
        );
        
        if (!valid) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Invalid signature");
        }
        
        // Process authenticated request...
        return ResponseEntity.ok("Success");
    }
}
```

## Migrating from 1.x to 2.0.0

2.0.0 drops Jackson 2 for Jackson 3 and adds a first-class way to sign a pre-serialized body.

- **Jackson 3.** The constructors take `tools.jackson.databind.ObjectMapper` instead of
  `com.fasterxml.jackson.databind.ObjectMapper`, and the library depends on
  `tools.jackson.core:jackson-databind` 3.x instead of Jackson 2. Change the import where you build
  the service; a Spring Boot 4 application can inject its auto-configured mapper.
- **No checked exception.** The `signRequest` overloads no longer declare
  `throws JsonProcessingException`. Jackson 3's `JacksonException` is unchecked, so remove
  `try`/`catch (JsonProcessingException)` blocks and `throws` clauses that existed only for it.
- **New `String`-body overloads.** `signRequest(method, path, host, headers, String serializedBody,
  secretKey[, keyId])` digests exactly the UTF-8 bytes of the string you pass; you must send that
  string unchanged. Prefer it whenever an HTTP client would otherwise serialize the body itself
  (Spring Boot 4's `RestTemplate`/`RestClient` write with Jackson 3, whose default property order
  differs from Jackson 2's). Workarounds such as passing `new RawValue(json)` as the body can be
  replaced with the plain `json` string.
- **A `String` argument now binds to the new overload.** In 1.x a `String`-typed body was
  JSON-encoded (signed as `"\"...\""`); in 2.0.0 it is signed verbatim. A `null` or empty
  `String` body is signed as a request without a body: any `Digest`/`Content-Length` already
  on the passed headers is removed.
- **Spring.** The optional Spring integration (`HttpSignatureHeaders.addToSpringHeaders`) is built
  and tested against Spring Framework 7.
- `verifyRequest` is unchanged: it digests the raw body string it is given.

## Generated Headers

The library generates standard HTTP Message Signature headers:

```http
POST /api/endpoint HTTP/1.1
Host: api.example.com
Date: Thu, 10 Oct 2024 15:30:45 GMT
Content-Type: application/json
Content-Length: 123
Digest: SHA-256=ABC123...
Signature: keyId="agent-key",algorithm="hmac-sha256",headers="(request-target) host date digest",signature="XYZ789..."
```

## Security Benefits

- **🔒 Industry Standard**: Uses proven HMAC-SHA256 cryptography
- **🛡️ Replay Protection**: Date-based timestamp validation (5-minute window)
- **🎯 Endpoint Protection**: Signs HTTP method and path to prevent confusion
- **🌐 Cross-Host Protection**: Host header prevents cross-domain attacks  
- **📦 Body Integrity**: SHA-256 digest ensures request body hasn't been tampered
- **🔍 Debuggable**: Standard headers make troubleshooting easier

## License

MIT License
