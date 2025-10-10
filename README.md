# HTTP Message Signatures Library for Java

A secure, standards-compliant HTTP Message Signatures library implementing RFC-like patterns for request authentication.

## Features

- ✅ **HMAC-SHA256 signatures** - Industry standard cryptography
- ✅ **HTTP Message Signatures patterns** - Follows RFC best practices  
- ✅ **Replay attack prevention** - Includes request-target, host, and date
- ✅ **Body integrity** - SHA-256 content digest verification
- ✅ **Cross-host protection** - Host header signing
- ✅ **Spring Boot integration** - Easy @Service integration
- ✅ **Lightweight** - No external dependencies beyond Jackson

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
    <version>1.0.0</version>
</dependency>
```

### Gradle
```gradle
implementation 'dev.bluestep:http-signatures:1.0.0'
```

### Spring Boot Configuration
```java
@Configuration
public class HttpSignatureConfiguration {
    
    @Bean
    public HttpSignatureService httpSignatureService(ObjectMapper objectMapper) {
        return new HttpSignatureService(objectMapper);
    }
}
```

### Signing Requests (Client Side)
```java
@Service
public class ApiClient {
    
    private final HttpSignatureService signatureService;
    private final RestTemplate restTemplate;
    
    @Value("${api.agent.token}")
    private String agentToken;
    
    public ResponseEntity<String> makeSecureRequest(RequestData data, String host, String path) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<RequestData> requestEntity = new HttpEntity<>(data, headers);
        
        // Sign the request
        HttpEntity<RequestData> signedRequest = signatureService.signRequest(
            requestEntity, agentToken, "POST", path, host
        );
        
        return restTemplate.postForEntity("https://" + host + path, signedRequest, String.class);
    }
}
```

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