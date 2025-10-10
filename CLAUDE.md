# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a security-focused HTTP Message Signatures library for Java, implementing HMAC-SHA256 request signing following HTTP Message Signatures specification patterns. The library provides both signing and verification capabilities for secure HTTP request authentication.

## Build Commands

```bash
# Build the library (compile + test)
./gradlew build

# Run tests
./gradlew test

# Clean build artifacts
./gradlew clean

# Build without tests
./gradlew assemble

# Build with all JAR artifacts (main, sources, javadoc)
./gradlew jar sourcesJar javadocJar
```

## Publishing

```bash
# Publish to local Maven repository for testing
./gradlew publishToMavenLocal

# Publish to GitHub Packages (requires credentials)
./gradlew publish
```

Set credentials via properties or environment variables:
- `gpr.user` / `USERNAME` - GitHub username
- `gpr.key` / `TOKEN` - GitHub personal access token

## Architecture

### Core Components

**HttpSignatureService** (`src/main/java/dev/bluestep/http/signatures/HttpSignatureService.java`)
- Primary service for creating and verifying HTTP signatures
- Implements HMAC-SHA256 signing with canonical string construction
- Follows HTTP Message Signatures specification patterns
- Key methods:
  - `signRequest()`: Creates signature headers for outbound requests
  - `verifyRequest()`: Validates signatures on inbound requests
- Creates canonical signing string from: (request-target), host, date, digest
- Provides 5-minute replay protection window via date validation

**HttpHeaders** (`src/main/java/dev/bluestep/http/signatures/HttpHeaders.java`)
- Lightweight header container with zero external dependencies
- Case-insensitive header storage (all keys normalized to lowercase)
- Provides basic Map interface for header manipulation

**HttpSignatureHeaders** (`src/main/java/dev/bluestep/http/signatures/HttpSignatureHeaders.java`)
- Wrapper providing convenient access to signature-related headers
- Contains helper methods for extracting Signature, Date, Digest, Host headers
- Includes Spring integration support via `addToSpringHeaders()` when Spring is available

### Security Features

The library implements multiple security layers:
1. **HMAC-SHA256 signatures** - Industry standard cryptographic signing
2. **Request-target signing** - HTTP method + path to prevent endpoint confusion attacks
3. **Host header signing** - Prevents cross-host replay attacks
4. **Timestamp validation** - Date header with 5-minute window prevents replay attacks
5. **Body integrity** - SHA-256 digest of request body prevents tampering
6. **Canonical signing string** - Prevents signature manipulation

### Dependencies

**Required (api)**:
- Jackson Core & Databind (2.15.3) - JSON serialization only

**Optional (compileOnly)**:
- Spring Web & Context (6.0.13) - For Spring integration
- Only required if using Spring Framework features

**Test**:
- JUnit Jupiter 5.13.4 (latest version with Java 25 support)
- JUnit Platform Launcher (required for test execution)
- Mockito 5.6.0
- Spring Test & Web (for integration tests)

### Design Philosophy

1. **Minimal dependencies**: Only Jackson for JSON, Spring is optional
2. **Security first**: Implements proven cryptographic patterns, not custom security
3. **Standards compliance**: Follows HTTP Message Signatures specification patterns
4. **Zero-trust verification**: Always validates all components (signature, timestamp, digest, host)
5. **Fail-safe**: Verification returns false on any exception or validation failure

## Testing

The project includes comprehensive test coverage (78 tests total):
- **HttpSignatureServiceTest** - 28 tests covering signing, verification, replay protection, and security validations
- **HttpHeadersTest** - 24 tests for case-insensitive header operations
- **HttpSignatureHeadersTest** - 26 tests for signature header wrapper functionality

Test coverage includes:
- Valid signature creation and verification
- Tamper detection (modified body, path, method, host)
- Replay attack prevention (expired/future timestamps)
- Edge cases (complex JSON, special characters, malformed inputs)
- Cross-host attack prevention
- Security validations with correct/incorrect secrets

Tests are located in `src/test/java/` following standard Maven/Gradle structure.

## Java Version

Library targets Java 25 for latest features and performance. JUnit 5.13.4 (July 2025) provides full Java 25 compatibility.
