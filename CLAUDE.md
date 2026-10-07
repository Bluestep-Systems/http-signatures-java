# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Overview

HMAC-SHA256 HTTP Message Signatures library for Java — signs and verifies both
outbound and inbound HTTP requests. Two independent signing modes:

- **Header signatures** — `signRequest()` / `verifyRequest()` on
  `HttpSignatureService`. The canonical signing string is built from exactly
  four components: `(request-target)`, `host`, `date`, `digest`. Changing that
  set or its order breaks compatibility with every deployed verifier.
  The `String`-body `signRequest` overloads are the primitive: they digest exactly
  the UTF-8 bytes given (the caller must send that string). The `Object`-body
  overloads serialize with the injected Jackson 3 `ObjectMapper` and delegate;
  `verifyRequest` digests the raw received string, never re-serializing.
- **Query-parameter signatures** — `signQueryParameters()` /
  `verifyQueryParameters()`, for signing a URL rather than a request. The
  signature and timestamp ride in the `_sig` and `_sig_ts` parameters, which are
  excluded from the signed payload and from `getParameters()`.

## Build & Publish

`./gradlew build | test | assemble | clean`, and `publishToMavenLocal` /
`publish` (GitHub Packages). Credentials come from `gpr.user`/`USERNAME` and
`gpr.key`/`TOKEN`. Exact dependency versions and artifact wiring live in
`build.gradle` — read it there rather than trusting a copy here.

## Non-obvious behavior

- **Replay windows differ between the two modes.** Header verification
  (`isDateValid`) accepts a `Date` up to 5 minutes away **in either direction**
  (symmetric skew). Query-parameter verification allows only **1 minute of
  clock skew into the future** and a `DEFAULT_MAX_SIGNATURE_AGE` of 5 minutes,
  overridable per call via the 3-argument
  `verifyQueryParameters(..., Duration maxAge)` — a verifier whose clock runs
  fast will reject otherwise valid signed URLs.
- **Verification is fail-safe by design**: any exception or failed check returns
  false (headers) or a `QuerySignatureVerificationResult.failure(...)` (query
  params) rather than propagating. Do not "fix" a swallowed exception here into
  a throw without understanding that callers depend on the boolean/result
  contract.
- **Comparisons are constant-time** to prevent timing attacks. Never replace a
  signature comparison with `String.equals` or `Arrays.equals`.
- `HttpHeaders` normalizes all keys to lowercase; `getParameters()` returns a
  defensive copy. Both are relied on by tests.
- Spring support in `HttpSignatureHeaders.addToSpringHeaders()` is `compileOnly`
  — the library must keep working with Spring absent from the classpath.

## Testing

`./gradlew test`. Four test classes, 135 tests total: `HttpSignatureServiceTest`
(49), `QueryParameterSignatureTest` (34), `HttpSignatureHeadersTest` (28),
`HttpHeadersTest` (24). Coverage includes tamper detection (modified body, path,
method, host), replay prevention, cross-host attacks, and malformed input.

If you add or remove tests, either update these counts or delete them — a stale
count is worse than none.

## Java Version

Targets Java 25; JUnit 5.13.4 for Java 25 compatibility.
