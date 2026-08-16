# Reference

This document provides reference details for `ApproovService` APIs in this package.

Import:

```dart
import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';
```

Most async methods may throw:

- `ApproovException`
- `ApproovNetworkException`
- `ApproovRejectionException`

## Initialization

### `initialize(String config, [String? comment])`

Initializes the service layer. A non-empty config initializes the native Approov SDK; an empty config enters bypass mode, where the service layer is initialized but Approov protection is disabled. `initialize()` completes only after the initialization attempt succeeds or fails.

Every non-empty config is forwarded to the native SDK. Native failures are surfaced to the caller and leave the existing service-layer state unchanged. Successful initialization resets runtime request configuration such as header overrides, token binding, substitutions, exclusions, message signing, and custom mutators.

### `isInitialized()`

Returns `Future<bool>`, resolving to `true` once `initialize()` has been called successfully at least once — including when initialized in bypass mode with an empty configuration string. Does not indicate whether Approov protection is actually active; use `isApproovEnabled()` for that. Unlike most other async methods in this package, this does not throw when `initialize()` has never been called or its most recent attempt failed — it resolves to `false` instead.

### `isApproovEnabled()`

Returns `Future<bool>`, resolving to `true` only when Approov-backed protection (token injection, pinning, secure string substitution) is actually active — i.e. `initialize()` was called with a non-empty configuration string. Resolves to `false` in bypass mode, and also resolves to `false` (rather than throwing) if `initialize()` has never been called or its most recent attempt failed.

### Behaviour in bypass mode

When the service layer is initialized with an empty configuration string it is *initialized but not
protected*. The methods below are guarded so nothing reaches the native Approov SDK, and they do not
all behave the same way — check the column before relying on one:

| Behaviour in bypass mode | Methods |
|---|---|
| Throws `ApproovException("Approov is not enabled")` | `precheck`, `getDeviceID`, `fetchToken`, `getMessageSignature`, `getAccountMessageSignature`, `fetchSecureString`, `fetchCustomJWT`, `setDevKey` |
| Returns an empty map | `getPins` |
| Returns an empty string | `getLastARC` |
| Silent no-op | `setDataHashInToken` |
| Returns the input unchanged | `substituteQueryParam` |

Request processing is unaffected by these guards: requests are forwarded with no Approov token, no
trace header, no message signing, no secure string substitution and no Approov dynamic pinning.
Ordinary TLS certificate validation still applies, and a certificate that fails it is still
rejected.

### Re-initialization and the `comment` argument

The `comment` participates in the native SDK's already-initialized matching, alongside the
configuration string. A repeat call with the same config is accepted only when the comment is
**identical to the one used at first initialization** (commonly `null`), or starts with `reinit`.
Any other comment - including swapping `null` for `""` - is reported by the native SDK as an
initialization with a different configuration and surfaced as an `ApproovException`, with the
service layer state left unchanged. Applications that re-initialize at runtime should therefore keep
the comment stable or use the `reinit...` form.

## Mutator APIs

### `setServiceMutator(ApproovServiceMutator? mutator)`

Sets callback handlers that can customize fetch/interceptor/pinning behavior.  
Passing `null` resets to `ApproovServiceMutator.DEFAULT`.

### `getServiceMutator()`

Returns the currently configured mutator.

### `setApproovInterceptorExtensions(ApproovServiceMutator? mutator)` (deprecated)

Alias for `setServiceMutator`.

### `getApproovInterceptorExtensions()` (deprecated)

Alias for `getServiceMutator`.

## Logging APIs

### `setLoggingLevel(ApproovLogLevel level)`

Sets service-layer log verbosity:

- `ApproovLogLevel.OFF`
- `ApproovLogLevel.ERROR`
- `ApproovLogLevel.WARNING`
- `ApproovLogLevel.TRACE`

`TRACE` enables detailed diagnostics in the service layer, including platform method call/return timing and error tracing with sensitive values redacted.

### `getLoggingLevel()`

Returns the currently configured service-layer logging level.

## Network behavior

### `setProceedOnNetworkFail(bool proceed)`

Controls whether interceptor flows can continue when Approov fetch fails due to networking conditions.

### `setApproovHeader(String header, String? prefix)`

Sets token header name and optional prefix.
Passing `null` for `prefix` is equivalent to no prefix.

This applies to both:

- normal token injection (`<prefix><jwt>`)
- optional status fallback injection (`<prefix><STATUS_ENUM>`)

### `setApproovTraceIDHeader(String? header)`

Sets (or disables) the optional trace ID header.

### `getApproovTraceIDHeader()`

Returns the current trace ID header or `null`.

### `setBindingHeader(String header)`

Binds tokens to a header value hash.

### `setUseApproovStatusIfNoToken(bool shouldUse)`

Enables/disables status fallback in the configured token header when no token is available.

When enabled, and interceptor mutator processing allows continuation, allowlisted token-fetch failure statuses can be sent in the token header:

- `NO_NETWORK`
- `POOR_NETWORK`
- `MITM_DETECTED`

### `getUseApproovStatusIfNoToken()`

Returns the current status-fallback toggle value.

### `addExclusionURLRegex(String urlRegex)`

Adds a URL exclusion regex to skip Approov processing for matching requests.

### `removeExclusionURLRegex(String urlRegex)`

Removes an exclusion regex.

## Secure strings

### `addSubstitutionHeader(String header, String? requiredPrefix)`

Marks a header for secure string substitution.

### `removeSubstitutionHeader(String header)`

Removes substitution header configuration.

### `addSubstitutionQueryParam(String key)`

Marks a query parameter key for automatic secure string substitution during request-open flow.

### `removeSubstitutionQueryParam(String key)`

Removes automatic query substitution for a key.

### `substituteQueryParam(Uri uri, String queryParameter)`

Performs explicit one-off query substitution and returns the resulting URI.

### `fetchSecureString(String key, String? newDef)`

Fetches secure string value or sets a per-device definition when `newDef` is provided.

## Tokens, attestation and JWT

### `prefetch()`

**OBSOLETE**: This method is obsolete and is now a no-op. The underlying Approov SDK manages prefetching automatically.

### `precheck()`

Runs pre-attestation style check by fetching a dummy secure string.

### `fetchToken(String url)`

Fetches a token for a specific URL.

### `fetchCustomJWT(String payload)`

Fetches a custom JWT with provided payload JSON.

### `getLastARC()`

Fetches and returns last ARC value if available.

### `getDeviceID()`

Returns device identifier from Approov SDK.

### `setDataHashInToken(String data)`

Directly sets a data hash to be included in token payload.

## Message signing

### `enableMessageSigning({SignatureParametersFactory? defaultFactory, Map<String, SignatureParametersFactory>? hostFactories})`

Enables automatic message signing.

**Failure semantics (fail-open, matching `approov-service-okhttp`):** if signing fails for any reason — the SDK cannot provide an install or account signature, a serialization error, a custom factory error — the request **proceeds unsigned** (no `Signature`, `Signature-Input`, or `Content-Digest` headers are added) and the reason is logged at error level. The backend is the enforcement point for message signatures. Only two conditions abort the request with an `ApproovException` instead: a body digest configured as **required** that cannot be generated (`RequiredBodyDigestException`), and an **unsupported or missing** signing algorithm (`UnsupportedSignatureAlgorithmException`). Both exception types are exported so custom `SignatureParametersFactory` implementations can throw them to force an abort.

### `disableMessageSigning()`

Disables message signing.

### `getMessageSignature(String message)`

Legacy account signature API.

### `getAccountMessageSignature(String message)`

Preferred account message signature API.

## HTTP client wrappers

### `ApproovHttpClient`

Drop-in replacement for `dart:io` `HttpClient` with Approov tokening, substitutions, and pinning.

### `ApproovClient`

Drop-in replacement for `package:http` `BaseClient`.

## Mutator callback types

### `ApproovServiceMutator`

Override callback methods to customize:

- precheck result handling
- fetchToken/fetchSecureString/fetchCustomJWT result handling
- request processing gate
- token fetch decision in interceptor flow
- header/query substitution decisions
- processed request hook (with `ApproovRequestMutations`)
- pinning gate

### `ApproovRequestMutations`

Provides mutation details:

- token header key
- trace ID header key
- substituted header keys
- original URL (for query substitutions)
- substituted query parameter keys

### `ApproovRequestSnapshot`

Immutable callback snapshot containing request method, URI, header snapshot and exclusion match.

### `ApproovTokenFetchResult` and `ApproovTokenFetchStatus`

Callback-safe fetch payload and status enum used by mutator callbacks.
