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

Initializes the Approov SDK. Must be called before any fetch operations.

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

## Network behavior

### `setProceedOnNetworkFail(bool proceed)`

Controls whether interceptor flows can continue when Approov fetch fails due to networking conditions.

### `setApproovHeader(String header, String prefix)`

Sets token header name and optional prefix.

### `setApproovTraceIDHeader(String? header)`

Sets (or disables) the optional trace ID header.

### `getApproovTraceIDHeader()`

Returns the current trace ID header or `null`.

### `setBindingHeader(String header)`

Binds tokens to a header value hash.

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

Starts an early token fetch to reduce effective latency later.

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
