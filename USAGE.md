# Usage

This document describes how to use the Approov Flutter HttpClient wrapper and how to customize request behavior with `ApproovServiceMutator`.

## Approov Service Mutator

`ApproovServiceMutator` lets you customize behavior at key points in the request lifecycle without forking this package.

### Why use a mutator

- Centralize app-specific policy in one place.
- Add telemetry for attestation failures and retryable networking failures.
- Control whether requests are processed by Approov.
- Customize token and secure string substitution behavior.
- Customize pinning decisions per request.

### Default behavior

By default, `ApproovServiceMutator.DEFAULT` preserves existing Flutter service behavior.

| Approov Fetch Status | Default Action |
| --- | --- |
| `SUCCESS` | Continue |
| `NO_NETWORK` / `POOR_NETWORK` / `MITM_DETECTED` | If `setUseApproovStatusIfNoToken(true)` is active, interceptor flow continues and status fallback can be injected in the token header. Otherwise throw `ApproovNetworkException` (unless `setProceedOnNetworkFail(true)` is active in interceptor flows). |
| `REJECTED` | Throw `ApproovRejectionException` |
| `NO_APPROOV_SERVICE` | `fetchToken`: return token as before (possibly empty). Interceptor flow: continue without token. |
| `UNKNOWN_URL` | Interceptor flow continues without token |
| `UNPROTECTED_URL` | Interceptor flow continues (token omitted, substitutions can still run) |

## Install a custom mutator

```dart
import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';

class MyMutator extends ApproovServiceMutator {
  @override
  FutureOr<bool> handleInterceptorShouldProcessRequest(
      ApproovRequestSnapshot request) {
    if (request.uri.host == 'metrics.example.com') {
      return false;
    }
    return super.handleInterceptorShouldProcessRequest(request);
  }
}

void configureApproov() {
  ApproovService.setServiceMutator(MyMutator());
}
```

To reset to defaults:

```dart
ApproovService.setServiceMutator(null);
```

## Service-layer logging

Use service-layer logging when diagnosing production issues.

```dart
ApproovService.setLoggingLevel(ApproovLogLevel.TRACE);
```

Available levels:

- `ApproovLogLevel.OFF`
- `ApproovLogLevel.ERROR`
- `ApproovLogLevel.WARNING`
- `ApproovLogLevel.TRACE`

`TRACE` enables detailed diagnostics from the service layer, including platform channel method calls, timing, and result/error traces (with sensitive values redacted).

## Failure status fallback in token header

Use this when you want backend services to receive a fetch-failure reason in the configured token header when no token is available.

```dart
ApproovService.setUseApproovStatusIfNoToken(true);
```

Defaults:

- `useApproovStatusIfNoToken = false`
- fallback allowlist: `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED`

Behavior in interceptor request flow:

1. Approov token fetch runs as normal.
2. Mutator callback `handleInterceptorFetchTokenResult(...)` is evaluated first.
3. If mutator allows processing:
   - `SUCCESS` + token present -> inject `<prefix><jwt>`
   - no token + status-fallback enabled + allowlisted status -> inject `<prefix><STATUS_ENUM>`
4. Otherwise no fallback value is injected.

Notes:

- Header name and prefix come from `setApproovHeader(header, prefix)`.
- Fallback is not injected by default for `NO_APPROOV_SERVICE`, `UNKNOWN_URL`, `UNPROTECTED_URL`, `REJECTED`, or internal/unknown statuses.
- Trace ID behavior is unchanged (only standard token success path controls trace ID injection).

## Message signing with a mutator

Message signing setup is unchanged. You can still call:

```dart
ApproovService.enableMessageSigning();
```

The mutator callback order is:

1. `handleInterceptorShouldProcessRequest`
2. token fetch and `handleInterceptorFetchTokenResult`
3. header/query substitutions callbacks
4. message signing (if enabled and token fetch succeeded)
5. `handleInterceptorProcessedRequest`

## Secure string substitutions

### Header substitutions

```dart
ApproovService.addSubstitutionHeader('Api-Key', null);
ApproovService.addSubstitutionHeader('Authorization', 'Bearer ');
```

### Query parameter substitutions

Explicit one-off substitution:

```dart
final rewritten = await ApproovService.substituteQueryParam(uri, 'api_key');
```

Automatic substitution for requests sent via `ApproovHttpClient` / `ApproovClient`:

```dart
ApproovService.addSubstitutionQueryParam('api_key');
ApproovService.removeSubstitutionQueryParam('api_key');
```

## Token binding

Bind tokens to a header value (for example OAuth bearer token):

```dart
ApproovService.setBindingHeader('Authorization');
```

## Real-world mutator example

```dart
import 'dart:async';
import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';

class PolicyMutator extends ApproovServiceMutator {
  final Set<String> protectedHosts = {'api.example.com'};
  final Set<String> allowOfflineHosts = {'status.example.com'};
  final Set<String> skipPinningHosts = {'metrics.example.com'};

  @override
  FutureOr<bool> handleInterceptorShouldProcessRequest(
      ApproovRequestSnapshot request) {
    if (!protectedHosts.contains(request.uri.host)) return false;
    return super.handleInterceptorShouldProcessRequest(request);
  }

  @override
  FutureOr<bool> handleInterceptorFetchTokenResult(
      ApproovTokenFetchResult result, String url) {
    final host = Uri.parse(url).host;
    if ((result.tokenFetchStatus == ApproovTokenFetchStatus.NO_NETWORK ||
            result.tokenFetchStatus == ApproovTokenFetchStatus.POOR_NETWORK) &&
        allowOfflineHosts.contains(host)) {
      return false;
    }
    return super.handleInterceptorFetchTokenResult(result, url);
  }

  @override
  FutureOr<bool> handlePinningShouldProcessRequest(
      ApproovRequestSnapshot request) {
    if (skipPinningHosts.contains(request.uri.host)) return false;
    return true;
  }
}
```

## Structured field conformance tests

HTTP message signing uses Structured Fields. To run conformance tests:

1. Clone [httpwg/structured-field-tests](https://github.com/httpwg/structured-field-tests).
2. Copy `.json`, `README.md`, `LICENSE.md`, and `serialisation-tests/` into `test/third_party/structured_field_tests`.
3. Run:

```bash
flutter test test/structured_fields_conformance_test.dart
```

## Tips

- Keep mutator logic lightweight because callbacks execute on the request path.
- Start from `ApproovServiceMutator.DEFAULT` behavior and override only required hooks.
- Use `ApproovRequestMutations` in `handleInterceptorProcessedRequest` for auditing what changed.
