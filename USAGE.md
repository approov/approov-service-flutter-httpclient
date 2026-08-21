# Usage

This document describes how to use the Approov Flutter HttpClient wrapper and how to customize request behavior with `ApproovServiceMutator`.

## Handling an initialization failure

`await ApproovService.initialize(config)` completes only after the native initialization attempt
finishes, and throws `ApproovException` if the SDK rejects the configuration. What to do next is a
policy decision rather than a technical one, so the package does not choose for you.

The strictest option is to let the exception propagate: the app does not start, and the failure is
impossible to miss. The permissive option is to fall back to bypass mode, where the layer is
initialized but applies no Approov token injection, no dynamic pinning and no secret substitution:

```dart
try {
  await ApproovService.initialize('<enter-your-config-string-here>');
} catch (e) {
  // Continues UNPROTECTED. Ordinary TLS certificate validation still applies, but no Approov
  // protection is active, so the backend is the only enforcement point for these requests.
  await ApproovService.initialize('');
}
```

Use `isApproovEnabled()` afterwards to report which state the app ended up in, and prefer your own
logger over `print` so the outcome reaches whatever telemetry you already collect. Note that this
pattern trades protection for availability on every launch that fails to initialize; if that is not
the trade you want, do not catch.

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
| `NO_NETWORK` / `POOR_NETWORK` / `MITM_DETECTED` | Throw `ApproovNetworkException` on the token fetch and on both substitution paths. Fail-closed unconditionally: `setUseApproovStatusIfNoToken(true)` is a backend-visibility feature and never lets a request continue, and `setProceedOnNetworkFail` is an obsolete no-op. Install a custom mutator to proceed instead — the status fallback is still injected into the token header when such a mutator returns `true` and the flag is on. |
| `REJECTED` | Throw `ApproovRejectionException` |
| `NO_APPROOV_SERVICE` | `fetchToken`: return token as before (possibly empty). Interceptor flow: **continue**, forwarding the request unmodified so an Approov outage does not take the app offline. No token is available, so the token header is **omitted** unless `setUseApproovStatusIfNoToken(true)` is active, in which case it carries `NO_APPROOV_SERVICE`. An empty-valued or prefix-only header is never sent. Secure-string substitution **fails closed** (`ApproovException`): with no secret resolved, the only alternative is sending the placeholder as the credential. |
| `UNKNOWN_URL` | Interceptor flow continues without token |
| `UNPROTECTED_URL` | Interceptor flow skips all mutation: no token, no trace header, no message signing, and **no secure-string substitution**. Automatic query substitution is suppressed too, by classifying the URL before the request is opened — that classification runs ahead of the mutator, so overriding `handleInterceptorFetchTokenResult` re-enables header substitution but not query substitution. Call `substituteQueryParam()` directly if you need one regardless |

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
- fallback allowlist: `NO_APPROOV_SERVICE`, `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED`

Of these, only `NO_APPROOV_SERVICE` is reached with the default mutator — the three network statuses
fail closed unless a custom mutator deliberately allows them to continue.

Behavior in interceptor request flow:

1. Approov token fetch runs as normal.
2. Mutator callback `handleInterceptorFetchTokenResult(...)` is evaluated first.
3. If mutator allows processing:
   - `SUCCESS` + token present -> inject `<prefix><jwt>`
   - no token + status-fallback enabled + allowlisted status -> inject `<prefix><STATUS_ENUM>`
4. Otherwise no fallback value is injected.

Notes:

- Header name and prefix come from `setApproovHeader(header, prefix)`; pass `null` for no prefix.
- Fallback is not injected for `UNKNOWN_URL`, `UNPROTECTED_URL`, `REJECTED`, or internal/unknown statuses. `NO_APPROOV_SERVICE` is on the allowlist, so the token header carries `NO_APPROOV_SERVICE` when the fallback is enabled — but with the fallback disabled the header is **omitted entirely** for it, exactly as for every other artifact-less outcome. An empty-valued or prefix-only token header is never sent.
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

**Signing failures are fail-open** (matching `approov-service-okhttp`): a request whose signature cannot be produced goes out **unsigned** with the reason logged at error level, and the backend decides whether to accept it. The only two conditions that abort the request instead are a body digest configured as required that cannot be generated (`RequiredBodyDigestException`) and an unsupported or missing signing algorithm (`UnsupportedSignatureAlgorithmException`). If your backend strictly enforces signatures, monitor error logs for `skipping message signing` lines.

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
