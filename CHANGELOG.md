## [3.5.8] - (30-July-2026)

> **Upgrade notes:**
> - `await ApproovService.initialize(config)` now completes only after the native initialization attempt finishes, and **throws `ApproovException` on failure** — previously it returned immediately and swallowed native failures. Wrap it in try/catch if you want to fall back to bypass mode (see README).
> - Every successful `initialize()`/re-initialize now **resets the runtime configuration** (custom mutator, header overrides, token binding, substitutions, exclusions, message signing, cached pinning certificates). Apply configuration **after** `await initialize(...)` returns; configuration applied before it is discarded.
> - **Mixed-quickstart apps:** the service layer no longer tolerates the native SDK reporting that it was already initialized with a *different* configuration. Previously that outcome was caught and ignored, so an app in which another Approov quickstart had already initialized the SDK with different parameters kept working; it now surfaces as an `ApproovException` from `initialize()` (`TESTING_REQUIREMENTS.md` §1, "Cross-Service-Layer Different Config Initialization" — a different config must not be silently accepted). Align the configuration strings, or use a `reinit...` comment.
> - Message signing failures now **proceed unsigned** instead of aborting the request, except for a required body digest that cannot be generated and an unsupported/missing signing algorithm, which still abort (`TESTING_REQUIREMENTS.md` §5; matches `approov-service-okhttp`). Backends enforcing signatures remain the enforcement point.

- **`setProceedOnNetworkFail()` is now an obsolete no-op** (matching `approov-service-okhttp`). The argument is ignored and no default handler reads it, so `NO_NETWORK` / `POOR_NETWORK` / `MITM_DETECTED` now fail closed on every path: the token fetch throws `ApproovNetworkException` unless `setUseApproovStatusIfNoToken(true)` is active, and header/query substitution always throws. The flag was a single global switch across every network-related status, so it could not proceed on "no network" without also proceeding on `MITM_DETECTED` — continuing after the SDK detected interception, potentially before dynamic pins had been received. Express the policy per status instead by overriding `ApproovServiceMutator.handleInterceptorFetchTokenResult` (or the substitution handlers) and installing it with `setServiceMutator`. `ApproovTokenFetchResult.proceedOnNetworkFail` is deprecated and always false.
- Fix secure-string substitution reaching URLs the SDK does not protect (`TESTING_REQUIREMENTS.md` §2, "Unprotected Request Processing"). Two paths were affected: the default mutator returned `true` for `UNPROTECTED_URL`, which let **header** substitution run after the token fetch, and automatic **query** substitution ran before any token fetch could classify the URL, because `dart:io` fixes a request's URI at `openUrl()` time. Either could resolve a secure string into a request bound for a host Approov neither tokenizes nor pins. The default mutator now returns `false` for `UNPROTECTED_URL` (joining `UNKNOWN_URL`, and matching `approov-service-okhttp`), and query substitution now runs only when a pre-open classification positively confirms the URL is protected — any other outcome, including a network failure or an internal error, suppresses it. A custom mutator can still opt back in by overriding `handleInterceptorFetchTokenResult`.
- Document that the config-taking constructors `ApproovHttpClient([config])` and `ApproovClient([config])` cannot report an initialization failure to the caller: a constructor cannot await, so `initialize()`'s new asynchronous throw is not catchable around construction. The failure is retained and rethrown from the first request through the client, and the pending error no longer surfaces as an unhandled asynchronous error. Prefer `await ApproovService.initialize(config)` before constructing the client, which is the pattern the README documents.
- Add `isInitialized()` and `isApproovEnabled()` public API methods (Dart, Android, iOS).
- Fix native initialization state being tracked **per `FlutterEngine`** rather than per process. The plugin instance is created once per engine, so an app with a second engine (background fetch, alarm or geolocation plugins) saw "not initialized" there while the process-wide Approov SDK was initialized and protecting traffic — and the Dart layer read that as "native unprotected" and committed real bypass mode, silently dropping token injection and pinning for every request from that engine. The state is now held in a process-wide static on both platforms (matching `approov-service-okhttp`), and `isInitialized()`/`isApproovEnabled()` are answered from it.
- Query the native state over the background method channel when the foreground channel cannot answer, so `isInitialized()`/`isApproovEnabled()` and the empty-config protection probe work from background isolates instead of reporting `false` because the channel was unreachable. When neither channel answers, bypass is assumed (per `TESTING_REQUIREMENTS.md` §1) and now logged at error level rather than passed over silently.
- Document the bypass-mode contract in `REFERENCE.md`: the guarded methods do not behave uniformly (throw / empty map / empty string / no-op / pass-through), and that difference is now stated per method.
- Document that the `comment` argument participates in the native SDK's already-initialized matching, so a same-config re-initialization is accepted only with an identical comment or one starting with `reinit` (`TESTING_REQUIREMENTS.md` §1, "Comment Is Part Of The Platform SDK Initialization Identity").
- Guard the iOS `initialConfig` argument against `NSNull`, as the `comment` and `updateConfig` arguments already are: `-[NSNull length]` is an unrecognised selector and would crash rather than read as empty.
- Fix `initialize('')` (empty configuration string) to actually enter bypass mode — initializes the service layer without calling the native Approov SDK, instead of throwing. Previously this would fail with a native exception surfaced as a Dart `PlatformException`, contradicting documentation that claimed bypass-mode support.
- Fix `initialize()` re-initialization guard to allow the "empty config → valid config" upgrade transition and to silently ignore a "valid config → empty config" downgrade attempt, per the cross-service-layer `TESTING_REQUIREMENTS.md` spec, instead of throwing in both directions.
- Fix initialization to await the current native initialization attempt, preserve `null` comments when forwarding to native, forward every non-empty config to the native SDK, and preserve existing service-layer state when native initialization fails.
- Reset runtime service-layer configuration after every successful initialization/re-initialization, including custom mutators, header overrides, token binding, substitutions, exclusions, message signing, and cached pinning certificates.
- Fix bypass mode (empty configuration string) to genuinely behave as a plain, unprotected network client end-to-end, matching `approov-service-react-native`'s pattern: the core request pipeline now skips token injection, pinning, and secure string substitution entirely for every request, and every other public method that talks to the native SDK directly (`precheck`, `getDeviceID`, `fetchToken`, `getMessageSignature`, `getAccountMessageSignature`, `fetchSecureString`, `fetchCustomJWT`, `setDevKey`, `getPins`, `setDataHashInToken`, `substituteQueryParam`) now fails cleanly with `ApproovException("Approov is not enabled")` (or a safe no-op/empty default, where that is the correct behavior) instead of crashing with a native exception. Previously only `initialize('')` itself worked; every other entry point still reached the uninitialized native SDK.
- Fix a cross-thread race on iOS between the background-channel `initialize` write and the foreground-channel `isInitialized`/`isApproovEnabled` reads of the same state, matching the equivalent Android fix (`volatile` fields).
- Fix automatic token binding to await `setDataHashInToken(...)` before fetching the bound Approov token.
- Fix message signing fallback behavior so signing and serialization failures fail open, while required body-digest failures and unsupported algorithms still fail closed.
- Fix Structured Fields date serialization conformance for syntactic min/max date values.
- Fix a race where overlapping failed re-initialization attempts could leave a healthy, successfully initialized service throwing a stale initialization error from every API call: a failed attempt now restores a freshly resolved initialization future (never a captured earlier one) whenever a successful initialization is in effect.
- Fix a state desynchronization window where a failure in the post-initialization telemetry call (`setUserProperty`) failed the whole `initialize()` after the native SDK had already committed — leaving Dart in bypass while native was protected. The Dart state now commits immediately after native success and the telemetry call is best-effort (matches `approov-service-okhttp` ordering).
- Fix a cross-isolate divergence where a fresh isolate (or hot restart) calling `initialize('')` while the process-wide native layer was already protected would commit bypass mode locally — silently skipping pinning and token injection for that isolate's requests while `isApproovEnabled()` reported `true`. The Dart layer now queries native and adopts protected mode.
- Fail-closed message signing classification now uses typed exceptions (`RequiredBodyDigestException`, `UnsupportedSignatureAlgorithmException`, both exported) instead of error-message string matching; a params object with a *missing* algorithm identifier now also fails closed, matching `approov-service-okhttp`. Custom `SignatureParametersFactory` implementations can throw `RequiredBodyDigestException` to force an abort.
- Fix staged message signing header application to preserve multi-value header adds from custom factories (previously collapsed to the last value, producing signatures the server could never verify). Note: as in `approov-service-okhttp`, when signing fails open the request goes out without `Content-Digest` (signing-related headers are staged and only applied on success).
- Log (rather than silently discard) the native SDK's already-initialized result on a same-config re-initialization, on both platforms.
- Raise the `logger` dependency lower bound to `^2.1.0` (`DateTimeFormat` is used and was added in 2.1.0).
- Deprecate `prefetch()` — it is now a no-op, matching the rest of the Approov service layer family (`approov-service-retrofit`, `approov-service-urlsession`, and others). The Approov SDK manages prefetching automatically; the explicit prefetch call is redundant.

## [3.5.7] - (27-July-2026)
- Add Swift Package Manager (SPM) support for iOS, alongside continued CocoaPods support.
- Move iOS native sources from `ios/Classes` to `ios/approov_service_flutter_httpclient/Sources/approov_service_flutter_httpclient` per Flutter's plugin SPM layout.

## [3.5.6] - (05-March-2026)
- Add `ApproovServiceMutator` support across fetch APIs, request mutation flow, and pinning gate callbacks.
- Add request mutation models: `ApproovRequestMutations`, `ApproovRequestSnapshot`, `ApproovTokenFetchResult`, and `ApproovTokenFetchStatus`.
- Add `setServiceMutator()` / `getServiceMutator()` plus deprecated alias methods for naming parity.
- Add service-layer logging controls: `ApproovLogLevel` with `OFF`, `ERROR`, `WARNING`, `TRACE` and `setLoggingLevel()` / `getLoggingLevel()`.
- Add detailed TRACE diagnostics for platform-channel method calls, timing, and failures (with sensitive-value redaction).
- Add automatic query substitution APIs: `addSubstitutionQueryParam()` and `removeSubstitutionQueryParam()`.
- Add `setUseApproovStatusIfNoToken(bool)` and `getUseApproovStatusIfNoToken()` to control token-header status fallback behavior.
- Add interceptor token-header fallback injection for allowlisted statuses when no token is available: `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED`.
- Preserve mutator-first decision ordering: fallback injection only occurs when `handleInterceptorFetchTokenResult(...)` allows continuation.
- Ensure configured token header name and prefix from `setApproovHeader(...)` apply equally to JWT and status fallback values.
- Propagate Approov trace IDs to request headers.
- Update `USAGE.md` and `REFERENCE.md` with status-fallback behavior, defaults, allowlist, and mutator interaction.
- Restructure docs to OkHttp-style layout with `README.md`, `USAGE.md`, and `REFERENCE.md`.
- (fix) Don't throw exception on missing public key
## [3.5.5] - (17-December-2025)
- Updates Approov IOS SDK to 3.5.3
- Add a capability to retrieve an ARC(Attestation Response Code) via getLastARC()
- Add a capability to retrieve pins from the Approov SDK via getPins().

## [3.5.4] - (05-December-2025)
- Ensure compatibility with Flutter 3.29+ threading model changes.

## [3.5.3] - (25-November-2025)
- Update Android SDK to version 3.5.3

## [3.5.2] - (12-November-2025)
- Update platform SDK to version 3.5.2
- HTTP Message Signing Support

## [3.5.1] - (31-July-2025)
- Update platform SDK to version 3.5.1

## [3.5.0] - (31-July-2025)
- Update platform SDK to version 3.5.0

## [3.4.2] - (2025-May-20)
- Async service initialize function now returns a future to enable awaits
- Fix pub.dev listing to link to the correct github repo

## [3.4.1] - (2025-May-09)
- Support calling Approov from main isolate and any background isolate
- Performance improvements
- Allow reinitialization with the same configuration
- Edge case bug fixes
- Align major and minor version with native SDK

## [0.0.5] - (2025-Feb-26)
- Updated readme. 
- First published to pub.dev
- Update iOS native pod package to 3.3.1
