## [3.5.7] - (05-March-2026)
- Add `setUseApproovStatusIfNoToken(bool)` and `getUseApproovStatusIfNoToken()` to control token-header status fallback behavior.
- Add interceptor token-header fallback injection for allowlisted statuses when no token is available: `NO_NETWORK`, `POOR_NETWORK`, `MITM_DETECTED`.
- Preserve mutator-first decision ordering: fallback injection only occurs when `handleInterceptorFetchTokenResult(...)` allows continuation.
- Ensure configured token header name and prefix from `setApproovHeader(...)` apply equally to JWT and status fallback values.
- Update `USAGE.md` and `REFERENCE.md` with status-fallback behavior, defaults, allowlist, and mutator interaction.

## [3.5.6] - (04-March-2026)
- Add `ApproovServiceMutator` support across fetch APIs, request mutation flow, and pinning gate callbacks.
- Add request mutation models: `ApproovRequestMutations`, `ApproovRequestSnapshot`, `ApproovTokenFetchResult`, and `ApproovTokenFetchStatus`.
- Add `setServiceMutator()` / `getServiceMutator()` plus deprecated alias methods for naming parity.
- Add service-layer logging controls: `ApproovLogLevel` with `OFF`, `ERROR`, `WARNING`, `TRACE` and `setLoggingLevel()` / `getLoggingLevel()`.
- Add detailed TRACE diagnostics for platform-channel method calls, timing, and failures (with sensitive-value redaction).
- Add automatic query substitution APIs: `addSubstitutionQueryParam()` and `removeSubstitutionQueryParam()`.
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
