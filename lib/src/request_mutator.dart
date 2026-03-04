import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:enum_to_string/enum_to_string.dart';

/// Potential status values returned by an Approov fetch operation.
///
/// These values are shared across token fetch, secure string fetch and custom
/// JWT operations.
enum ApproovTokenFetchStatus {
  SUCCESS,
  NO_NETWORK,
  MITM_DETECTED,
  POOR_NETWORK,
  NO_APPROOV_SERVICE,
  BAD_URL,
  UNKNOWN_URL,
  UNPROTECTED_URL,
  NO_NETWORK_PERMISSION,
  MISSING_LIB_DEPENDENCY,
  INTERNAL_ERROR,
  REJECTED,
  DISABLED,
  UNKNOWN_KEY,
  BAD_KEY,
  BAD_PAYLOAD
}

/// Result payload returned from an Approov fetch operation.
///
/// This object carries both platform-provided result data and request-scoped
/// callback context (for example the request URL and
/// `proceedOnNetworkFail` snapshot).
class ApproovTokenFetchResult {
  /// Creates a token fetch result value.
  ///
  /// @param tokenFetchStatus is the normalized status of the fetch operation
  /// @param token is the token/JWT value returned by the SDK when available
  /// @param secureString is the secure string value for secure string lookups
  /// @param arc is the attestation response code from the SDK
  /// @param rejectionReasons is the textual rejection reason details
  /// @param isConfigChanged is true if SDK config changed during fetch
  /// @param isForceApplyPins is true if pins must be refreshed before traffic
  /// @param measurementConfig is measurement configuration bytes from SDK
  /// @param loggableToken is a token-safe logging value
  /// @param traceID is the trace identifier associated with the fetch
  /// @param requestURL is the request URL associated with the fetch, if known
  /// @param proceedOnNetworkFail is the active proceed-on-network-fail setting
  /// @param useApproovStatusIfNoToken indicates status fallback token semantics
  ApproovTokenFetchResult({
    required this.tokenFetchStatus,
    required this.token,
    required this.secureString,
    required this.arc,
    required this.rejectionReasons,
    required this.isConfigChanged,
    required this.isForceApplyPins,
    required this.measurementConfig,
    required this.loggableToken,
    required this.traceID,
    required this.requestURL,
    required this.proceedOnNetworkFail,
    required this.useApproovStatusIfNoToken,
  });

  /// Convenience constructor that parses a platform channel result map.
  ///
  /// @param tokenFetchResultMap is the raw map returned by the platform plugin
  /// @param requestURL is an optional request URL associated with the fetch
  /// @param proceedOnNetworkFail is the callback-time network failure policy
  /// @param useApproovStatusIfNoToken indicates status fallback token semantics
  /// @return a normalized [ApproovTokenFetchResult] instance
  factory ApproovTokenFetchResult.fromTokenFetchResultMap(
    Map tokenFetchResultMap, {
    String? requestURL,
    bool proceedOnNetworkFail = false,
    bool useApproovStatusIfNoToken = false,
  }) {
    final parsedStatus = EnumToString.fromString(
      ApproovTokenFetchStatus.values,
      tokenFetchResultMap["TokenFetchStatus"],
    );
    return ApproovTokenFetchResult(
      tokenFetchStatus: parsedStatus ?? ApproovTokenFetchStatus.INTERNAL_ERROR,
      token: tokenFetchResultMap["Token"] ?? "",
      secureString: tokenFetchResultMap["SecureString"],
      arc: tokenFetchResultMap["ARC"] ?? "",
      rejectionReasons: tokenFetchResultMap["RejectionReasons"] ?? "",
      isConfigChanged: tokenFetchResultMap["IsConfigChanged"] ?? false,
      isForceApplyPins: tokenFetchResultMap["IsForceApplyPins"] ?? false,
      measurementConfig:
          tokenFetchResultMap["MeasurementConfig"] ?? Uint8List(0),
      loggableToken: tokenFetchResultMap["LoggableToken"] ?? "",
      traceID: tokenFetchResultMap["TraceID"] ?? "",
      requestURL: requestURL,
      proceedOnNetworkFail: proceedOnNetworkFail,
      useApproovStatusIfNoToken: useApproovStatusIfNoToken,
    );
  }

  /// Normalized fetch status.
  final ApproovTokenFetchStatus tokenFetchStatus;

  /// Returned token value (or custom JWT value for custom JWT operations).
  final String token;

  /// Returned secure string value for secure string fetch operations.
  final String? secureString;

  /// Attestation response code returned by the SDK.
  final String arc;

  /// Additional rejection details returned by the SDK.
  final String rejectionReasons;

  /// True if SDK configuration changed during the operation.
  final bool isConfigChanged;

  /// True if pins must be force-applied before continuing traffic.
  final bool isForceApplyPins;

  /// Measurement configuration bytes returned by the SDK.
  final Uint8List measurementConfig;

  /// Logging-safe representation of the token fetch output.
  final String loggableToken;

  /// Trace identifier for the fetch operation.
  final String traceID;

  /// Optional URL associated with the fetch operation.
  final String? requestURL;

  /// Snapshot of `setProceedOnNetworkFail` at the callback point.
  final bool proceedOnNetworkFail;

  /// Snapshot of whether the status should be used as token value when empty.
  final bool useApproovStatusIfNoToken;

  /// Returns a copy of this result with optional callback-context overrides.
  ///
  /// @param requestURL overrides the request URL for callback consumers
  /// @param proceedOnNetworkFail overrides network failure continuation policy
  /// @param useApproovStatusIfNoToken overrides status fallback token behavior
  /// @return a copied [ApproovTokenFetchResult] with requested overrides
  ApproovTokenFetchResult copyWith({
    String? requestURL,
    bool? proceedOnNetworkFail,
    bool? useApproovStatusIfNoToken,
  }) {
    return ApproovTokenFetchResult(
      tokenFetchStatus: tokenFetchStatus,
      token: token,
      secureString: secureString,
      arc: arc,
      rejectionReasons: rejectionReasons,
      isConfigChanged: isConfigChanged,
      isForceApplyPins: isForceApplyPins,
      measurementConfig: measurementConfig,
      loggableToken: loggableToken,
      traceID: traceID,
      requestURL: requestURL ?? this.requestURL,
      proceedOnNetworkFail: proceedOnNetworkFail ?? this.proceedOnNetworkFail,
      useApproovStatusIfNoToken:
          useApproovStatusIfNoToken ?? this.useApproovStatusIfNoToken,
    );
  }
}

/// Immutable snapshot of request metadata provided to mutator callbacks.
///
/// Header names are normalized to lowercase for case-insensitive lookup.
class ApproovRequestSnapshot {
  /// Creates a request snapshot.
  ///
  /// @param requestMethod is the HTTP method associated with the callback
  /// @param uri is the request URI at the callback point
  /// @param headers are the current request headers
  /// @param isURLExcluded is true when URL exclusion rules matched this request
  ApproovRequestSnapshot({
    required this.requestMethod,
    required this.uri,
    required Map<String, List<String>> headers,
    required this.isURLExcluded,
  }) : headers = LinkedHashMap<String, List<String>>.fromEntries(
          headers.entries.map((entry) => MapEntry(
              entry.key.toLowerCase(), List<String>.from(entry.value))),
        );

  /// HTTP method for the request.
  final String requestMethod;

  /// Request URI as seen at this callback point.
  final Uri uri;

  /// Snapshot of headers, keyed by lowercase header name.
  final LinkedHashMap<String, List<String>> headers;

  /// True when URL exclusion regex rules matched this request.
  final bool isURLExcluded;

  /// Checks if a header exists in this snapshot.
  ///
  /// @param headerName is the case-insensitive header name to test
  /// @return true if the header exists, otherwise false
  bool hasHeader(String headerName) =>
      headers.containsKey(headerName.toLowerCase());

  /// Returns the combined header value for a given header name.
  ///
  /// If a header has multiple values they are joined with `", "`.
  ///
  /// @param headerName is the case-insensitive header name to retrieve
  /// @return the combined header value, or null if header is absent
  String? headerValue(String headerName) {
    final values = headers[headerName.toLowerCase()];
    if (values == null || values.isEmpty) return null;
    return values.join(', ');
  }
}

/// Tracks request mutations applied during Approov request processing.
///
/// This payload is provided to `handleInterceptorProcessedRequest` so custom
/// mutators can inspect what was changed.
class ApproovRequestMutations {
  String? _tokenHeaderKey;
  String? _traceIDHeaderKey;
  final LinkedHashSet<String> _substitutionHeaderKeys = LinkedHashSet<String>();
  String? _originalURL;
  final LinkedHashSet<String> _substitutionQueryParamKeys =
      LinkedHashSet<String>();

  /// Gets the header name where an Approov token was written, if any.
  String? get tokenHeaderKey => _tokenHeaderKey;

  /// Records the header name where an Approov token was written.
  ///
  /// @param tokenHeaderKey is the token header name that was set
  void setTokenHeaderKey(String tokenHeaderKey) {
    _tokenHeaderKey = tokenHeaderKey;
  }

  /// Gets the header name where an Approov trace ID was written, if any.
  String? get traceIDHeaderKey => _traceIDHeaderKey;

  /// Records the header name where an Approov trace ID was written.
  ///
  /// @param traceIDHeaderKey is the trace ID header name that was set
  void setTraceIDHeaderKey(String traceIDHeaderKey) {
    _traceIDHeaderKey = traceIDHeaderKey;
  }

  /// Gets header names that were substituted using secure strings.
  List<String> get substitutionHeaderKeys =>
      List<String>.unmodifiable(_substitutionHeaderKeys);

  /// Replaces the tracked substituted header key set.
  ///
  /// @param substitutionHeaderKeys is the complete substituted header key list
  void setSubstitutionHeaderKeys(List<String> substitutionHeaderKeys) {
    _substitutionHeaderKeys
      ..clear()
      ..addAll(substitutionHeaderKeys);
  }

  /// Adds one substituted header key to the tracked mutation set.
  ///
  /// @param headerName is the substituted header name
  void addSubstitutionHeaderKey(String headerName) {
    _substitutionHeaderKeys.add(headerName);
  }

  /// Gets the original URL before any automatic query substitutions.
  String? get originalURL => _originalURL;

  /// Gets query parameter keys that were substituted using secure strings.
  List<String> get substitutionQueryParamKeys =>
      List<String>.unmodifiable(_substitutionQueryParamKeys);

  /// Replaces tracked query substitution results.
  ///
  /// @param originalURL is the URL before query substitutions were applied
  /// @param substitutionQueryParamKeys are substituted query parameter keys
  void setSubstitutionQueryParamResults(
      String originalURL, List<String> substitutionQueryParamKeys) {
    _originalURL = originalURL;
    _substitutionQueryParamKeys
      ..clear()
      ..addAll(substitutionQueryParamKeys);
  }

  /// Adds one substituted query parameter key.
  ///
  /// The first provided [originalURL] is retained for callback inspection.
  ///
  /// @param queryKey is the substituted query parameter key
  /// @param originalURL is the pre-substitution URL
  void addSubstitutionQueryParamKey(String queryKey, String originalURL) {
    _originalURL ??= originalURL;
    _substitutionQueryParamKeys.add(queryKey);
  }
}

/// Allows customization of Approov lifecycle and request processing behavior.
///
/// The default implementations preserve the existing Flutter behavior.
class ApproovServiceMutator {
  /// Default mutator instance that mirrors historic Flutter behavior.
  static final ApproovServiceMutator DEFAULT = ApproovServiceMutator();

  /// Handles precheck results.
  ///
  /// Default behavior:
  /// - accepts `SUCCESS` and `UNKNOWN_KEY`
  /// - throws [ApproovRejectionException] for `REJECTED`
  /// - throws [ApproovNetworkException] for network-related failures
  /// - throws [ApproovException] for all other statuses
  ///
  /// @param approovResults is the precheck fetch result
  /// @throws ApproovException for any disallowed status
  FutureOr<void> handlePrecheckResult(ApproovTokenFetchResult approovResults) {
    final status = approovResults.tokenFetchStatus;
    switch (status) {
      case ApproovTokenFetchStatus.REJECTED:
        throw ApproovRejectionException(
            "precheck: ${status.name}: ${approovResults.arc} ${approovResults.rejectionReasons}",
            approovResults.arc,
            approovResults.rejectionReasons);
      case ApproovTokenFetchStatus.NO_NETWORK:
      case ApproovTokenFetchStatus.POOR_NETWORK:
      case ApproovTokenFetchStatus.MITM_DETECTED:
        throw ApproovNetworkException("precheck: ${status.name}");
      case ApproovTokenFetchStatus.SUCCESS:
      case ApproovTokenFetchStatus.UNKNOWN_KEY:
        break;
      default:
        throw ApproovException("precheck: ${status.name}");
    }
  }

  /// Handles direct `fetchToken` API results.
  ///
  /// Default behavior:
  /// - accepts `SUCCESS` and `NO_APPROOV_SERVICE`
  /// - throws [ApproovNetworkException] for network-related failures
  /// - throws [ApproovException] for all other statuses
  ///
  /// @param approovResults is the fetch result
  /// @throws ApproovException for any disallowed status
  FutureOr<void> handleFetchTokenResult(
      ApproovTokenFetchResult approovResults) {
    final status = approovResults.tokenFetchStatus;
    final url = approovResults.requestURL ?? "";
    if ((status == ApproovTokenFetchStatus.SUCCESS) ||
        (status == ApproovTokenFetchStatus.NO_APPROOV_SERVICE)) {
      return null;
    }
    if ((status == ApproovTokenFetchStatus.NO_NETWORK) ||
        (status == ApproovTokenFetchStatus.POOR_NETWORK) ||
        (status == ApproovTokenFetchStatus.MITM_DETECTED)) {
      throw ApproovNetworkException("fetchToken for $url: ${status.name}");
    }
    throw ApproovException("fetchToken for $url: ${status.name}");
  }

  /// Handles direct `fetchSecureString` API results.
  ///
  /// Default behavior:
  /// - accepts `SUCCESS` and `UNKNOWN_KEY`
  /// - throws [ApproovRejectionException] for `REJECTED`
  /// - throws [ApproovNetworkException] for network-related failures
  /// - throws [ApproovException] for all other statuses
  ///
  /// @param approovResults is the secure string fetch result
  /// @param operation is a human-readable operation label (`lookup/definition`)
  /// @param key is the secure string key associated with the request
  /// @throws ApproovException for any disallowed status
  FutureOr<void> handleFetchSecureStringResult(
    ApproovTokenFetchResult approovResults,
    String operation,
    String key,
  ) {
    final status = approovResults.tokenFetchStatus;
    switch (status) {
      case ApproovTokenFetchStatus.REJECTED:
        throw ApproovRejectionException(
            "fetchSecureString $operation for $key: ${status.name}: ${approovResults.arc} ${approovResults.rejectionReasons}",
            approovResults.arc,
            approovResults.rejectionReasons);
      case ApproovTokenFetchStatus.NO_NETWORK:
      case ApproovTokenFetchStatus.POOR_NETWORK:
      case ApproovTokenFetchStatus.MITM_DETECTED:
        throw ApproovNetworkException(
            "fetchSecureString $operation for $key: ${status.name}");
      case ApproovTokenFetchStatus.SUCCESS:
      case ApproovTokenFetchStatus.UNKNOWN_KEY:
        break;
      default:
        throw ApproovException(
            "fetchSecureString $operation for $key: ${status.name}");
    }
  }

  /// Handles direct `fetchCustomJWT` API results.
  ///
  /// Default behavior:
  /// - accepts `SUCCESS`
  /// - throws [ApproovRejectionException] for `REJECTED`
  /// - throws [ApproovNetworkException] for network-related failures
  /// - throws [ApproovException] for all other statuses
  ///
  /// @param approovResults is the custom JWT fetch result
  /// @throws ApproovException for any disallowed status
  FutureOr<void> handleFetchCustomJWTResult(
      ApproovTokenFetchResult approovResults) {
    final status = approovResults.tokenFetchStatus;
    switch (status) {
      case ApproovTokenFetchStatus.REJECTED:
        throw ApproovRejectionException(
            "fetchCustomJWT: ${status.name}: ${approovResults.arc} ${approovResults.rejectionReasons}",
            approovResults.arc,
            approovResults.rejectionReasons);
      case ApproovTokenFetchStatus.NO_NETWORK:
      case ApproovTokenFetchStatus.POOR_NETWORK:
      case ApproovTokenFetchStatus.MITM_DETECTED:
        throw ApproovNetworkException("fetchCustomJWT: ${status.name}");
      case ApproovTokenFetchStatus.SUCCESS:
        break;
      default:
        throw ApproovException("fetchCustomJWT: ${status.name}");
    }
  }

  /// Decides whether interceptor processing should run for a request.
  ///
  /// Default behavior skips processing for URLs matched by exclusion rules.
  ///
  /// @param request is the request snapshot at interceptor entry
  /// @return true to continue interceptor processing, otherwise false
  FutureOr<bool> handleInterceptorShouldProcessRequest(
      ApproovRequestSnapshot request) {
    return !request.isURLExcluded;
  }

  /// Handles token fetch result during interceptor request processing.
  ///
  /// Default behavior:
  /// - continues for `SUCCESS` and `UNPROTECTED_URL`
  /// - skips token/header mutation for `NO_APPROOV_SERVICE` and `UNKNOWN_URL`
  /// - on network failures, either throws or skips based on
  ///   `approovResults.proceedOnNetworkFail`
  /// - throws [ApproovException] for all other statuses
  ///
  /// @param approovResults is the interceptor token fetch result
  /// @param url is the request URL being processed
  /// @return true to continue request mutation, false to skip mutation
  /// @throws ApproovException for disallowed failure statuses
  FutureOr<bool> handleInterceptorFetchTokenResult(
      ApproovTokenFetchResult approovResults, String url) {
    final status = approovResults.tokenFetchStatus;
    switch (status) {
      case ApproovTokenFetchStatus.SUCCESS:
        return true;
      case ApproovTokenFetchStatus.NO_NETWORK:
      case ApproovTokenFetchStatus.POOR_NETWORK:
      case ApproovTokenFetchStatus.MITM_DETECTED:
        if (!approovResults.proceedOnNetworkFail) {
          throw ApproovNetworkException(
              "Approov token fetch for $url: ${status.name}");
        }
        return false;
      case ApproovTokenFetchStatus.NO_APPROOV_SERVICE:
      case ApproovTokenFetchStatus.UNKNOWN_URL:
        return false;
      case ApproovTokenFetchStatus.UNPROTECTED_URL:
        return true;
      default:
        throw ApproovException("Approov token fetch for $url: ${status.name}");
    }
  }

  /// Handles secure string substitution result for a header.
  ///
  /// Default behavior:
  /// - returns true only for `SUCCESS`
  /// - returns false for `UNKNOWN_KEY`
  /// - on network failures, either throws or returns false based on
  ///   `approovResults.proceedOnNetworkFail`
  /// - throws [ApproovRejectionException] for `REJECTED`
  /// - throws [ApproovException] for all other statuses
  ///
  /// @param approovResults is the secure string fetch result
  /// @param header is the header name being substituted
  /// @return true to apply substitution, false to leave original value
  /// @throws ApproovException for disallowed failure statuses
  FutureOr<bool> handleInterceptorHeaderSubstitutionResult(
      ApproovTokenFetchResult approovResults, String header) {
    final status = approovResults.tokenFetchStatus;
    switch (status) {
      case ApproovTokenFetchStatus.SUCCESS:
        return true;
      case ApproovTokenFetchStatus.REJECTED:
        throw ApproovRejectionException(
            "Header substitution for $header: ${status.name}: ${approovResults.arc} ${approovResults.rejectionReasons}",
            approovResults.arc,
            approovResults.rejectionReasons);
      case ApproovTokenFetchStatus.NO_NETWORK:
      case ApproovTokenFetchStatus.POOR_NETWORK:
      case ApproovTokenFetchStatus.MITM_DETECTED:
        if (!approovResults.proceedOnNetworkFail) {
          throw ApproovNetworkException(
              "Header substitution for $header: ${status.name}");
        }
        return false;
      case ApproovTokenFetchStatus.UNKNOWN_KEY:
        return false;
      default:
        throw ApproovException(
            "Header substitution for $header: ${status.name}");
    }
  }

  /// Handles secure string substitution result for a query parameter.
  ///
  /// Default behavior:
  /// - returns true only for `SUCCESS`
  /// - returns false for `UNKNOWN_KEY`
  /// - on network failures, either throws or returns false based on
  ///   `approovResults.proceedOnNetworkFail`
  /// - throws [ApproovRejectionException] for `REJECTED`
  /// - throws [ApproovException] for all other statuses
  ///
  /// @param approovResults is the secure string fetch result
  /// @param queryKey is the query parameter key being substituted
  /// @return true to apply substitution, false to leave original value
  /// @throws ApproovException for disallowed failure statuses
  FutureOr<bool> handleInterceptorQueryParamSubstitutionResult(
      ApproovTokenFetchResult approovResults, String queryKey) {
    final status = approovResults.tokenFetchStatus;
    switch (status) {
      case ApproovTokenFetchStatus.SUCCESS:
        return true;
      case ApproovTokenFetchStatus.REJECTED:
        throw ApproovRejectionException(
            "Query parameter substitution for $queryKey: ${status.name}: ${approovResults.arc} ${approovResults.rejectionReasons}",
            approovResults.arc,
            approovResults.rejectionReasons);
      case ApproovTokenFetchStatus.NO_NETWORK:
      case ApproovTokenFetchStatus.POOR_NETWORK:
      case ApproovTokenFetchStatus.MITM_DETECTED:
        if (!approovResults.proceedOnNetworkFail) {
          throw ApproovNetworkException(
              "Query parameter substitution for $queryKey: ${status.name}");
        }
        return false;
      case ApproovTokenFetchStatus.UNKNOWN_KEY:
        return false;
      default:
        throw ApproovException(
            "Query parameter substitution for $queryKey: ${status.name}");
    }
  }

  /// Called after interceptor processing finishes for a request.
  ///
  /// Default behavior is a no-op.
  ///
  /// @param request is the processed request object (typically `HttpClientRequest`)
  /// @param changes describes all mutations applied during processing
  FutureOr<void> handleInterceptorProcessedRequest(
      dynamic request, ApproovRequestMutations changes) {}

  /// Decides whether pinning setup should run for a request.
  ///
  /// Default behavior always enables pinning processing.
  ///
  /// @param request is the request snapshot at pinning decision point
  /// @return true to apply pinning behavior, false to bypass pinning setup
  FutureOr<bool> handlePinningShouldProcessRequest(
      ApproovRequestSnapshot request) {
    return true;
  }
}

/// Base exception for Approov SDK and mutator related failures.
class ApproovException implements Exception {
  /// Root failure reason.
  String? cause;

  /// Creates a new exception with a message.
  ///
  /// @param cause is the underlying error reason
  ApproovException(String cause) {
    this.cause = cause;
  }

  @override
  String toString() {
    return "ApproovException: $cause";
  }
}

/// Exception indicating temporary network-related failures.
class ApproovNetworkException extends ApproovException {
  /// Creates a new network exception.
  ///
  /// @param cause is the underlying error reason
  ApproovNetworkException(String cause) : super(cause);

  @override
  String toString() {
    return "ApproovNetworkException: $cause";
  }
}

/// Exception carrying explicit rejection metadata from Approov.
class ApproovRejectionException extends ApproovException {
  /// Attestation response code associated with the rejection.
  String? arc;

  /// Detailed rejection reasons associated with the rejection.
  String? rejectionReasons;

  /// Creates a rejection exception with ARC and rejection reason details.
  ///
  /// @param cause is the underlying error reason
  /// @param arc is the attestation response code
  /// @param rejectionReasons is the detailed rejection reason text
  ApproovRejectionException(String cause, String arc, String rejectionReasons)
      : super(cause) {
    this.arc = arc;
    this.rejectionReasons = rejectionReasons;
  }

  @override
  String toString() {
    return "ApproovRejectionException: $cause ARC:$arc reasons:$rejectionReasons";
  }
}
