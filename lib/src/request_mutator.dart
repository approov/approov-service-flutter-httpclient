import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:enum_to_string/enum_to_string.dart';

/// Potential status results from an Approov fetch attempt.
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

/// Results from an Approov token fetch.
class ApproovTokenFetchResult {
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

  /// Convenience constructor to generate the results from a platform map.
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

  final ApproovTokenFetchStatus tokenFetchStatus;
  final String token;
  final String? secureString;
  final String arc;
  final String rejectionReasons;
  final bool isConfigChanged;
  final bool isForceApplyPins;
  final Uint8List measurementConfig;
  final String loggableToken;
  final String traceID;

  /// Optional URL associated with the fetch operation.
  final String? requestURL;

  /// Snapshot of `setProceedOnNetworkFail` at the callback point.
  final bool proceedOnNetworkFail;

  /// Snapshot of whether the status should be used as token value when empty.
  final bool useApproovStatusIfNoToken;

  /// Copies the result, optionally overriding request-scoped callback context.
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

/// Metadata describing a request at a mutator callback point.
class ApproovRequestSnapshot {
  ApproovRequestSnapshot({
    required this.requestMethod,
    required this.uri,
    required Map<String, List<String>> headers,
    required this.isURLExcluded,
  }) : headers = LinkedHashMap<String, List<String>>.fromEntries(
          headers.entries.map((entry) => MapEntry(
              entry.key.toLowerCase(), List<String>.from(entry.value))),
        );

  final String requestMethod;
  final Uri uri;
  final LinkedHashMap<String, List<String>> headers;
  final bool isURLExcluded;

  bool hasHeader(String headerName) =>
      headers.containsKey(headerName.toLowerCase());

  String? headerValue(String headerName) {
    final values = headers[headerName.toLowerCase()];
    if (values == null || values.isEmpty) return null;
    return values.join(', ');
  }
}

/// Stores information about changes made to a request during Approov processing.
class ApproovRequestMutations {
  String? _tokenHeaderKey;
  String? _traceIDHeaderKey;
  final LinkedHashSet<String> _substitutionHeaderKeys = LinkedHashSet<String>();
  String? _originalURL;
  final LinkedHashSet<String> _substitutionQueryParamKeys =
      LinkedHashSet<String>();

  String? get tokenHeaderKey => _tokenHeaderKey;

  void setTokenHeaderKey(String tokenHeaderKey) {
    _tokenHeaderKey = tokenHeaderKey;
  }

  String? get traceIDHeaderKey => _traceIDHeaderKey;

  void setTraceIDHeaderKey(String traceIDHeaderKey) {
    _traceIDHeaderKey = traceIDHeaderKey;
  }

  List<String> get substitutionHeaderKeys =>
      List<String>.unmodifiable(_substitutionHeaderKeys);

  void setSubstitutionHeaderKeys(List<String> substitutionHeaderKeys) {
    _substitutionHeaderKeys
      ..clear()
      ..addAll(substitutionHeaderKeys);
  }

  void addSubstitutionHeaderKey(String headerName) {
    _substitutionHeaderKeys.add(headerName);
  }

  String? get originalURL => _originalURL;

  List<String> get substitutionQueryParamKeys =>
      List<String>.unmodifiable(_substitutionQueryParamKeys);

  void setSubstitutionQueryParamResults(
      String originalURL, List<String> substitutionQueryParamKeys) {
    _originalURL = originalURL;
    _substitutionQueryParamKeys
      ..clear()
      ..addAll(substitutionQueryParamKeys);
  }

  void addSubstitutionQueryParamKey(String queryKey, String originalURL) {
    _originalURL ??= originalURL;
    _substitutionQueryParamKeys.add(queryKey);
  }
}

/// Allows customization of Approov service behavior at key lifecycle points.
///
/// The default implementations preserve the existing Flutter behavior.
class ApproovServiceMutator {
  static final ApproovServiceMutator DEFAULT = ApproovServiceMutator();

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

  FutureOr<bool> handleInterceptorShouldProcessRequest(
      ApproovRequestSnapshot request) {
    return !request.isURLExcluded;
  }

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

  FutureOr<void> handleInterceptorProcessedRequest(
      dynamic request, ApproovRequestMutations changes) {}

  FutureOr<bool> handlePinningShouldProcessRequest(
      ApproovRequestSnapshot request) {
    return true;
  }
}

/// ApproovException is thrown if there is an error from Approov.
class ApproovException implements Exception {
  String? cause;

  ApproovException(String cause) {
    this.cause = cause;
  }

  @override
  String toString() {
    return "ApproovException: $cause";
  }
}

/// ApproovNetworkException indicates temporary networking issues.
class ApproovNetworkException extends ApproovException {
  ApproovNetworkException(String cause) : super(cause);

  @override
  String toString() {
    return "ApproovNetworkException: $cause";
  }
}

/// ApproovRejectionException carries additional rejection details.
class ApproovRejectionException extends ApproovException {
  String? arc;
  String? rejectionReasons;

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
