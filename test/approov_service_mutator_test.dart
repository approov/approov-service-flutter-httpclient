import 'dart:async';
import 'dart:typed_data';

import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  tearDown(() {
    ApproovService.setServiceMutator(null);
    ApproovService.setLoggingLevel(ApproovLogLevel.WARNING);
    ApproovService.setUseApproovStatusIfNoToken(false);
  });

  test('setServiceMutator and aliases update active mutator', () {
    final custom = _RecordingMutator();
    ApproovService.setServiceMutator(custom);
    expect(ApproovService.getServiceMutator(), same(custom));

    final alias = _RecordingMutator();
    ApproovService.setApproovInterceptorExtensions(alias);
    expect(ApproovService.getApproovInterceptorExtensions(), same(alias));

    ApproovService.setServiceMutator(null);
    expect(ApproovService.getServiceMutator(), isNot(same(custom)));
  });

  test('default mutator throws rejection for precheck rejected', () {
    final mutator = ApproovServiceMutator.DEFAULT;
    expect(
      () => mutator
          .handlePrecheckResult(_result(ApproovTokenFetchStatus.REJECTED)),
      throwsA(isA<ApproovRejectionException>()),
    );
  });

  test('default mutator allows fetchToken success and no approov service', () {
    final mutator = ApproovServiceMutator.DEFAULT;
    expect(
      () => mutator
          .handleFetchTokenResult(_result(ApproovTokenFetchStatus.SUCCESS)),
      returnsNormally,
    );
    expect(
      () => mutator.handleFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_APPROOV_SERVICE)),
      returnsNormally,
    );
  });

  test(
      'default mutator token callback handles network and unprotected statuses',
      () {
    final mutator = ApproovServiceMutator.DEFAULT;
    expect(
      mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.SUCCESS), 'https://api.example.com'),
      isTrue,
    );
    expect(
      mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.UNPROTECTED_URL),
          'https://api.example.com'),
      isTrue,
    );
    expect(
      () => mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_NETWORK),
          'https://api.example.com'),
      throwsA(isA<ApproovNetworkException>()),
    );
    expect(
      mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_NETWORK,
              proceedOnNetworkFail: true),
          'https://api.example.com'),
      isFalse,
    );
    expect(
      mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_NETWORK,
              useApproovStatusIfNoToken: true),
          'https://api.example.com'),
      isTrue,
    );
    expect(
      mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.POOR_NETWORK,
              useApproovStatusIfNoToken: true),
          'https://api.example.com'),
      isTrue,
    );
    expect(
      mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.MITM_DETECTED,
              useApproovStatusIfNoToken: true),
          'https://api.example.com'),
      isTrue,
    );
    expect(
      mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_APPROOV_SERVICE,
              useApproovStatusIfNoToken: true),
          'https://api.example.com'),
      isFalse,
    );
  });

  test('default mutator handles header and query substitution statuses', () {
    final mutator = ApproovServiceMutator.DEFAULT;
    expect(
      mutator.handleInterceptorHeaderSubstitutionResult(
          _result(ApproovTokenFetchStatus.SUCCESS), 'Authorization'),
      isTrue,
    );
    expect(
      mutator.handleInterceptorHeaderSubstitutionResult(
          _result(ApproovTokenFetchStatus.UNKNOWN_KEY), 'Authorization'),
      isFalse,
    );
    expect(
      mutator.handleInterceptorQueryParamSubstitutionResult(
          _result(ApproovTokenFetchStatus.UNKNOWN_KEY), 'api_key'),
      isFalse,
    );
  });

  test('mutator methods can be async', () async {
    final mutator = _RecordingMutator();
    await mutator
        .handleFetchTokenResult(_result(ApproovTokenFetchStatus.SUCCESS));
    expect(mutator.called, isTrue);
  });

  test('setLoggingLevel updates active level', () {
    ApproovService.setLoggingLevel(ApproovLogLevel.TRACE);
    expect(ApproovService.getLoggingLevel(), ApproovLogLevel.TRACE);

    ApproovService.setLoggingLevel(ApproovLogLevel.ERROR);
    expect(ApproovService.getLoggingLevel(), ApproovLogLevel.ERROR);

    ApproovService.setLoggingLevel(ApproovLogLevel.OFF);
    expect(ApproovService.getLoggingLevel(), ApproovLogLevel.OFF);
  });

  test('setUseApproovStatusIfNoToken updates active value', () {
    expect(ApproovService.getUseApproovStatusIfNoToken(), isFalse);
    ApproovService.setUseApproovStatusIfNoToken(true);
    expect(ApproovService.getUseApproovStatusIfNoToken(), isTrue);
    ApproovService.setUseApproovStatusIfNoToken(false);
    expect(ApproovService.getUseApproovStatusIfNoToken(), isFalse);
  });
}

class _RecordingMutator extends ApproovServiceMutator {
  bool called = false;

  @override
  FutureOr<void> handleFetchTokenResult(
      ApproovTokenFetchResult approovResults) async {
    await Future<void>.delayed(const Duration(milliseconds: 1));
    called = true;
  }
}

ApproovTokenFetchResult _result(
  ApproovTokenFetchStatus status, {
  bool proceedOnNetworkFail = false,
  bool useApproovStatusIfNoToken = false,
}) {
  return ApproovTokenFetchResult(
    tokenFetchStatus: status,
    token: '',
    secureString: null,
    arc: 'arc',
    rejectionReasons: 'reasons',
    isConfigChanged: false,
    isForceApplyPins: false,
    measurementConfig: Uint8List(0),
    loggableToken: '',
    traceID: '',
    requestURL: 'https://api.example.com',
    proceedOnNetworkFail: proceedOnNetworkFail,
    useApproovStatusIfNoToken: useApproovStatusIfNoToken,
  );
}
