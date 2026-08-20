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
      isFalse,
      reason: 'a URL the SDK does not protect must not be mutated at all - no '
          'token, and no secure-string substitution (TESTING_REQUIREMENTS §2)',
    );
    expect(
      () => mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_NETWORK),
          'https://api.example.com'),
      throwsA(isA<ApproovNetworkException>()),
    );
    expect(
      // proceedOnNetworkFail is an obsolete no-op: it no longer opens this path,
      // so a network failure still fails closed regardless of the flag. A custom
      // mutator overriding this handler is the supported way to proceed.
      () => mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_NETWORK,
              // ignore: deprecated_member_use_from_same_package
              proceedOnNetworkFail: true),
          'https://api.example.com'),
      throwsA(isA<ApproovNetworkException>()),
    );
    // setUseApproovStatusIfNoToken(true) is a backend-visibility feature and must
    // never decide whether a request is allowed to continue. The default mutator
    // is fail-closed for every status except SUCCESS and NO_APPROOV_SERVICE
    // (TESTING_REQUIREMENTS §3 "Default Mutator Behavior"). This deliberately
    // diverges from approov-service-okhttp, which still has the escape hatch.
    expect(
      () => mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_NETWORK,
              useApproovStatusIfNoToken: true),
          'https://api.example.com'),
      throwsA(isA<ApproovNetworkException>()),
    );
    expect(
      () => mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.POOR_NETWORK,
              useApproovStatusIfNoToken: true),
          'https://api.example.com'),
      throwsA(isA<ApproovNetworkException>()),
    );
    expect(
      () => mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.MITM_DETECTED,
              useApproovStatusIfNoToken: true),
          'https://api.example.com'),
      throwsA(isA<ApproovNetworkException>()),
      reason: 'enabling the status fallback must never let a request continue '
          'after the SDK reported MITM_DETECTED',
    );
    expect(
      () => mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.MITM_DETECTED),
          'https://api.example.com'),
      throwsA(isA<ApproovNetworkException>()),
    );
    expect(
      () => mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.POOR_NETWORK),
          'https://api.example.com'),
      throwsA(isA<ApproovNetworkException>()),
    );
    expect(
      // NO_APPROOV_SERVICE proceeds, matching approov-service-okhttp: the request
      // goes out unmodified rather than failing during an Approov outage
      // (TESTING_REQUIREMENTS §2 "Missing Artifacts Fallback").
      mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_APPROOV_SERVICE,
              useApproovStatusIfNoToken: true),
          'https://api.example.com'),
      isTrue,
    );
    expect(
      mutator.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_APPROOV_SERVICE),
          'https://api.example.com'),
      isTrue,
      reason: 'the status alone decides this, not the fallback flag',
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
    // NO_APPROOV_SERVICE fails closed on both substitution paths. The §3
    // carve-out that lets this status proceed covers the TOKEN fetch, where "no
    // token, backend decides" is a coherent degraded state; there is no
    // equivalent for a secret, because the only alternative to failing is
    // sending the placeholder as the credential - a wrong secret rather than an
    // absent one, with nothing for the app to retry on. Matches
    // approov-service-okhttp, approov-service-urlsession and
    // approov-service-nsurlsession.
    expect(
      () => mutator.handleInterceptorHeaderSubstitutionResult(
          _result(ApproovTokenFetchStatus.NO_APPROOV_SERVICE), 'Authorization'),
      throwsA(isA<ApproovException>()),
    );
    expect(
      () => mutator.handleInterceptorQueryParamSubstitutionResult(
          _result(ApproovTokenFetchStatus.NO_APPROOV_SERVICE), 'api_key'),
      throwsA(isA<ApproovException>()),
    );
    // the fallback flag does not turn substitution back into a proceed either:
    // it is a token-header visibility control, never a substitution decision
    expect(
      () => mutator.handleInterceptorHeaderSubstitutionResult(
          _result(ApproovTokenFetchStatus.NO_APPROOV_SERVICE,
              useApproovStatusIfNoToken: true),
          'Authorization'),
      throwsA(isA<ApproovException>()),
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
  test('setProceedOnNetworkFail is an obsolete no-op', () {
    // The setter must not change any behaviour. Calling it with true and then
    // exercising the default mutator on a network failure must still fail closed.
    // ignore: deprecated_member_use_from_same_package
    ApproovService.setProceedOnNetworkFail(true);
    expect(
      () => ApproovServiceMutator.DEFAULT.handleInterceptorFetchTokenResult(
          _result(ApproovTokenFetchStatus.NO_NETWORK),
          'https://api.example.com'),
      throwsA(isA<ApproovNetworkException>()),
    );
    expect(
      () => ApproovServiceMutator.DEFAULT
          .handleInterceptorHeaderSubstitutionResult(
              _result(ApproovTokenFetchStatus.NO_NETWORK), 'X-Api-Key'),
      throwsA(isA<ApproovNetworkException>()),
    );
    expect(
      ApproovService.runtimeStateForTesting()['proceedOnNetworkFail'],
      isFalse,
      reason: 'the setter must not record the value either',
    );
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
