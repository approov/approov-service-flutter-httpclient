// Regression cover for TESTING_REQUIREMENTS.md §2 "Unprotected Request Processing": a URL the
// Approov SDK does not protect must be forwarded without tokens, trace headers, message signing or
// **string substitutions**.
//
// Two paths used to violate that. The default mutator returned true for UNPROTECTED_URL, which let
// header substitution run after the token fetch; and automatic query substitution ran before any
// token fetch could classify the URL at all, because dart:io fixes a request's URI at openUrl()
// time. Either one could resolve a secure string into a request bound for a host Approov neither
// tokenizes nor pins - the MitM exposure that approov-service-okhttp's default mutator calls out
// explicitly when it returns false for the same statuses.

import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const MethodChannel fgChannel =
      MethodChannel('approov_service_flutter_httpclient_fg');
  const MethodChannel bgChannel =
      MethodChannel('approov_service_flutter_httpclient_bg');
  late Future<dynamic> Function(MethodCall call) fgHandler;
  late Future<dynamic> Function(MethodCall call) bgHandler;

  setUp(() {
    ApproovService.resetInitStateForTesting();
    fgHandler = (MethodCall call) async => null;
    bgHandler = (MethodCall call) async => null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(fgChannel, (call) => fgHandler(call));
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(bgChannel, (call) => bgHandler(call));
  });

  tearDown(() {
    ApproovService.removeSubstitutionQueryParam('api_key');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(fgChannel, null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(bgChannel, null);
  });

  /// Delivers a fetch result for [transactionID] the way the native side would.
  Future<void> deliver(String transactionID, Map<String, Object?> result) {
    return TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .handlePlatformMessage(
      fgChannel.name,
      fgChannel.codec.encodeMethodCall(MethodCall('response', {
        'TransactionID': transactionID,
        'ARC': '',
        'RejectionReasons': '',
        'IsConfigChanged': false,
        'IsForceApplyPins': false,
        'MeasurementConfig': Uint8List(0),
        'LoggableToken': 'loggable',
        'TraceID': '',
        'ConfigEpoch': 0,
        ...result,
      })),
      null,
    );
  }

  test('the default mutator skips mutation for an unprotected URL', () {
    // The gate that keeps header substitution off unprotected hosts: _updateRequest returns as soon
    // as this is false, before it reaches the substitution loop.
    final mutator = ApproovServiceMutator.DEFAULT;
    expect(
      mutator.handleInterceptorFetchTokenResult(
          ApproovTokenFetchResult(
            tokenFetchStatus: ApproovTokenFetchStatus.UNPROTECTED_URL,
            token: '',
            secureString: null,
            arc: '',
            rejectionReasons: '',
            isConfigChanged: false,
            isForceApplyPins: false,
            measurementConfig: Uint8List(0),
            loggableToken: 'loggable',
            traceID: '',
            requestURL: 'https://unprotected.example.com/',
            proceedOnNetworkFail: false,
            useApproovStatusIfNoToken: false,
          ),
          'https://unprotected.example.com/'),
      isFalse,
    );
  });

  test('query substitution is skipped for an unprotected URL', () async {
    final methods = <String>[];
    fgHandler = (MethodCall call) async {
      methods.add(call.method);
      if (call.method == 'fetchApproovToken') {
        final args = call.arguments as Map;
        await deliver('${args['transactionID']}', {
          'TokenFetchStatus': 'UNPROTECTED_URL',
          'Token': '',
        });
      }
      return null;
    };

    await ApproovService.initialize('real-config');
    ApproovService.addSubstitutionQueryParam('api_key');

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://unprotected.example.com/?api_key=secret-id'));

    expect(preparation.uri.queryParameters['api_key'], 'secret-id',
        reason: 'the placeholder must be left untouched for an unprotected URL');
    expect(methods, isNot(contains('fetchSecureString')),
        reason: 'no secure string may even be fetched for an unprotected URL');
    expect(preparation.requestMutations.substitutionQueryParamKeys, isEmpty);
  });

  test('query substitution still runs for a protected URL', () async {
    // The control: the same configuration on a URL the SDK does protect must substitute, so the
    // guard above cannot pass by disabling the feature outright.
    fgHandler = (MethodCall call) async {
      final args = call.arguments as Map;
      if (call.method == 'fetchApproovToken') {
        await deliver('${args['transactionID']}', {
          'TokenFetchStatus': 'SUCCESS',
          'Token': 'approov-token',
        });
      } else if (call.method == 'fetchSecureString') {
        await deliver('${args['transactionID']}', {
          'TokenFetchStatus': 'SUCCESS',
          'Token': '',
          'SecureString': 'resolved-secret',
        });
      }
      return null;
    };

    await ApproovService.initialize('real-config');
    ApproovService.addSubstitutionQueryParam('api_key');

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://protected.example.com/?api_key=secret-id'));

    expect(preparation.uri.queryParameters['api_key'], 'resolved-secret');
    expect(preparation.requestMutations.substitutionQueryParamKeys,
        contains('api_key'));
  });

  test('a URL that cannot be classified is not substituted', () async {
    // An inconclusive classification (no network, internal error) must not leak the secret either:
    // the substitution is skipped and the request proceeds to be judged by the mutator later.
    fgHandler = (MethodCall call) async {
      if (call.method == 'fetchApproovToken') {
        final args = call.arguments as Map;
        await deliver('${args['transactionID']}', {
          'TokenFetchStatus': 'NO_NETWORK',
          'Token': '',
        });
      }
      return null;
    };

    await ApproovService.initialize('real-config');
    ApproovService.addSubstitutionQueryParam('api_key');

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://protected.example.com/?api_key=secret-id'));

    expect(preparation.uri.queryParameters['api_key'], 'secret-id');
  });
  test('an empty secure string leaves the query placeholder in place', () async {
    // TESTING_REQUIREMENTS §2 "Missing Artifacts Fallback": an empty value is not a value. Rewriting
    // the parameter to `api_key=` would destroy the placeholder the backend needs to see, and the
    // header equivalent would send an empty or prefix-only header.
    fgHandler = (MethodCall call) async {
      final args = call.arguments as Map;
      if (call.method == 'fetchApproovToken') {
        await deliver('${args['transactionID']}', {
          'TokenFetchStatus': 'SUCCESS',
          'Token': 'approov-token',
        });
      } else if (call.method == 'fetchSecureString') {
        await deliver('${args['transactionID']}', {
          'TokenFetchStatus': 'SUCCESS',
          'Token': '',
          'SecureString': '',
        });
      }
      return null;
    };

    await ApproovService.initialize('real-config');
    ApproovService.addSubstitutionQueryParam('api_key');

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://protected.example.com/?api_key=secret-id'));

    expect(preparation.uri.queryParameters['api_key'], 'secret-id',
        reason: 'an empty secure string must not overwrite the placeholder');
    expect(preparation.requestMutations.substitutionQueryParamKeys, isEmpty,
        reason: 'no substitution was applied, so none may be recorded');
  });

  test('substituteQueryParam leaves the placeholder for an empty secure string', () async {
    // Same rule through the public API, which apps call directly when they build URLs themselves.
    fgHandler = (MethodCall call) async {
      final args = call.arguments as Map;
      if (call.method == 'fetchSecureString') {
        await deliver('${args['transactionID']}', {
          'TokenFetchStatus': 'SUCCESS',
          'Token': '',
          'SecureString': '',
        });
      }
      return null;
    };

    await ApproovService.initialize('real-config');
    final original = Uri.parse('https://protected.example.com/?api_key=secret-id');
    final result = await ApproovService.substituteQueryParam(original, 'api_key');
    expect(result, original);
  });

}
