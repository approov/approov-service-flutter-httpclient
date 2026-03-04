import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('request mutations stores token and trace header keys', () {
    final mutations = ApproovRequestMutations();
    mutations.setTokenHeaderKey('Approov-Token');
    mutations.setTraceIDHeaderKey('Approov-TraceID');

    expect(mutations.tokenHeaderKey, 'Approov-Token');
    expect(mutations.traceIDHeaderKey, 'Approov-TraceID');
  });

  test('request mutations deduplicates substitution headers', () {
    final mutations = ApproovRequestMutations();
    mutations.addSubstitutionHeaderKey('Authorization');
    mutations.addSubstitutionHeaderKey('Authorization');
    mutations.addSubstitutionHeaderKey('Api-Key');

    expect(mutations.substitutionHeaderKeys, ['Authorization', 'Api-Key']);
  });

  test('request mutations records original URL and query keys once', () {
    final mutations = ApproovRequestMutations();
    mutations.addSubstitutionQueryParamKey(
        'api_key', 'https://example.com?api_key=secret');
    mutations.addSubstitutionQueryParamKey(
        'api_key', 'https://example.com?api_key=secret');
    mutations.addSubstitutionQueryParamKey(
        'token', 'https://example.com?api_key=secret');

    expect(mutations.originalURL, 'https://example.com?api_key=secret');
    expect(mutations.substitutionQueryParamKeys, ['api_key', 'token']);
  });

  test('request snapshot normalizes and reads headers', () {
    final snapshot = ApproovRequestSnapshot(
      requestMethod: 'GET',
      uri: Uri.parse('https://api.example.com/path'),
      headers: <String, List<String>>{
        'Authorization': ['Bearer abc'],
      },
      isURLExcluded: false,
    );

    expect(snapshot.hasHeader('authorization'), isTrue);
    expect(snapshot.headerValue('Authorization'), 'Bearer abc');
  });

  test('token fetch result parses map and copyWith context', () {
    final parsed = ApproovTokenFetchResult.fromTokenFetchResultMap(
      <String, dynamic>{
        'TokenFetchStatus': 'SUCCESS',
        'Token': 'tok',
        'SecureString': 'sec',
        'ARC': 'A',
        'RejectionReasons': 'none',
        'IsConfigChanged': true,
        'IsForceApplyPins': false,
        'LoggableToken': 'loggable',
        'TraceID': 'trace',
      },
      requestURL: 'https://api.example.com',
      proceedOnNetworkFail: true,
    );

    final copied = parsed.copyWith(useApproovStatusIfNoToken: true);
    expect(parsed.tokenFetchStatus, ApproovTokenFetchStatus.SUCCESS);
    expect(parsed.requestURL, 'https://api.example.com');
    expect(parsed.proceedOnNetworkFail, isTrue);
    expect(copied.useApproovStatusIfNoToken, isTrue);
  });
}
