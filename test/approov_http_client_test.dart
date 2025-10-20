import 'dart:convert';
import 'dart:typed_data';

import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const MethodChannel channel = MethodChannel('approov_http_client');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {});

  test('signature base matches HTTP message signatures format', () {
    final bodyBytes = Uint8List.fromList(utf8.encode('{"hello":"world"}'));
    final headers = <String, List<String>>{
      'host': ['api.example.com'],
      'content-type': ['application/json'],
      'approov-token': ['Bearer token'],
    };
    final context = ApproovSigningContext(
      requestMethod: 'post',
      uri: Uri.parse('https://api.example.com/v1/resource?b=2&a=1&b=1'),
      headers: headers,
      bodyBytes: bodyBytes,
      tokenHeaderName: 'Approov-Token',
      onSetHeader: (name, value) => headers[name.toLowerCase()] = [value],
      onAddHeader: (name, value) => headers.putIfAbsent(name.toLowerCase(), () => <String>[]).add(value),
    );

    final factory = SignatureParametersFactory()
        .setBaseParameters(SignatureParameters()
          ..addComponentIdentifier('@method')
          ..addComponentIdentifier('@target-uri'))
        .setUseAccountMessageSigning()
        .setAddApproovTokenHeader(true)
        .addOptionalHeaders(const ['content-type'])
        .setBodyDigestConfig(SignatureDigest.sha256.identifier, required: false);

    final params = factory.build(context);
    final signatureBase = SignatureBaseBuilder(params, context).createSignatureBase();

    final digestHeader = 'sha-256=:${base64Encode(sha256.convert(bodyBytes).bytes)}:';
    expect(headers['content-digest'], [digestHeader]);
    final expectedString = [
      '"@method": POST',
      '"@target-uri": https://api.example.com/v1/resource?b=2&a=1&b=1',
      '"approov-token": Bearer token',
      '"content-type": application/json',
      '"content-digest": $digestHeader',
      '"@signature-params": ("@method" "@target-uri" "approov-token" "content-type" "content-digest");alg="hmac-sha256"'
    ].join('\n');

    expect(signatureBase, expectedString);
  });

  test('content-length header with zero body is not signed', () {
    final headers = <String, List<String>>{
      'content-length': ['0'],
      'approov-token': ['Bearer token'],
    };
    final context = ApproovSigningContext(
      requestMethod: 'get',
      uri: Uri.parse('https://api.example.com/v1/resource'),
      headers: headers,
      bodyBytes: Uint8List(0),
      tokenHeaderName: 'Approov-Token',
      onSetHeader: (name, value) => headers[name.toLowerCase()] = [value],
      onAddHeader: (name, value) => headers.putIfAbsent(name.toLowerCase(), () => <String>[]).add(value),
    );

    final factory = SignatureParametersFactory.generateDefaultFactory();
    final params = factory.build(context);

    final componentNames = params.componentIdentifiers.map((item) => item.value).toList();
    expect(componentNames.contains('content-length'), isFalse);
    expect(params.serializeComponentValue().contains('"content-length"'), isFalse);
  });
}
