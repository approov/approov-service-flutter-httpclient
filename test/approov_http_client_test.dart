import 'dart:convert';

import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const MethodChannel fgChannel =
      MethodChannel('approov_service_flutter_httpclient_fg');
  late Future<dynamic> Function(MethodCall call) channelHandler;

  setUp(() {
    channelHandler = (MethodCall methodCall) async => '42';
    fgChannel.setMockMethodCallHandler(
      (MethodCall call) => channelHandler(call),
    );
  });

  tearDown(() {
    fgChannel.setMockMethodCallHandler(null);
    ApproovService.disableMessageSigning();
  });

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
      onAddHeader: (name, value) =>
          headers.putIfAbsent(name.toLowerCase(), () => <String>[]).add(value),
    );

    final factory = SignatureParametersFactory()
        .setBaseParameters(SignatureParameters()
          ..addComponentIdentifier('@method')
          ..addComponentIdentifier('@target-uri'))
        .setUseAccountMessageSigning()
        .setAddApproovTokenHeader(true)
        .addOptionalHeaders(const ['content-type']).setBodyDigestConfig(
            SignatureDigest.sha256.identifier,
            required: false);

    final params = factory.build(context);
    final signatureBase =
        SignatureBaseBuilder(params, context).createSignatureBase();

    final digestHeader =
        'sha-256=:${base64Encode(sha256.convert(bodyBytes).bytes)}:';
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
      onAddHeader: (name, value) =>
          headers.putIfAbsent(name.toLowerCase(), () => <String>[]).add(value),
    );

    final factory = SignatureParametersFactory.generateDefaultFactory();
    final params = factory.build(context);

    final componentNames = params.componentIdentifiers
        .map((item) => item.bareItem.value as String)
        .toList();
    expect(componentNames.contains('content-length'), isFalse);
    expect(
        params.serializeComponentValue().contains('"content-length"'), isFalse);
  });

  test('signature parameters serialize using structured fields', () {
    final params = SignatureParameters()
      ..addComponentIdentifier('@method')
      ..addComponentIdentifier('content-type', parameters: {'charset': 'utf-8'})
      ..setAlg('hmac-sha256')
      ..setNonce('nonce123')
      ..setTag('tagged');

    // Duplicate component with identical parameters should be ignored.
    params.addComponentIdentifier('content-type',
        parameters: {'charset': 'utf-8'});
    expect(params.componentIdentifiers.length, 2);

    final serialized = params.serializeComponentValue();
    expect(
      serialized,
      '("@method" "content-type";charset="utf-8");alg="hmac-sha256";nonce="nonce123";tag="tagged"',
    );
  });

  test('signature base builder includes derived query-param component', () {
    final params = SignatureParameters()
      ..addComponentIdentifier('@method')
      ..addComponentIdentifier('@query-param', parameters: {'name': 'foo'})
      ..setAlg('ecdsa-p256-sha256');

    final context = ApproovSigningContext(
      requestMethod: 'get',
      uri: Uri.parse('https://api.example.com/search?foo=bar&baz=1'),
      headers: <String, List<String>>{},
      bodyBytes: null,
      tokenHeaderName: null,
      onSetHeader: (_, __) {},
      onAddHeader: (_, __) {},
    );

    final base = SignatureBaseBuilder(params, context).createSignatureBase();
    final expected = [
      '"@method": GET',
      '"@query-param";name="foo": bar',
      '"@signature-params": ("@method" "@query-param";name="foo");alg="ecdsa-p256-sha256"',
    ].join('\n');

    expect(base, expected);
  });

  test('enableMessageSigning configures default and host factories', () {
    final defaultFactory = SignatureParametersFactory()
        .setBaseParameters(
            SignatureParameters()..addComponentIdentifier('@method'))
        .setUseAccountMessageSigning();
    final hostFactory = SignatureParametersFactory()
        .setBaseParameters(
            SignatureParameters()..addComponentIdentifier('@path'))
        .setUseInstallMessageSigning();

    ApproovService.enableMessageSigning(
      defaultFactory: defaultFactory,
      hostFactories: {'api.example.com': hostFactory},
    );

    final messageSigning = ApproovService.messageSigningForTesting();
    expect(messageSigning, isNotNull);

    final defaultContext =
        _buildSigningContext(Uri.parse('https://example.org/resource'));
    final defaultParams =
        messageSigning!.buildParametersFor(defaultContext.uri, defaultContext);
    expect(defaultParams, isNotNull);
    final defaultComponents = defaultParams!.componentIdentifiers
        .map((item) => item.bareItem.value as String)
        .toList();
    expect(defaultComponents, contains('@method'));
    expect(defaultParams.algorithmIdentifier, 'hmac-sha256');

    final hostContext =
        _buildSigningContext(Uri.parse('https://api.example.com/resource'));
    final hostParams =
        messageSigning.buildParametersFor(hostContext.uri, hostContext);
    expect(hostParams, isNotNull);
    final hostComponents = hostParams!.componentIdentifiers
        .map((item) => item.bareItem.value as String)
        .toList();
    expect(hostComponents, contains('@path'));
    expect(hostParams.algorithmIdentifier, 'ecdsa-p256-sha256');
  });

  test('getAccountMessageSignature invokes account-specific channel', () async {
    final calls = <MethodCall>[];
    const message = 'payload';
    channelHandler = (MethodCall call) async {
      calls.add(call);
      switch (call.method) {
        case 'initialize':
        case 'setUserProperty':
          return null;
        case 'getAccountMessageSignature':
          expect(call.arguments, {'message': message});
          return 'account-signature';
        default:
          fail('Unexpected method ${call.method}');
      }
    };

    await ApproovService.initialize('test-config', 'reinit-account');
    final signature = await ApproovService.getAccountMessageSignature(message);

    expect(signature, 'account-signature');
    expect(
      calls.map((call) => call.method),
      ['initialize', 'setUserProperty', 'getAccountMessageSignature'],
    );
  });

  test('getAccountMessageSignature falls back when channel missing', () async {
    final calls = <MethodCall>[];
    const message = 'payload';
    channelHandler = (MethodCall call) async {
      calls.add(call);
      switch (call.method) {
        case 'initialize':
        case 'setUserProperty':
          return null;
        case 'getAccountMessageSignature':
          throw MissingPluginException('getAccountMessageSignature');
        case 'getMessageSignature':
          expect(call.arguments, {'message': message});
          return 'legacy-signature';
        default:
          fail('Unexpected method ${call.method}');
      }
    };

    await ApproovService.initialize('test-config', 'reinit-fallback');
    final signature = await ApproovService.getAccountMessageSignature(message);

    expect(signature, 'legacy-signature');
    expect(
      calls.map((call) => call.method),
      [
        'initialize',
        'setUserProperty',
        'getAccountMessageSignature',
        'getMessageSignature'
      ],
    );
  });
}

ApproovSigningContext _buildSigningContext(Uri uri) {
  final headers = <String, List<String>>{
    'host': [uri.host],
  };
  return ApproovSigningContext(
    requestMethod: 'get',
    uri: uri,
    headers: headers,
    bodyBytes: null,
    tokenHeaderName: null,
    onSetHeader: (name, value) => headers[name.toLowerCase()] = [value],
    onAddHeader: (name, value) =>
        headers.putIfAbsent(name.toLowerCase(), () => <String>[]).add(value),
  );
}
