import 'dart:convert';
import 'dart:io';

import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';
// SfItem is internal to the package (not re-exported from the public library), so the signing
// component identifier is built from the source library directly, as structured_fields_test does.
import 'package:approov_service_flutter_httpclient/src/structured_fields.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const MethodChannel fgChannel =
      MethodChannel('approov_service_flutter_httpclient_fg');
  const MethodChannel bgChannel =
      MethodChannel('approov_service_flutter_httpclient_bg');
  late Future<dynamic> Function(MethodCall call) channelHandler;
  late Future<dynamic> Function(MethodCall call) bgChannelHandler;

  setUp(() {
    ApproovService.resetInitStateForTesting();
    channelHandler = (MethodCall methodCall) async => '42';
    bgChannelHandler = (MethodCall methodCall) async => null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      fgChannel,
      (MethodCall call) => channelHandler(call),
    );
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      bgChannel,
      (MethodCall call) => bgChannelHandler(call),
    );
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(fgChannel, null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(bgChannel, null);
    // state isolation is provided by resetInitStateForTesting() in setUp,
    // which restores every mutable runtime field
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
      ['setUserProperty', 'getAccountMessageSignature'],
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
      ['setUserProperty', 'getAccountMessageSignature', 'getMessageSignature'],
    );
  });

  test('service layer adds trace header by default when fetch result has one',
      () {
    final headers = <String, String>{};
    final mutations = ApproovRequestMutations();

    ApproovService.applyTokenFetchResultHeadersForTesting(
      headers,
      _successfulFetchResult(traceID: 'trace-id-123'),
      mutations,
    );

    expect(headers['Approov-Token'], 'trace-test-token');
    expect(headers['Approov-TraceID'], 'trace-id-123');
    expect(mutations.tokenHeaderKey, 'Approov-Token');
    expect(mutations.traceIDHeaderKey, 'Approov-TraceID');
  });

  test('service layer omits trace header when disabled', () {
    final headers = <String, String>{};
    final mutations = ApproovRequestMutations();
    ApproovService.setApproovTraceIDHeader(null);

    ApproovService.applyTokenFetchResultHeadersForTesting(
      headers,
      _successfulFetchResult(traceID: 'trace-id-123'),
      mutations,
    );

    expect(headers['Approov-Token'], 'trace-test-token');
    expect(headers.containsKey('Approov-TraceID'), isFalse);
    expect(mutations.tokenHeaderKey, 'Approov-Token');
    expect(mutations.traceIDHeaderKey, isNull);
  });

  test('null token prefix is treated as no prefix', () {
    final headers = <String, String>{};
    final mutations = ApproovRequestMutations();
    ApproovService.setApproovHeader('X-Approov-Token', null);

    ApproovService.applyTokenFetchResultHeadersForTesting(
      headers,
      _successfulFetchResult(traceID: ''),
      mutations,
    );

    expect(headers['X-Approov-Token'], 'trace-test-token');
    expect(headers['X-Approov-Token']!.startsWith('null'), false);
    expect(mutations.tokenHeaderKey, 'X-Approov-Token');
  });

  test('NO_APPROOV_SERVICE omits the token header when the fallback is off',
      () async {
    // TESTING_REQUIREMENTS §2 "Missing Artifacts Fallback": empty token values must be omitted,
    // never sent as an empty-valued header. Status evidence belongs behind
    // setUseApproovStatusIfNoToken(true) instead.
    final headers = <String, String>{};
    final mutations = ApproovRequestMutations();
    ApproovService.setApproovHeader('Approov-Token', null);
    expect(ApproovService.getUseApproovStatusIfNoToken(), isFalse);

    ApproovService.applyTokenFetchResultHeadersForTesting(
      headers,
      _noApproovServiceFetchResult(),
      mutations,
    );

    expect(headers.containsKey('Approov-Token'), isFalse);
    expect(mutations.tokenHeaderKey, isNull);
  });

  test('NO_APPROOV_SERVICE never emits a prefix-only token header', () async {
    // with a prefix configured and the fallback off, the header must still be absent rather than
    // carrying a bare "Bearer " value.
    final headers = <String, String>{};
    final mutations = ApproovRequestMutations();
    ApproovService.setApproovHeader('Approov-Token', 'Bearer ');

    ApproovService.applyTokenFetchResultHeadersForTesting(
      headers,
      _noApproovServiceFetchResult(),
      mutations,
    );

    expect(headers.containsKey('Approov-Token'), isFalse);
    expect(mutations.tokenHeaderKey, isNull);
  });

  test('NO_APPROOV_SERVICE carries the status when the fallback is enabled', () async {
    final headers = <String, String>{};
    final mutations = ApproovRequestMutations();
    ApproovService.setApproovHeader('Approov-Token', 'Bearer ');
    ApproovService.setUseApproovStatusIfNoToken(true);
    addTearDown(() => ApproovService.setUseApproovStatusIfNoToken(false));

    ApproovService.applyTokenFetchResultHeadersForTesting(
      headers,
      _noApproovServiceFetchResult(),
      mutations,
    );

    expect(headers['Approov-Token'], 'Bearer NO_APPROOV_SERVICE');
    expect(mutations.tokenHeaderKey, 'Approov-Token');
    // the trace ID is an artifact in its own right: there is none for this
    // status, so its header stays absent whatever the fallback setting
    expect(headers.containsKey('Approov-TraceID'), isFalse);
    expect(mutations.traceIDHeaderKey, isNull);
  });

  test('MITM_DETECTED injects the status only when a mutator allows it',
      () async {
    // The default mutator throws for MITM_DETECTED, so this header value is only
    // ever reachable through a custom mutator that deliberately returns true.
    // The injection path itself must remain intact for that case.
    final headers = <String, String>{};
    final mutations = ApproovRequestMutations();
    ApproovService.setApproovHeader('Approov-Token', null);

    ApproovService.applyTokenFetchResultHeadersForTesting(
      headers,
      _mitmDetectedFetchResult(),
      mutations,
    );
    expect(headers.containsKey('Approov-Token'), isFalse,
        reason: 'with the fallback off no header is emitted at all');

    ApproovService.setUseApproovStatusIfNoToken(true);
    addTearDown(() => ApproovService.setUseApproovStatusIfNoToken(false));
    ApproovService.applyTokenFetchResultHeadersForTesting(
      headers,
      _mitmDetectedFetchResult(),
      mutations,
    );
    expect(headers['Approov-Token'], 'MITM_DETECTED');
  });

  test('message signing SDK failures proceed unsigned', () async {
    final calls = <MethodCall>[];
    final observedHeaders = <String, List<String>>{};

    bgChannelHandler = (MethodCall call) async {
      calls.add(call);
      return null;
    };
    channelHandler = (MethodCall call) async {
      calls.add(call);
      switch (call.method) {
        case 'setUserProperty':
          return null;
        case 'fetchApproovToken':
          final args = call.arguments as Map;
          await TestDefaultBinaryMessengerBinding
              .instance.defaultBinaryMessenger
              .handlePlatformMessage(
            fgChannel.name,
            fgChannel.codec.encodeMethodCall(MethodCall('response', {
              'TransactionID': args['transactionID'],
              'TokenFetchStatus': 'SUCCESS',
              'Token': 'approov-token',
              'ARC': 'ARC',
              'RejectionReasons': '',
              'IsConfigChanged': false,
              'IsForceApplyPins': false,
              'MeasurementConfig': Uint8List(0),
              'LoggableToken': 'loggable-token',
              'TraceID': 'trace-id',
              'ConfigEpoch': 0,
            })),
            null,
          );
          return null;
        case 'getAccountMessageSignature':
          throw PlatformException(
              code: 'Approov.sign', message: 'account key unavailable');
        default:
          fail('Unexpected method ${call.method}');
      }
    };

    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final serverSubscription = server.listen((request) async {
      request.headers.forEach((name, values) {
        observedHeaders[name.toLowerCase()] = values;
      });
      request.response.statusCode = 200;
      request.response.write('ok');
      await request.response.close();
    });
    addTearDown(() async {
      await serverSubscription.cancel();
      await server.close(force: true);
    });

    await ApproovService.initialize('test-config', 'reinit-signing-fail-open');
    ApproovService.setServiceMutator(_SkipPinningMutator());
    ApproovService.enableMessageSigning(
      defaultFactory: SignatureParametersFactory()
          .setBaseParameters(
              SignatureParameters()..addComponentIdentifier('@method'))
          .setUseAccountMessageSigning(),
    );

    final previousHttpOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = previousHttpOverrides);

    final client = ApproovClient();
    addTearDown(client.close);

    final response =
        await client.get(Uri.parse('http://127.0.0.1:${server.port}/signed'));

    expect(response.statusCode, 200);
    expect(response.body, 'ok');
    expect(observedHeaders['approov-token'], ['approov-token']);
    expect(observedHeaders.containsKey('signature'), false);
    expect(observedHeaders.containsKey('signature-input'), false);
    expect(calls.map((call) => call.method),
        containsAll(['fetchApproovToken', 'getAccountMessageSignature']));
  });

  test('install message signing SDK failures proceed unsigned', () async {
    final observedHeaders = <String, List<String>>{};
    channelHandler = (MethodCall call) async {
      switch (call.method) {
        case 'setUserProperty':
          return null;
        case 'fetchApproovToken':
          final args = call.arguments as Map;
          await TestDefaultBinaryMessengerBinding
              .instance.defaultBinaryMessenger
              .handlePlatformMessage(
            fgChannel.name,
            fgChannel.codec.encodeMethodCall(MethodCall('response', {
              'TransactionID': args['transactionID'],
              'TokenFetchStatus': 'SUCCESS',
              'Token': 'approov-token',
              'ARC': 'ARC',
              'RejectionReasons': '',
              'IsConfigChanged': false,
              'IsForceApplyPins': false,
              'MeasurementConfig': Uint8List(0),
              'LoggableToken': 'loggable-token',
              'TraceID': 'trace-id',
              'ConfigEpoch': 0,
            })),
            null,
          );
          return null;
        case 'getInstallMessageSignature':
          throw PlatformException(
              code: 'Approov.sign', message: 'install key unavailable');
        default:
          fail('Unexpected method ${call.method}');
      }
    };
    bgChannelHandler = (MethodCall call) async => null;

    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final serverSubscription = server.listen((request) async {
      request.headers.forEach((name, values) {
        observedHeaders[name.toLowerCase()] = values;
      });
      request.response.statusCode = 200;
      request.response.write('ok');
      await request.response.close();
    });
    addTearDown(() async {
      await serverSubscription.cancel();
      await server.close(force: true);
    });

    await ApproovService.initialize('test-config', 'reinit-install-fail-open');
    ApproovService.setServiceMutator(_SkipPinningMutator());
    ApproovService.enableMessageSigning(
      defaultFactory: SignatureParametersFactory()
          .setBaseParameters(
              SignatureParameters()..addComponentIdentifier('@method'))
          .setUseInstallMessageSigning(),
    );

    final previousHttpOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = previousHttpOverrides);

    final client = ApproovClient();
    addTearDown(client.close);

    final response =
        await client.get(Uri.parse('http://127.0.0.1:${server.port}/signed'));

    expect(response.statusCode, 200);
    expect(observedHeaders['approov-token'], ['approov-token']);
    expect(observedHeaders.containsKey('signature'), false,
        reason: 'install signature failure must proceed unsigned, not abort');
  });

  test('required body digest failure aborts the request (fail-closed)',
      () async {
    var serverSawRequest = false;
    channelHandler = (MethodCall call) async {
      switch (call.method) {
        case 'setUserProperty':
          return null;
        case 'fetchApproovToken':
          final args = call.arguments as Map;
          await TestDefaultBinaryMessengerBinding
              .instance.defaultBinaryMessenger
              .handlePlatformMessage(
            fgChannel.name,
            fgChannel.codec.encodeMethodCall(MethodCall('response', {
              'TransactionID': args['transactionID'],
              'TokenFetchStatus': 'SUCCESS',
              'Token': 'approov-token',
              'ARC': 'ARC',
              'RejectionReasons': '',
              'IsConfigChanged': false,
              'IsForceApplyPins': false,
              'MeasurementConfig': Uint8List(0),
              'LoggableToken': 'loggable-token',
              'TraceID': 'trace-id',
              'ConfigEpoch': 0,
            })),
            null,
          );
          return null;
        default:
          return null;
      }
    };
    bgChannelHandler = (MethodCall call) async => null;

    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final serverSubscription = server.listen((request) async {
      serverSawRequest = true;
      request.response.statusCode = 200;
      await request.response.close();
    });
    addTearDown(() async {
      await serverSubscription.cancel();
      await server.close(force: true);
    });

    await ApproovService.initialize('test-config', 'reinit-digest-required');
    ApproovService.setServiceMutator(_SkipPinningMutator());
    // A GET has no body, so a REQUIRED body digest cannot be generated. This
    // is one of the two deliberate fail-closed signing conditions
    // (TESTING_REQUIREMENTS.md section 5): the request must abort, not go out
    // unsigned.
    ApproovService.enableMessageSigning(
      defaultFactory: SignatureParametersFactory()
          .setBaseParameters(
              SignatureParameters()..addComponentIdentifier('@method'))
          .setUseAccountMessageSigning()
          .setBodyDigestConfig(SignatureDigest.sha256.identifier,
              required: true),
    );

    final previousHttpOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = previousHttpOverrides);

    final client = ApproovClient();
    addTearDown(client.close);

    await expectLater(
      client.get(Uri.parse('http://127.0.0.1:${server.port}/signed')),
      throwsA(anyOf(isA<ApproovException>(), isA<Exception>())),
    );
    expect(serverSawRequest, false,
        reason: 'a fail-closed signing error must abort before the request '
            'reaches the network');
  });

  test('unsupported signing algorithm aborts the request (fail-closed)',
      () async {
    var serverSawRequest = false;
    channelHandler = (MethodCall call) async {
      switch (call.method) {
        case 'setUserProperty':
          return null;
        case 'fetchApproovToken':
          final args = call.arguments as Map;
          await TestDefaultBinaryMessengerBinding
              .instance.defaultBinaryMessenger
              .handlePlatformMessage(
            fgChannel.name,
            fgChannel.codec.encodeMethodCall(MethodCall('response', {
              'TransactionID': args['transactionID'],
              'TokenFetchStatus': 'SUCCESS',
              'Token': 'approov-token',
              'ARC': 'ARC',
              'RejectionReasons': '',
              'IsConfigChanged': false,
              'IsForceApplyPins': false,
              'MeasurementConfig': Uint8List(0),
              'LoggableToken': 'loggable-token',
              'TraceID': 'trace-id',
              'ConfigEpoch': 0,
            })),
            null,
          );
          return null;
        default:
          return null;
      }
    };
    bgChannelHandler = (MethodCall call) async => null;

    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final serverSubscription = server.listen((request) async {
      serverSawRequest = true;
      request.response.statusCode = 200;
      await request.response.close();
    });
    addTearDown(() async {
      await serverSubscription.cancel();
      await server.close(force: true);
    });

    await ApproovService.initialize('test-config', 'reinit-bad-alg');
    ApproovService.setServiceMutator(_SkipPinningMutator());
    // The second deliberate fail-closed signing condition: a misconfigured
    // (unsupported) algorithm must abort rather than silently disable signing.
    ApproovService.enableMessageSigning(
        defaultFactory: _UnsupportedAlgFactory());

    final previousHttpOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = previousHttpOverrides);

    final client = ApproovClient();
    addTearDown(client.close);

    await expectLater(
      client.get(Uri.parse('http://127.0.0.1:${server.port}/signed')),
      throwsA(anyOf(isA<ApproovException>(), isA<Exception>())),
    );
    expect(serverSawRequest, false,
        reason: 'an unsupported signing algorithm must abort before the '
            'request reaches the network');
  });

  test('missing signing algorithm aborts the request (fail-closed)',
      () async {
    var serverSawRequest = false;
    channelHandler = (MethodCall call) async {
      switch (call.method) {
        case 'setUserProperty':
          return null;
        case 'fetchApproovToken':
          final args = call.arguments as Map;
          await TestDefaultBinaryMessengerBinding
              .instance.defaultBinaryMessenger
              .handlePlatformMessage(
            fgChannel.name,
            fgChannel.codec.encodeMethodCall(MethodCall('response', {
              'TransactionID': args['transactionID'],
              'TokenFetchStatus': 'SUCCESS',
              'Token': 'approov-token',
              'ARC': 'ARC',
              'RejectionReasons': '',
              'IsConfigChanged': false,
              'IsForceApplyPins': false,
              'MeasurementConfig': Uint8List(0),
              'LoggableToken': 'loggable-token',
              'TraceID': 'trace-id',
              'ConfigEpoch': 0,
            })),
            null,
          );
          return null;
        default:
          return null;
      }
    };
    bgChannelHandler = (MethodCall call) async => null;

    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final serverSubscription = server.listen((request) async {
      serverSawRequest = true;
      request.response.statusCode = 200;
      await request.response.close();
    });
    addTearDown(() async {
      await serverSubscription.cancel();
      await server.close(force: true);
    });

    await ApproovService.initialize('test-config', 'reinit-missing-alg');
    ApproovService.setServiceMutator(_SkipPinningMutator());
    // Parameters carrying no algorithm identifier at all must fail closed too, not
    // fall back to a default or silently proceed unsigned.
    ApproovService.enableMessageSigning(
        defaultFactory: _MissingAlgFactory());

    final previousHttpOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = previousHttpOverrides);

    final client = ApproovClient();
    addTearDown(client.close);

    await expectLater(
      client.get(Uri.parse('http://127.0.0.1:${server.port}/signed')),
      throwsA(anyOf(isA<ApproovException>(), isA<Exception>())),
    );
    expect(serverSawRequest, false,
        reason: 'a missing signing algorithm must abort before the '
            'request reaches the network');
  });

  test('multi-value header adds are preserved in the signed message', () async {
    // Regression test for staged header application: a factory that calls
    // onAddHeader twice for the same name previously collapsed to the last
    // value, so the signature covered a message the server could never
    // reconstruct. Both values must survive into the signing context.
    final uri = Uri.parse('https://example.com/multi');
    final context = _buildSigningContext(uri);

    context.addHeader('X-Multi', 'first');
    context.addHeader('X-Multi', 'second');

    expect(context.getComponentValue(SfItem.string('x-multi')), 'first, second',
        reason: 'both added values must appear in the signature base, in the '
            'order the factory added them');
  });

  test('token binding hash is set (and awaited) before the token fetch',
      () async {
    final sequence = <String>[];
    channelHandler = (MethodCall call) async {
      switch (call.method) {
        case 'setUserProperty':
          return null;
        case 'setDataHashInToken':
          // delay so a fire-and-forget caller would demonstrably race ahead:
          // only an awaited call keeps the fetch from starting first
          await Future<void>.delayed(const Duration(milliseconds: 30));
          sequence.add('setDataHashInToken-complete');
          return null;
        case 'fetchApproovToken':
          sequence.add('fetchApproovToken-start');
          final args = call.arguments as Map;
          await TestDefaultBinaryMessengerBinding
              .instance.defaultBinaryMessenger
              .handlePlatformMessage(
            fgChannel.name,
            fgChannel.codec.encodeMethodCall(MethodCall('response', {
              'TransactionID': args['transactionID'],
              'TokenFetchStatus': 'SUCCESS',
              'Token': 'approov-token',
              'ARC': 'ARC',
              'RejectionReasons': '',
              'IsConfigChanged': false,
              'IsForceApplyPins': false,
              'MeasurementConfig': Uint8List(0),
              'LoggableToken': 'loggable-token',
              'TraceID': 'trace-id',
              'ConfigEpoch': 0,
            })),
            null,
          );
          return null;
        default:
          return null;
      }
    };
    bgChannelHandler = (MethodCall call) async => null;

    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final serverSubscription = server.listen((request) async {
      request.response.statusCode = 200;
      request.response.write('ok');
      await request.response.close();
    });
    addTearDown(() async {
      await serverSubscription.cancel();
      await server.close(force: true);
    });

    await ApproovService.initialize('test-config', 'reinit-binding');
    ApproovService.setServiceMutator(_SkipPinningMutator());
    ApproovService.setBindingHeader('Authorization');

    final previousHttpOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = previousHttpOverrides);

    final client = ApproovClient();
    addTearDown(client.close);

    final response = await client.get(
      Uri.parse('http://127.0.0.1:${server.port}/bound'),
      headers: {'Authorization': 'Bearer user-token'},
    );

    expect(response.statusCode, 200);
    expect(
        sequence, ['setDataHashInToken-complete', 'fetchApproovToken-start'],
        reason: 'the binding hash must reach native (awaited) before the '
            'token fetch starts, or the pay claim can be missing from the '
            'issued token (TESTING_REQUIREMENTS.md section 2, Token Binding)');
  });
}

/// Factory producing parameters with an algorithm the service does not
/// support - used to prove the fail-closed path for misconfigured algorithms.
/// Produces parameters with no algorithm identifier at all. Distinct from
/// [_UnsupportedAlgFactory]: that one names an algorithm the layer does not
/// implement, this one names none, and both must fail closed.
class _MissingAlgFactory extends SignatureParametersFactory {
  @override
  SignatureParameters build(ApproovSigningContext context) {
    return SignatureParameters()..addComponentIdentifier('@method');
  }
}

class _UnsupportedAlgFactory extends SignatureParametersFactory {
  @override
  SignatureParameters build(ApproovSigningContext context) {
    return SignatureParameters()
      ..addComponentIdentifier('@method')
      ..setAlg('rsa-pss-sha512');
  }
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

ApproovTokenFetchResult _successfulFetchResult({required String traceID}) {
  return ApproovTokenFetchResult(
    tokenFetchStatus: ApproovTokenFetchStatus.SUCCESS,
    token: 'trace-test-token',
    secureString: null,
    arc: 'ARC',
    rejectionReasons: '',
    isConfigChanged: false,
    isForceApplyPins: false,
    measurementConfig: Uint8List(0),
    loggableToken: 'trace-loggable',
    traceID: traceID,
    requestURL: 'https://api.example.com',
    proceedOnNetworkFail: false,
    useApproovStatusIfNoToken: false,
  );
}

ApproovTokenFetchResult _mitmDetectedFetchResult() {
  return ApproovTokenFetchResult(
    tokenFetchStatus: ApproovTokenFetchStatus.MITM_DETECTED,
    token: '',
    secureString: null,
    arc: '',
    rejectionReasons: '',
    isConfigChanged: false,
    isForceApplyPins: false,
    measurementConfig: Uint8List(0),
    loggableToken: '',
    traceID: '',
    requestURL: 'https://api.example.com',
    // ignore: deprecated_member_use_from_same_package
    proceedOnNetworkFail: false,
    useApproovStatusIfNoToken: false,
  );
}

ApproovTokenFetchResult _noApproovServiceFetchResult() {
  return ApproovTokenFetchResult(
    tokenFetchStatus: ApproovTokenFetchStatus.NO_APPROOV_SERVICE,
    token: '',
    secureString: null,
    arc: '',
    rejectionReasons: '',
    isConfigChanged: false,
    isForceApplyPins: false,
    measurementConfig: Uint8List(0),
    loggableToken: '',
    traceID: '',
    requestURL: 'https://api.example.com',
    // ignore: deprecated_member_use_from_same_package
    proceedOnNetworkFail: false,
    useApproovStatusIfNoToken: false,
  );
}

class _SkipPinningMutator extends ApproovServiceMutator {
  @override
  bool handlePinningShouldProcessRequest(ApproovRequestSnapshot request) {
    return false;
  }
}
