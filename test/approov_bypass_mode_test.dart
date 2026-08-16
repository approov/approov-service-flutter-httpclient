import 'dart:async';
import 'dart:io';

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
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(fgChannel, null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(bgChannel, null);
  });

  test('empty config after a valid config is ignored, not thrown', () async {
    final bgCalls = <MethodCall>[];
    bgHandler = (call) async {
      bgCalls.add(call);
      return null;
    };

    await ApproovService.initialize('real-config', 'reinit-a');
    // No throw expected here - this is the bug being fixed.
    await ApproovService.initialize('');

    expect(
      bgCalls.map((c) => c.method).where((m) => m == 'initialize').length,
      1,
      reason: 'the empty-config call must not reach native at all once a valid '
          'config is active',
    );
  });

  test('valid config after an empty config is allowed (upgrade)', () async {
    final bgCalls = <MethodCall>[];
    bgHandler = (call) async {
      bgCalls.add(call);
      return null;
    };

    await ApproovService.initialize('', 'reinit-b');
    // No throw expected here either - this is the other half of the bug.
    await ApproovService.initialize('real-config-2');

    expect(
      bgCalls.where((c) => c.method == 'initialize').map((c) => c.arguments),
      [
        {'initialConfig': '', 'updateConfig': 'auto', 'comment': 'reinit-b'},
        {
          'initialConfig': 'real-config-2',
          'updateConfig': 'auto',
          'comment': null
        },
      ],
    );
  });

  test('initialize awaits and surfaces current native initialization failure',
      () async {
    final fgCalls = <MethodCall>[];
    final bgCalls = <MethodCall>[];
    fgHandler = (call) async {
      fgCalls.add(call);
      return null;
    };
    bgHandler = (call) async {
      bgCalls.add(call);
      if (call.method == 'initialize') {
        throw PlatformException(
            code: 'Approov.initialize', message: 'bad config');
      }
      return null;
    };

    await expectLater(
      ApproovService.initialize('bad-config'),
      throwsA(isA<ApproovException>()
          .having((e) => e.cause ?? '', 'cause', contains('bad config'))),
    );
    expect(bgCalls.map((c) => c.method), ['initialize']);
    expect(fgCalls, isEmpty,
        reason: 'setUserProperty must not run after failed native init');
  });

  test('same non-empty config is forwarded to native on reinitialization',
      () async {
    final bgCalls = <MethodCall>[];
    bgHandler = (call) async {
      bgCalls.add(call);
      return null;
    };

    await ApproovService.initialize('real-config', null);
    bgCalls.clear();

    await ApproovService.initialize('real-config', null);

    expect(
      bgCalls.where((c) => c.method == 'initialize').map((c) => c.arguments),
      [
        {
          'initialConfig': 'real-config',
          'updateConfig': 'auto',
          'comment': null
        }
      ],
      reason: 'same-config reinitialization must still reach native so the SDK '
          'can return its already-initialized result',
    );
  });

  test('different non-empty native failure preserves protected mode', () async {
    final fgCalls = <MethodCall>[];
    final bgCalls = <MethodCall>[];
    fgHandler = (call) async {
      fgCalls.add(call);
      if (call.method == 'getDeviceID') return 'protected-device';
      return null;
    };
    bgHandler = (call) async {
      bgCalls.add(call);
      if (call.method == 'initialize' &&
          call.arguments['initialConfig'] == 'different-config') {
        throw PlatformException(
            code: 'Approov.initialize', message: 'different config');
      }
      return null;
    };

    await ApproovService.initialize('real-config', 'reinit-protected');
    await expectLater(
      ApproovService.initialize('different-config', 'reinit-different'),
      throwsA(isA<ApproovException>()
          .having((e) => e.cause ?? '', 'cause', contains('different config'))),
    );
    fgCalls.clear();

    expect(await ApproovService.getDeviceID(), 'protected-device');
    expect(fgCalls.map((c) => c.method), contains('getDeviceID'),
        reason: 'a failed different-config init must not poison the previous '
            'successful protected initialization future');
  });

  test('failed protected upgrade after bypass leaves bypass mode usable',
      () async {
    bgHandler = (call) async {
      if (call.method == 'initialize' &&
          call.arguments['initialConfig'] == 'bad-real-config') {
        throw PlatformException(
            code: 'Approov.initialize', message: 'bad real config');
      }
      return null;
    };

    await ApproovService.initialize('', 'reinit-empty-first');
    await expectLater(
      ApproovService.initialize('bad-real-config', 'reinit-upgrade'),
      throwsA(isA<ApproovException>()
          .having((e) => e.cause ?? '', 'cause', contains('bad real config'))),
    );

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://example.com/'));

    expect(preparation.shouldProcessApproov, false);
    expect(preparation.shouldApplyPinning, false,
        reason: 'the service must remain initialized in bypass mode after a '
            'failed upgrade attempt');
  });

  test(
      'empty config in a fresh isolate adopts protected mode when native is '
      'already protected', () async {
    // Simulates a background isolate (fresh Dart statics via the setUp reset)
    // whose process-wide native layer was already initialized with a valid
    // config by the root isolate. Native ignores the empty config and stays
    // protected; the Dart layer must NOT commit bypass mode for this isolate,
    // otherwise its requests silently skip pinning and tokens while
    // isApproovEnabled() reports true (TESTING_REQUIREMENTS.md section 1,
    // "Empty Configuration after Valid Configuration").
    fgHandler = (call) async {
      if (call.method == 'isApproovEnabled') return true;
      return null;
    };

    await ApproovService.initialize('');

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://example.com/'));
    expect(preparation.shouldProcessApproov, true,
        reason: 'the isolate must follow the protected native state, not '
            'downgrade itself to bypass mode');
  });

  test('empty config still enters bypass mode when native is unprotected',
      () async {
    fgHandler = (call) async {
      if (call.method == 'isApproovEnabled') return false;
      return null;
    };

    await ApproovService.initialize('');

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://example.com/'));
    expect(preparation.shouldProcessApproov, false);
  });

  test(
      'overlapping failed re-initializations cannot poison a healthy '
      'protected service', () async {
    bgHandler = (call) async {
      if (call.method == 'initialize' &&
          call.arguments['initialConfig'] == 'bad-config') {
        // keep the failing attempts in flight long enough to overlap
        await Future<void>.delayed(const Duration(milliseconds: 20));
        throw PlatformException(code: 'Approov.initialize', message: 'bad');
      }
      return null;
    };
    fgHandler = (call) async {
      if (call.method == 'getDeviceID') return 'healthy-device';
      return null;
    };

    await ApproovService.initialize('good-config');

    // Two overlapping retries of a bad config: the second captures the first
    // (doomed) attempt as its predecessor. The failure-restore logic must
    // never reinstall a captured earlier future - only a freshly resolved one
    // - or the service ends up with _isInitialized true but every
    // _requireInitialized() rethrowing a stale error while native is healthy.
    final first = ApproovService.initialize('bad-config');
    final second = ApproovService.initialize('bad-config');
    await expectLater(first, throwsA(isA<ApproovException>()));
    await expectLater(second, throwsA(isA<ApproovException>()));

    expect(await ApproovService.getDeviceID(), 'healthy-device',
        reason: 'the surviving successful initialization must remain usable '
            'after overlapping failed retries');
  });

  test('setUserProperty failure does not fail an initialized service',
      () async {
    // Native init succeeds and commits process-wide state; the follow-up
    // telemetry call fails. Failing initialize() at that point would leave
    // Dart in bypass while native is protected - requests would then skip
    // pinning and tokens with isApproovEnabled() still true. The property
    // call is best-effort (matches approov-service-okhttp, which commits
    // service-layer state before setting the user property).
    fgHandler = (call) async {
      if (call.method == 'setUserProperty') {
        throw PlatformException(code: 'setUserProperty', message: 'detached');
      }
      if (call.method == 'getDeviceID') return 'device-after-telemetry-fail';
      return null;
    };

    await ApproovService.initialize('real-config-telemetry');

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://example.com/'));
    expect(preparation.shouldProcessApproov, true);
    expect(await ApproovService.getDeviceID(), 'device-after-telemetry-fail');
  });

  test('successful initialization resets runtime service-layer state',
      () async {
    final mutator = _AlwaysAllowMutator();
    ApproovService.setServiceMutator(mutator);
    ApproovService.setApproovHeader('Custom-Approov', 'Bearer ');
    ApproovService.setApproovTraceIDHeader(null);
    ApproovService.setUseApproovStatusIfNoToken(true);
    ApproovService.setProceedOnNetworkFail(true);
    ApproovService.setBindingHeader('Authorization');
    ApproovService.addSubstitutionHeader('X-Secret', null);
    ApproovService.addSubstitutionQueryParam('apiKey');
    ApproovService.addExclusionURLRegex('.*excluded.*');
    ApproovService.enableMessageSigning();

    await ApproovService.initialize('real-config-reset', 'reinit-reset');

    expect(ApproovService.getServiceMutator(),
        same(ApproovServiceMutator.DEFAULT));
    expect(ApproovService.getApproovTraceIDHeader(), 'Approov-TraceID');
    expect(ApproovService.getUseApproovStatusIfNoToken(), false);
    expect(ApproovService.messageSigningForTesting(), isNull);

    // Every mutable runtime field must be back at its default - asserting the
    // full snapshot (not just the fields with getters) so that dropping any
    // line from _resetServiceStateAfterSuccessfulInitialization fails a test.
    expect(ApproovService.runtimeStateForTesting(), <String, Object?>{
      'approovTokenHeader': 'Approov-Token',
      'approovTraceIDHeader': 'Approov-TraceID',
      'approovTokenPrefix': '',
      'proceedOnNetworkFail': false,
      'useApproovStatusIfNoToken': false,
      'bindingHeader': null,
      'substitutionHeaders': <String, String>{},
      'substitutionQueryParams': <String>{},
      'exclusionURLRegexs': <String>{},
      'hostCertificateHosts': <String>{},
    });

    final headers = <String, String>{};
    ApproovService.applyTokenFetchResultHeadersForTesting(
      headers,
      ApproovTokenFetchResult(
        tokenFetchStatus: ApproovTokenFetchStatus.SUCCESS,
        token: 'token',
        secureString: null,
        arc: '',
        rejectionReasons: '',
        isConfigChanged: false,
        isForceApplyPins: false,
        measurementConfig: Uint8List(0),
        loggableToken: '',
        traceID: 'trace',
        requestURL: 'https://example.com',
        proceedOnNetworkFail: false,
        useApproovStatusIfNoToken: false,
      ),
      ApproovRequestMutations(),
    );
    expect(headers['Approov-Token'], 'token',
        reason: 'token header name and prefix should reset to defaults');
    expect(headers.containsKey('Custom-Approov'), false);
  });

  test('state queries fall back to the background channel', () async {
    // A background isolate cannot reach the foreground channel. Before the
    // fallback existed, that surfaced as "not initialized" - and on the
    // empty-config path the Dart layer read it as "native unprotected" and
    // committed real bypass mode, dropping tokens and pinning for that
    // isolate. Both queries must therefore be answerable over the background
    // channel, which the same native handler serves.
    fgHandler = (call) async => throw MissingPluginException(
        'foreground channel unavailable in this isolate');
    bgHandler = (call) async {
      switch (call.method) {
        case 'isInitialized':
          return true;
        case 'isApproovEnabled':
          return true;
        default:
          return null;
      }
    };

    expect(await ApproovService.isInitialized(), true,
        reason: 'the background channel must answer when the foreground '
            'channel cannot');
    expect(await ApproovService.isApproovEnabled(), true);
  });

  test('isInitialized and isApproovEnabled reflect bypass mode', () async {
    fgHandler = (call) async {
      switch (call.method) {
        case 'isInitialized':
          return true;
        case 'isApproovEnabled':
          return false;
        default:
          return null;
      }
    };

    await ApproovService.initialize('', 'reinit-c');

    expect(await ApproovService.isInitialized(), true);
    expect(await ApproovService.isApproovEnabled(), false);
  });

  test('isInitialized and isApproovEnabled reflect protected mode', () async {
    fgHandler = (call) async {
      switch (call.method) {
        case 'isInitialized':
          return true;
        case 'isApproovEnabled':
          return true;
        default:
          return null;
      }
    };

    await ApproovService.initialize('real-config-3', 'reinit-d');

    expect(await ApproovService.isInitialized(), true);
    expect(await ApproovService.isApproovEnabled(), true);
  });

  test('query methods consult native even when this isolate never initialized',
      () async {
    // Simulates a background isolate: the process-wide native SDK is already
    // initialized (from another isolate), but this isolate never called
    // initialize(), so _futureInitialization is null. The query methods must
    // still report the native truth rather than short-circuiting to false.
    final fgCalls = <String>[];
    fgHandler = (call) async {
      fgCalls.add(call.method);
      switch (call.method) {
        case 'isInitialized':
          return true;
        case 'isApproovEnabled':
          return true;
        default:
          return null;
      }
    };

    // Note: no ApproovService.initialize(...) call here.
    expect(await ApproovService.isInitialized(), true);
    expect(await ApproovService.isApproovEnabled(), true);
    expect(fgCalls, containsAll(<String>['isInitialized', 'isApproovEnabled']),
        reason: 'both queries must reach the native layer, not return false '
            'early on a null local initialization future');
  });

  test('bypass mode short-circuits before the mutator is ever consulted',
      () async {
    // This mutator always answers "true" for both gates. If the production
    // code called it and then (incorrectly) overrode the result afterwards,
    // shouldProcessApproov/shouldApplyPinning would still read false here -
    // so the flags alone cannot distinguish "never asked" from "asked, then
    // overridden". The *Consulted flags are what actually prove the mutator
    // was skipped entirely.
    await ApproovService.initialize('', 'reinit-e');
    final mutator = _AlwaysAllowMutator();
    ApproovService.setServiceMutator(mutator);
    addTearDown(() => ApproovService.setServiceMutator(null));

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://example.com/'));

    expect(preparation.shouldProcessApproov, false,
        reason: 'bypass mode must never process Approov for a real request');
    expect(preparation.shouldApplyPinning, false,
        reason: 'bypass mode must never apply pinning for a real request');
    expect(preparation.uri, Uri.parse('https://example.com/'),
        reason: 'the URI must be returned unchanged in bypass mode');
    expect(
      mutator.interceptorConsulted,
      false,
      reason: 'handleInterceptorShouldProcessRequest must never be invoked '
          'in bypass mode - this mutator would answer true if asked, so a '
          'false result on its own would not prove the mutator was really '
          'skipped rather than asked-and-overridden',
    );
    expect(
      mutator.pinningConsulted,
      false,
      reason: 'handlePinningShouldProcessRequest must never be invoked in '
          'bypass mode, for the same reason as above',
    );
  });

  test(
      'protected mode still consults the mutator for the processing/pinning gates',
      () async {
    // Sanity check for the guard added above: a real configuration must
    // still route through the mutator as before, so the bypass-mode check
    // is not accidentally short-circuiting (or inverted to always
    // short-circuit) regardless of configuration.
    await ApproovService.initialize('real-config-4', 'reinit-f');
    final mutator = _AlwaysAllowMutator();
    ApproovService.setServiceMutator(mutator);
    addTearDown(() => ApproovService.setServiceMutator(null));

    final preparation = await ApproovService.prepareRequestForApproovForTesting(
        'GET', Uri.parse('https://example.com/'));

    expect(preparation.shouldProcessApproov, true);
    expect(preparation.shouldApplyPinning, true);
    expect(mutator.interceptorConsulted, true,
        reason: 'a real configuration must still consult the mutator for '
            'the interceptor gate');
    expect(mutator.pinningConsulted, true,
        reason: 'a real configuration must still consult the mutator for '
            'the pinning gate');
  });

  group('Task 9: per-method bypass-mode guards', () {
    test(
        'precheck() rejects in bypass mode without reaching the platform channel',
        () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-precheck');
      fgCalls.clear();
      bgCalls.clear();

      await _expectBypassRejection(() => ApproovService.precheck(),
          fgCalls: fgCalls, bgCalls: bgCalls);
    });

    test(
        'getDeviceID() rejects in bypass mode without reaching the platform channel',
        () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-getdeviceid');
      fgCalls.clear();
      bgCalls.clear();

      await _expectBypassRejection(() => ApproovService.getDeviceID(),
          fgCalls: fgCalls, bgCalls: bgCalls);
    });

    test(
        'setDevKey() rejects in bypass mode without reaching the platform channel',
        () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-setdevkey');
      fgCalls.clear();
      bgCalls.clear();

      await _expectBypassRejection(
          () => ApproovService.setDevKey('some-dev-key'),
          fgCalls: fgCalls,
          bgCalls: bgCalls);
    });

    test(
        'fetchToken() rejects in bypass mode without reaching the platform channel',
        () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-fetchtoken');
      fgCalls.clear();
      bgCalls.clear();

      await _expectBypassRejection(
          () => ApproovService.fetchToken('https://example.com/api'),
          fgCalls: fgCalls,
          bgCalls: bgCalls);
    });

    test(
        'getMessageSignature() rejects in bypass mode without reaching the platform channel',
        () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-getmessagesignature');
      fgCalls.clear();
      bgCalls.clear();

      await _expectBypassRejection(
          () => ApproovService.getMessageSignature('hello-message'),
          fgCalls: fgCalls,
          bgCalls: bgCalls);
    });

    test(
        'getAccountMessageSignature() rejects in bypass mode without reaching the '
        'platform channel, independent of getMessageSignature', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-getaccountmessagesignature');
      fgCalls.clear();
      bgCalls.clear();

      await _expectBypassRejection(
          () => ApproovService.getAccountMessageSignature('hello-message'),
          fgCalls: fgCalls,
          bgCalls: bgCalls);
    });

    test(
        'fetchSecureString() rejects in bypass mode without reaching the platform channel',
        () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-fetchsecurestring');
      fgCalls.clear();
      bgCalls.clear();

      await _expectBypassRejection(
          () => ApproovService.fetchSecureString('some-key', null),
          fgCalls: fgCalls,
          bgCalls: bgCalls);
    });

    test(
        'fetchCustomJWT() rejects in bypass mode without reaching the platform channel',
        () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-fetchcustomjwt');
      fgCalls.clear();
      bgCalls.clear();

      await _expectBypassRejection(
          () => ApproovService.fetchCustomJWT('{"sub":"user1"}'),
          fgCalls: fgCalls,
          bgCalls: bgCalls);
    });

    test(
        'getPins() returns an empty map in bypass mode without reaching the platform channel',
        () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-getpins');
      fgCalls.clear();
      bgCalls.clear();

      final pins = await ApproovService.getPins('public-key-sha256');

      expect(pins, isEmpty,
          reason: 'bypass mode has no active pinning configuration, so an '
              'empty map is the correct (non-error) answer');
      expect(fgCalls, isEmpty);
      expect(bgCalls, isEmpty,
          reason: 'getPins uses the background channel - it must not be '
              'reached in bypass mode');
    });

    test(
        'setDataHashInToken() resolves normally in bypass mode without reaching the '
        'platform channel', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-setdatahash');
      fgCalls.clear();
      bgCalls.clear();

      // Must resolve without throwing: this only stages data for a future
      // token fetch that will never happen in bypass mode, so silently
      // accepting and doing nothing is the correct behavior, not an error.
      await ApproovService.setDataHashInToken('some-binding-value');

      expect(fgCalls, isEmpty);
      expect(bgCalls, isEmpty);
    });

    test(
        'substituteQueryParam() returns the Uri unchanged in bypass mode '
        'without reaching the platform channel', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-substitutequeryparam');
      fgCalls.clear();
      bgCalls.clear();

      // Unlike the reject-style guards above, substituteQueryParam has its
      // own separate, inlined platform-channel call rather than delegating
      // to the already-guarded fetchSecureString() - so it must not throw
      // here, but must instead pass the Uri through unchanged, matching
      // what the core request pipeline (_prepareRequestForApproov) already
      // does when it uses this same substitution logic internally in
      // bypass mode (it never reaches this method at all).
      final originalUri =
          Uri.parse('https://example.com/api?apiKey=some-secure-key');
      final resultUri =
          await ApproovService.substituteQueryParam(originalUri, 'apiKey');

      expect(resultUri, originalUri,
          reason: 'bypass mode must pass the Uri through unchanged rather '
              'than throwing or forwarding a doomed call to the platform '
              'channel');
      expect(fgCalls, isEmpty);
      expect(bgCalls, isEmpty);
    });

    test('prefetch() is obsolete and never attempts a platform-channel call',
        () async {
      // prefetch() is now unconditionally a no-op (matching the rest of the
      // Approov service layer family, e.g. approov-service-retrofit and
      // approov-service-urlsession) - this is no longer bypass-mode-specific
      // behavior, so this test only needs to cover the empty-config case;
      // the equivalent real-config case is covered below.
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-prefetch');
      fgCalls.clear();
      bgCalls.clear();

      // ignore: deprecated_member_use_from_same_package
      ApproovService.prefetch();
      await Future<void>.delayed(Duration.zero);

      expect(fgCalls, isEmpty,
          reason: 'prefetch() is obsolete and must never reach the '
              'platform channel');
      expect(bgCalls, isEmpty);
    });

    test(
        'getLastARC() already degrades to "" in bypass mode (no new guard needed)',
        () async {
      // getLastARC() calls getPins() internally, which now returns {} in
      // bypass mode (see the getPins test above). With no pinned hostname
      // available, getLastARC() takes its normal "no host pinning
      // information available" return branch - it never even reaches its
      // own pre-existing broad try/catch fallback. This test pins down that
      // exact behavior end-to-end through the public API, complementing the
      // code-reading confirmation in the task report.
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize('', 'reinit-getlastarc');
      fgCalls.clear();
      bgCalls.clear();

      final arc = await ApproovService.getLastARC();

      expect(arc, '');
      expect(fgCalls, isEmpty);
      expect(bgCalls, isEmpty,
          reason: 'getLastARC must not reach the platform channel in bypass '
              'mode - getPins already short-circuits before it would');
    });

    test(
        'bypass mode: real loopback HTTP request succeeds with no Approov-Token '
        'header and no token/pin/cert platform-channel calls', () async {
      // This is the offline, network-free, CI-repeatable end-to-end
      // regression test for Task 8's core-pipeline fix: a genuine socket
      // request over loopback (not a mocked platform channel, not a mocked
      // HTTP client) proves the whole request path - from
      // ApproovClient/ApproovHttpClient through _prepareRequestForApproov,
      // _createPinnedHttpClient and _updateRequest - really does skip
      // Approov entirely in bypass mode.
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      // Bind a real server on loopback with an OS-assigned free port so this
      // test is deterministic and safe to run in parallel/CI.
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final observedHeaderNames = <String>{};
      final serverSubscription = server.listen((request) async {
        request.headers.forEach((name, values) {
          observedHeaderNames.add(name.toLowerCase());
        });
        request.response.statusCode = 200;
        request.response.write('ok');
        await request.response.close();
      });
      addTearDown(() async {
        await serverSubscription.cancel();
        await server.close(force: true);
      });

      await ApproovService.initialize('', 'reinit-e2e-loopback');
      fgCalls.clear();
      bgCalls.clear();

      // TestWidgetsFlutterBinding installs a global HttpOverrides that fakes
      // every HttpClient() construction to return a canned 400 with no real
      // socket touched (see the "at least one test in this suite creates an
      // HttpClient" warning) - it exists so widget tests never accidentally
      // hit the real network. This test's whole point is the opposite: it
      // must prove a genuine socket round-trip, so the override is nulled
      // out for its duration and restored afterwards regardless of outcome.
      final previousHttpOverrides = HttpOverrides.current;
      HttpOverrides.global = null;
      addTearDown(() => HttpOverrides.global = previousHttpOverrides);

      final client = ApproovClient();
      addTearDown(client.close);

      final response =
          await client.get(Uri.parse('http://127.0.0.1:${server.port}/ping'));

      expect(response.statusCode, 200);
      expect(response.body, 'ok');
      expect(observedHeaderNames, isNotEmpty,
          reason: 'the server must have genuinely received the request and '
              'recorded real headers - otherwise the assertion below would '
              'pass vacuously even if the request never reached the server '
              'at all');
      expect(
        observedHeaderNames.contains('approov-token'),
        false,
        reason: 'a real request in bypass mode must not carry an Approov '
            'token header - this is Task 8\'s fix, exercised here over a '
            'genuine loopback socket rather than a mock',
      );

      final calledMethods = <String>{
        ...fgCalls.map((c) => c.method),
        ...bgCalls.map((c) => c.method),
      };
      for (final suspectMethod in const [
        'fetchApproovToken',
        'getPins',
        'fetchHostCertificates',
        'waitForFetchValue',
      ]) {
        expect(calledMethods.contains(suspectMethod), false,
            reason: '$suspectMethod must never be invoked for a real '
                'request in bypass mode');
      }
    });
  });

  group('Task 9 fix: protected-mode counter-tests (C1 regression)', () {
    // These are the counter-tests C2 identified as missing: every guard
    // added for Task 9 was only ever exercised in bypass mode, which is
    // exactly how the C1 regression (fetchToken()/prefetch() misfiring in
    // PROTECTED mode) shipped undetected. Each test here initializes with a
    // REAL config and confirms the guarded method still actually reaches
    // the platform channel, rather than incorrectly short-circuiting as if
    // bypass mode were active.
    test(
        'fetchToken() reaches the platform channel after a real config '
        'initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-fetchtoken-protected');
      fgCalls.clear();
      bgCalls.clear();

      // fetchToken() will hang waiting on a completer that this simple mock
      // never resolves (it does not simulate the platform's asynchronous
      // response callback), so it must not be awaited to completion here -
      // this test only needs to confirm the call reaches the platform
      // channel rather than being rejected as if in bypass mode, so it is
      // fired and the event loop is pumped, matching the style of the
      // fire-and-forget prefetch() tests elsewhere in this file.
      unawaited(ApproovService.fetchToken('https://example.com/api')
          .catchError((_) => ''));
      await Future<void>.delayed(Duration.zero);

      expect(
        fgCalls.map((c) => c.method),
        contains('fetchApproovToken'),
        reason: 'a real configuration must still reach the platform channel '
            'for fetchToken - the bypass-mode guard must not misfire while '
            'a genuine initialization is settled (this is the C1 '
            'regression: the guard used to read _initialConfig before it '
            'was reliably set)',
      );
    });

    test('prefetch() remains a no-op even with a real config initialization',
        () async {
      // Confirms prefetch()'s obsolescence is unconditional - not merely a
      // bypass-mode guard that could regress into a C1-style "only checked
      // in one mode" bug. A real, valid configuration must not cause it to
      // start reaching for the platform channel again.
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-prefetch-protected');
      fgCalls.clear();
      bgCalls.clear();

      // ignore: deprecated_member_use_from_same_package
      ApproovService.prefetch();
      await Future<void>.delayed(Duration.zero);

      expect(fgCalls, isEmpty,
          reason: 'prefetch() is obsolete and must never reach the '
              'platform channel, in bypass mode or protected mode');
      expect(bgCalls, isEmpty);
    });
  });

  group('Task 9b: protected-mode counter-tests for remaining bypass guards',
      () {
    // These cover the remaining Task 9 guards that, like fetchToken() and
    // prefetch() before the tests above were added, were only ever
    // exercised in bypass mode - exactly how the C1 regression shipped
    // undetected. Each test here initializes with a REAL config and
    // confirms the guarded method still actually reaches the platform
    // channel (or, for getPins()/getLastARC(), still returns real data)
    // rather than incorrectly short-circuiting as if bypass mode were
    // active.

    test(
        'precheck() reaches the platform channel after a real config '
        'initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-precheck-protected');
      fgCalls.clear();
      bgCalls.clear();

      // precheck() waits on a Completer that only a genuine platform
      // "response" callback would resolve, which this simple mock never
      // sends (the root-isolate path taken in this test environment - see
      // the fetchToken()/prefetch() tests above), so it must not be awaited
      // to completion here; only that it reaches the platform channel
      // rather than being rejected as if in bypass mode matters.
      unawaited(ApproovService.precheck().catchError((_) {}));
      await Future<void>.delayed(Duration.zero);

      expect(
        fgCalls.map((c) => c.method),
        contains('fetchSecureString'),
        reason: 'a real configuration must still reach the platform channel '
            'for precheck via fetchSecureString - the bypass-mode guard '
            'must not misfire while a genuine initialization is settled '
            '(the C1 regression shape)',
      );
    });

    test(
        'getDeviceID() reaches the platform channel after a real config '
        'initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        if (call.method == 'getDeviceID') return 'test-device-id';
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-getdeviceid-protected');
      fgCalls.clear();
      bgCalls.clear();

      // getDeviceID() awaits the platform channel result directly (no
      // transaction/Completer indirection), so it can be awaited to
      // completion in this test.
      final deviceID = await ApproovService.getDeviceID();

      expect(
        fgCalls.map((c) => c.method),
        contains('getDeviceID'),
        reason: 'a real configuration must still reach the platform channel '
            'for getDeviceID - the bypass-mode guard must not misfire while '
            'a genuine initialization is settled (the C1 regression shape)',
      );
      expect(deviceID, 'test-device-id',
          reason: 'getDeviceID must return the value supplied by the '
              'platform channel rather than throwing as if bypass mode '
              'were active');
    });

    test(
        'setDevKey() reaches the platform channel after a real config '
        'initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-setdevkey-protected');
      fgCalls.clear();
      bgCalls.clear();

      await ApproovService.setDevKey('some-dev-key');

      expect(
        fgCalls.map((c) => c.method),
        contains('setDevKey'),
        reason: 'a real configuration must still forward setDevKey to the '
            'platform channel rather than throwing as if bypass mode were '
            'active (the C1 regression shape)',
      );
    });

    test(
        'getMessageSignature() reaches the platform channel after a real '
        'config initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        if (call.method == 'getMessageSignature') return 'base64-signature';
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-getmessagesignature-protected');
      fgCalls.clear();
      bgCalls.clear();

      final signature =
          await ApproovService.getMessageSignature('hello-message');

      expect(
        fgCalls.map((c) => c.method),
        contains('getMessageSignature'),
        reason: 'a real configuration must still reach the platform channel '
            'for getMessageSignature - the bypass-mode guard must not '
            'misfire while a genuine initialization is settled (the C1 '
            'regression shape)',
      );
      expect(signature, 'base64-signature');
    });

    test(
        'getAccountMessageSignature() reaches the platform channel after a '
        'real config initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        if (call.method == 'getAccountMessageSignature') {
          return 'account-signature';
        }
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-getaccountmessagesignature-protected');
      fgCalls.clear();
      bgCalls.clear();

      final signature =
          await ApproovService.getAccountMessageSignature('hello-message');

      expect(
        fgCalls.map((c) => c.method),
        contains('getAccountMessageSignature'),
        reason: 'a real configuration must still reach the platform channel '
            'for getAccountMessageSignature - the bypass-mode guard must '
            'not misfire while a genuine initialization is settled (the C1 '
            'regression shape), independent of getMessageSignature',
      );
      expect(signature, 'account-signature');
    });

    test(
        'fetchSecureString() reaches the platform channel after a real '
        'config initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-fetchsecurestring-protected');
      fgCalls.clear();
      bgCalls.clear();

      // fetchSecureString() waits on a Completer that only a genuine
      // platform "response" callback would resolve, which this simple mock
      // never sends (the root-isolate path - see the fetchToken() test
      // above), so it must not be awaited to completion here.
      unawaited(ApproovService.fetchSecureString('some-key', null)
          .catchError((_) => null));
      await Future<void>.delayed(Duration.zero);

      expect(
        fgCalls.map((c) => c.method),
        contains('fetchSecureString'),
        reason: 'a real configuration must still reach the platform channel '
            'for fetchSecureString - the bypass-mode guard must not misfire '
            'while a genuine initialization is settled (the C1 regression '
            'shape)',
      );
    });

    test(
        'fetchCustomJWT() reaches the platform channel after a real config '
        'initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-fetchcustomjwt-protected');
      fgCalls.clear();
      bgCalls.clear();

      // fetchCustomJWT() waits on a Completer that only a genuine platform
      // "response" callback would resolve, which this simple mock never
      // sends (the root-isolate path - see the fetchToken() test above), so
      // it must not be awaited to completion here.
      unawaited(ApproovService.fetchCustomJWT('{"sub":"user1"}')
          .catchError((_) => ''));
      await Future<void>.delayed(Duration.zero);

      expect(
        fgCalls.map((c) => c.method),
        contains('fetchCustomJWT'),
        reason: 'a real configuration must still reach the platform channel '
            'for fetchCustomJWT - the bypass-mode guard must not misfire '
            'while a genuine initialization is settled (the C1 regression '
            'shape)',
      );
    });

    test(
        'getPins() reaches the platform channel after a real config '
        'initialization and returns real pin data', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        if (call.method == 'getPins') {
          return {
            'example.com': ['pin-sha256-value']
          };
        }
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-getpins-protected');
      fgCalls.clear();
      bgCalls.clear();

      final pins = await ApproovService.getPins('public-key-sha256');

      expect(
        bgCalls.map((c) => c.method),
        contains('getPins'),
        reason: 'a real configuration must still reach the platform channel '
            'for getPins - the bypass-mode guard must not misfire while a '
            'genuine initialization is settled (the C1 regression shape)',
      );
      expect(pins, isNotEmpty,
          reason: 'getPins must return the real pin data supplied by the '
              'platform channel rather than the bypass-mode empty map');
      expect(pins, {
        'example.com': ['pin-sha256-value']
      });
    });

    test(
        'setDataHashInToken() reaches the platform channel after a real '
        'config initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-setdatahash-protected');
      fgCalls.clear();
      bgCalls.clear();

      await ApproovService.setDataHashInToken('some-binding-value');

      expect(
        fgCalls.map((c) => c.method),
        contains('setDataHashInToken'),
        reason: 'a real configuration must still forward setDataHashInToken '
            'to the platform channel rather than silently no-op-ing as if '
            'bypass mode were active (the C1 regression shape)',
      );
    });

    test(
        'substituteQueryParam() reaches the platform channel after a real '
        'config initialization instead of passing the Uri through '
        'unchanged', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        return null;
      };

      await ApproovService.initialize(
          'real-config', 'reinit-substitutequeryparam-protected');
      fgCalls.clear();
      bgCalls.clear();

      final originalUri =
          Uri.parse('https://example.com/api?apiKey=some-secure-key');

      // Like precheck()/fetchSecureString() above, this waits on a
      // Completer that only a genuine platform "response" callback would
      // resolve, which this simple mock never sends (the root-isolate
      // path), so it must not be awaited to completion here; what matters
      // is that it genuinely attempts the secure string substitution
      // rather than short-circuiting straight back to the unchanged Uri, as
      // bypass mode does.
      unawaited(ApproovService.substituteQueryParam(originalUri, 'apiKey')
          .catchError((_) => originalUri));
      await Future<void>.delayed(Duration.zero);

      expect(
        fgCalls.map((c) => c.method),
        contains('fetchSecureString'),
        reason: 'a real configuration must still attempt the secure string '
            'substitution via fetchSecureString rather than '
            'short-circuiting straight back to the unchanged Uri as if '
            'bypass mode were active (the C1 regression shape)',
      );
      final fetchCall =
          fgCalls.firstWhere((c) => c.method == 'fetchSecureString');
      expect(fetchCall.arguments['key'], 'some-secure-key',
          reason: 'the secure string lookup key must be the query '
              'parameter value extracted from the Uri, proving the '
              'substitution logic really ran rather than the call being '
              'coincidental');
    });

    test(
        'getLastARC() proceeds past the getPins short-circuit and reaches '
        'the token-fetch path after a real config initialization', () async {
      final fgCalls = <MethodCall>[];
      final bgCalls = <MethodCall>[];
      fgHandler = (call) async {
        fgCalls.add(call);
        return null;
      };
      bgHandler = (call) async {
        bgCalls.add(call);
        switch (call.method) {
          case 'getPins':
            return {
              'example.com': ['pin-sha256-value']
            };
          case 'waitForFetchValue':
            return {
              'TokenFetchStatus': 'SUCCESS',
              'Token': 'test-arc-token',
              'ARC': 'test-arc-value',
              'ConfigEpoch': 1,
            };
          default:
            return null;
        }
      };

      await ApproovService.initialize(
          'real-config', 'reinit-getlastarc-protected');
      fgCalls.clear();
      bgCalls.clear();

      // Unlike fetchToken()/precheck() above, getLastARC() uses
      // _fetchApproovTokenNoCallback internally, which always waits via the
      // background "waitForFetchValue" mechanism regardless of isolate, so
      // (with a properly-shaped mock response) it resolves normally and can
      // be awaited to completion here.
      final arc = await ApproovService.getLastARC();

      expect(
        fgCalls.map((c) => c.method),
        contains('fetchApproovToken'),
        reason: 'a real configuration with pin data available must still '
            'reach the token-fetch path via fetchApproovToken - the '
            'getPins-derived short-circuit must not misfire while a '
            'genuine initialization is settled (the C1 regression shape)',
      );
      expect(
        bgCalls.map((c) => c.method),
        containsAll(['getPins', 'waitForFetchValue']),
        reason: 'getLastARC must consult getPins for pinned hosts and then '
            'wait for the token fetch result via the background channel',
      );
      expect(arc, 'test-arc-value',
          reason: 'getLastARC must return the real ARC value from the '
              'token fetch result rather than the "" it would return if it '
              'incorrectly took the no-pinning-information short-circuit');
    });
  });
}

/// Standard assertion for the reject-style bypass guards added in Task 9:
/// invokes [invoke] (already running against an ApproovService initialized
/// in bypass mode) and confirms it throws an ApproovException mentioning
/// "not enabled", while the mocked platform channel records no call at all -
/// proving the guard fires before any channel invocation is attempted,
/// rather than the channel merely happening to fail gracefully on its own.
Future<void> _expectBypassRejection(
  Future<dynamic> Function() invoke, {
  required List<MethodCall> fgCalls,
  required List<MethodCall> bgCalls,
}) async {
  await expectLater(
    invoke(),
    throwsA(
      isA<ApproovException>().having(
        (e) => e.cause ?? '',
        'cause',
        contains('not enabled'),
      ),
    ),
  );
  expect(fgCalls, isEmpty,
      reason: 'no foreground platform-channel call should be made once the '
          'bypass-mode guard rejects the call');
  expect(bgCalls, isEmpty,
      reason: 'no background platform-channel call should be made once the '
          'bypass-mode guard rejects the call');
}

/// Mutator whose gate callbacks always allow processing/pinning, while
/// recording whether each was actually invoked. Used to prove that bypass
/// mode skips consulting the mutator entirely, rather than consulting it and
/// discarding a result that happens to get overridden to the same value the
/// production short-circuit would have produced anyway.
class _AlwaysAllowMutator extends ApproovServiceMutator {
  bool interceptorConsulted = false;
  bool pinningConsulted = false;

  @override
  FutureOr<bool> handleInterceptorShouldProcessRequest(
      ApproovRequestSnapshot request) {
    interceptorConsulted = true;
    return true;
  }

  @override
  FutureOr<bool> handlePinningShouldProcessRequest(
      ApproovRequestSnapshot request) {
    pinningConsulted = true;
    return true;
  }
}
