import 'dart:async';

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
    fgChannel.setMockMethodCallHandler((call) => fgHandler(call));
    bgChannel.setMockMethodCallHandler((call) => bgHandler(call));
  });

  tearDown(() {
    fgChannel.setMockMethodCallHandler(null);
    bgChannel.setMockMethodCallHandler(null);
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
      reason:
          'the empty-config call must not reach native at all once a valid '
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
    // initialize() does not await its own internal work - it only awaits the
    // PRIOR pending call's future (see _futureInitialization guard at the top
    // of initialize()). A second call with the same config forces a full wait
    // on the previous call's completion, including its setUserProperty call,
    // before this test asserts on the calls it made.
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

  test('bypass mode short-circuits before the mutator is ever consulted',
      () async {
    // This mutator always answers "true" for both gates. If the production
    // code called it and then (incorrectly) overrode the result afterwards,
    // shouldProcessApproov/shouldApplyPinning would still read false here -
    // so the flags alone cannot distinguish "never asked" from "asked, then
    // overridden". The *Consulted flags are what actually prove the mutator
    // was skipped entirely.
    final mutator = _AlwaysAllowMutator();
    ApproovService.setServiceMutator(mutator);
    addTearDown(() => ApproovService.setServiceMutator(null));

    await ApproovService.initialize('', 'reinit-e');

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
    final mutator = _AlwaysAllowMutator();
    ApproovService.setServiceMutator(mutator);
    addTearDown(() => ApproovService.setServiceMutator(null));

    await ApproovService.initialize('real-config-4', 'reinit-f');

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
