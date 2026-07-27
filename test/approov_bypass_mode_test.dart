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
}
