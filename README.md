# Approov Service for Flutter HttpClient

![Flutter](https://img.shields.io/badge/Flutter-3.7%2B-02569B?logo=flutter&logoColor=white)
![pub.dev](https://img.shields.io/pub/v/approov_service_flutter_httpclient.svg?label=pub.dev&logo=dart&logoColor=white)
![iOS](https://img.shields.io/badge/iOS-11%2B-000000?logo=apple&logoColor=white)
![Android](https://img.shields.io/badge/Android-minSdk%2021-3DDC84?logo=android&logoColor=white)
![Message Signing](https://img.shields.io/badge/Message%20Signing-RFC%209421-1f6feb)

A wrapper for the iOS [Approov SDK](https://github.com/approov/approov-ios-sdk) and Android [Approov SDK](https://github.com/approov/approov-android-sdk) to enable easy integration when using [`Flutter`](https://flutter.dev) for making API calls you want to protect with Approov. In order to use this you will need a trial or paid [Approov](https://www.approov.io) account.

See the [Quickstart](https://github.com/approov/quickstart-flutter-httpclient) for a full integration example.

## ADDING APPROOV SERVICE DEPENDENCY

The Approov integration is available via [pub.dev](https://pub.dev/packages/approov_service_flutter_httpclient). Add it to your `pubspec.yaml`:

```yaml
dependencies:
  approov_service_flutter_httpclient: ^3.5.7
```

Then fetch it:

```bash
flutter pub get
```

This package depends on the closed-source Approov SDK for [iOS](https://github.com/approov/approov-ios-sdk) and [Android](https://github.com/approov/approov-android-sdk), which are pulled in automatically.

## MANIFEST / PROJECT CHANGES

**Android:** no manual manifest changes are needed — the `ACCESS_NETWORK_STATE` and `INTERNET` permissions are bundled in the plugin's own manifest and merged into your app automatically.

**iOS:** both [Swift Package Manager](https://www.swift.org/documentation/package-manager/) and CocoaPods are supported for the native iOS side, so no project changes are required either way:
- On Flutter 3.24+ with SPM enabled (`flutter config --enable-swift-package-manager`, the default from Flutter 3.44), the plugin resolves via SPM.
- On older Flutter versions, or with SPM disabled, the plugin falls back to its bundled `.podspec` via CocoaPods.

## INITIALIZING APPROOV SERVICE

Initialize `ApproovService` once, early in your app's lifecycle (e.g. in `main()` before `runApp`):

```dart
import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';
import 'package:uuid/uuid.dart'; // add the `uuid` pub package, or swap in any
                                  // session/user identifier you already have

Future<void> initializeApproov() async {
  // An app-generated id used to correlate this install/session across your own app
  // logs and your backend. Use a UUID, or any session/user identifier you already
  // have — it is NOT an Approov secret.
  final correlationId = const Uuid().v4();

  await ApproovService.initialize('<enter-your-config-string-here>');
  try {
    // getDeviceID() waits on the initialization result, so this is where an
    // initialization failure actually surfaces.
    final deviceID = await ApproovService.getDeviceID();
    // Initialization succeeded — log identifiers for correlation / observability.
    print('Approov initialized; deviceID=$deviceID session=$correlationId');
  } catch (e) {
    // Initialization failed — log it and continue UNPROTECTED so the app still works.
    // Re-initializing with an empty config string enters bypass mode (initialized,
    // but no Approov token injection, pinning, or secret substitution).
    print('Approov init failed (session=$correlationId): $e; continuing unprotected');
    await ApproovService.initialize('');
  }
}
```

The `<enter-your-config-string-here>` is a custom string that configures your Approov account access. This will have been provided in your Approov onboarding email.

On success the example logs the Approov **device ID** (`getDeviceID()`) and an **app-generated session/correlation id** so a given install can be correlated across your app logs, backend, and the Approov [Live Metrics](https://approov.io/docs/latest/approov-usage-documentation/#metrics-graphs). If initialization fails, the example re-initializes with an empty config so the app keeps working — but those requests go out **without Approov protection**, so treat the backend as the enforcement point.

You can confirm bypass mode programmatically with `await ApproovService.isApproovEnabled()` (returns `false` when running unprotected, `true` when a real config is active) and `await ApproovService.isInitialized()` (`true` in both cases, once `initialize()` has been called at least once).

## USING APPROOV SERVICE

Use `ApproovHttpClient` as a drop-in replacement for Dart's `HttpClient`:

```dart
import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';

final client = ApproovHttpClient();
final request = await client.getUrl(Uri.parse('https://your.api.domain/endpoint'));
final response = await request.close();
```

Or `ApproovClient` if you use the [`package:http`](https://pub.dev/packages/http) `BaseClient` interface:

```dart
import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';

final client = ApproovClient();
final response = await client.get(Uri.parse('https://your.api.domain/endpoint'));
```

For API domains that are configured to be protected with an Approov token, this adds the `Approov-Token` header and pins the connection. This may also substitute header values when using secrets protection.

Approov errors are thrown as `ApproovException` (or its subtypes `ApproovNetworkException` / `ApproovRejectionException`).

See [USAGE.md](USAGE.md) for mutator patterns, logging, and other customization options.

## CHECKING IT WORKS

Initially you won't have set which API domains to protect, so requests won't be modified. It will have called Approov though and made contact with the Approov cloud service. You will see logging from Approov saying `UNKNOWN_URL`.

Your Approov onboarding email should contain a link allowing you to access [Live Metrics Graphs](https://approov.io/docs/latest/approov-usage-documentation/#metrics-graphs). After you've run your app with Approov integration you should be able to see the results in the live metrics within a minute or so. At this stage you could even release your app to get details of your app population and the attributes of the devices they are running upon.

## NEXT STEPS

To actually protect your APIs and/or secrets there are some further steps. Approov provides two different options for protection:

* **API PROTECTION**: use this if you control the backend API(s) being protected and can modify them to ensure that a valid Approov token is being passed by the app. An [Approov Token](https://approov.io/docs/latest/approov-usage-documentation/#approov-tokens) is a short-lived cryptographically signed JWT proving the authenticity of the call.
* **SECRETS PROTECTION**: this allows app secrets, including API keys for 3rd party services, to be protected so that they no longer need to be included in the released app code. These secrets are only made available to valid apps at runtime.

Note that it is possible to use both approaches side-by-side in the same app.

---

## Useful Links

- [Approov iOS SDK](https://github.com/approov/approov-ios-sdk)
- [Approov Android SDK](https://github.com/approov/approov-android-sdk)
- [Approov Website](https://www.approov.io)
- [Quickstart Guide](https://github.com/approov/quickstart-flutter-httpclient)
- [Changelog](CHANGELOG.md)
- [Reference Documentation](REFERENCE.md)
- [Usage Guide](USAGE.md)
