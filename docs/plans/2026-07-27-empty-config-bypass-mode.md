# Empty-Config Bypass Mode Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Make `ApproovService.initialize('')` actually enter a safe "bypass mode" (initialized, no Approov protection, behaves as a plain network client) instead of throwing — and expose `isInitialized()` / `isApproovEnabled()` so callers and tests can observe that state, matching what the plugin's own README already (currently falsely) claims and what the sibling `approov-service-react-native` plugin already does correctly.

**Architecture:** Add an empty-string guard around the native `Approov.initialize(...)` call on both platforms (skip the SDK call, still record `initializedConfig`/`initializedComment` so the plugin knows it's "initialized but unprotected"), add `isInitialized`/`isApproovEnabled` platform-channel methods that read that same state, add matching async Dart wrappers, and fix the Dart-level `_initializeAsync` re-init guard so empty↔non-empty config transitions are handled per `TESTING_REQUIREMENTS.md` §1 instead of throwing.

**Tech Stack:** Dart (`lib/approov_service_flutter_httpclient.dart`), Java (Android plugin), Objective-C (iOS plugin), `flutter_test` with mocked `MethodChannel`s.

**Branch / PR decision (flagged, not decided here):** This repo's only open work is `feature/use-swiftpm` → PR #35 ("Add Swift Package Manager support for iOS"), which is where the false bypass-mode claim was originally written and caught in review. This plan's diff is a real behavioral feature (native code on two platforms + new public API), not a packaging fix like the two prior commits on that branch. Ask the user before starting execution: bundle onto `feature/use-swiftpm` (keeps the fix next to the claim it fixes, but further swells an already-large review) or cut a fresh branch/PR for it (cleaner scope, but the SPM PR ships with the false claim removed rather than made-true in the interim). Default recommendation if asked to just pick: fresh branch — the SPM PR is CocoaPods/SPM packaging only; keep it that way and land bypass-mode support as its own reviewable unit.

---

## Context every task needs

- Repo: `/Users/ivol/Approov/service-layers/approov-service-flutter-httpclient`.
- Reference implementation to mirror (read, don't copy wholesale — this plugin's native layer is much thinner than RN's, most runtime state lives in Dart): `/Users/ivol/Approov/service-layers/approov-service-react-native`:
  - Android pattern: `android/src/main/java/io/approov/reactnative/ApproovService.java:750-896` (the `@ReactMethod initialize` method and `isInitialized()`/`isApproovEnabled()` below it).
  - iOS pattern: `ios/ApproovService.m:122-125` (`ApproovIsEnabled()` helper) and the `initialize` method-call branch.
- Spec every behavior below is checked against: `/Users/ivol/Approov/core-service-layers-testing/TESTING_REQUIREMENTS.md` §1 "Initialization" (specifically: Empty Configuration (Valid/Empty Comment), Empty Then Valid Configuration, Empty Configuration after Valid Configuration, Service-Layer State Only Updated On Success) and §7 "Common Service Layer Interface" (`isInitialized()`, `isApproovEnabled()` are mandatory).
- **Out of scope, do not touch:** the existing "two different non-empty configs" throw behavior in Dart (`lib/approov_service_flutter_httpclient.dart:451-454`) is itself a pre-existing deviation from the spec (spec says forward to native and let native's `IllegalStateException` surface; this code throws its own `ApproovException` before ever reaching native) — that's a separate, pre-existing gap. This plan only touches the empty-string transitions.
- Verified fact, do not re-derive: neither `isInitialized()` nor `isApproovEnabled()` exists anywhere in this plugin today (checked via grep across `lib/`, `android/`, `ios/`). Native Android/iOS `initialize` handlers currently call the native SDK unconditionally regardless of config emptiness — confirmed by reading both files directly.
- **Why `isInitialized`/`isApproovEnabled` must go through the platform channel, not local Dart state:** Dart's own `_isInitialized`/`_initialConfig` are `static` fields scoped to a single Dart **isolate**. Flutter background isolates get their own copy — a background isolate that never itself called `initialize()` would see `_isInitialized == false` even though the native side (a process-wide singleton) is already initialized from the root isolate. This exact problem is why the existing `initialize()` code already re-derives its "am I already initialized" answer from *native* state (`initializedConfig`) rather than trusting Dart's own flag across isolates (see the comment at `android/src/main/java/com/criticalblue/approov_service_flutter_httpclient/ApproovHttpClientPlugin.java:225-226`). Query methods need the same treatment.

---

### Task 1: Fix Dart-level empty-config re-init guard

**Files:**
- Modify: `lib/approov_service_flutter_httpclient.dart:442-497` (the `_initializeAsync` method)
- Test: `test/approov_bypass_mode_test.dart` (new file)

**Step 1: Write the failing tests**

Create `test/approov_bypass_mode_test.dart`:

```dart
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
```

**Step 2: Run tests to verify they fail**

Run: `flutter test test/approov_bypass_mode_test.dart`

Expected: FAIL. The first test throws `ApproovException: Attempt to reinitialize the Approov SDK with a different configuration` when calling `initialize('')` after `'real-config'`. The second test throws the same exception in the opposite direction.

**Step 3: Fix `_initializeAsync`**

In `lib/approov_service_flutter_httpclient.dart`, replace this block (currently lines 448-456):

```dart
      if (_isInitialized &&
          ((comment == null) || !comment.startsWith("reinit"))) {
        // this is a reinitialization attempt and we need to check if the config is the same
        if (_initialConfig != config) {
          throw ApproovException(
              "Attempt to reinitialize the Approov SDK with a different configuration $config");
        }
        Log.d(
            "$TAG: $isolate initialization ignoring attempt with the same config");
      } else {
```

with:

```dart
      if (_isInitialized &&
          ((comment == null) || !comment.startsWith("reinit")) &&
          config.isEmpty) {
        // Empty configuration after any prior initialization (valid or bypass)
        // is ignored outright - it must never silently drop an already-active
        // configuration back into bypass mode (TESTING_REQUIREMENTS.md §1,
        // "Empty Configuration after Valid Configuration").
        Log.d(
            "$TAG: $isolate initialization ignoring empty configuration; already initialized");
      } else if (_isInitialized &&
          ((comment == null) || !comment.startsWith("reinit")) &&
          _initialConfig.isNotEmpty) {
        // this is a reinitialization attempt and we need to check if the config is the same
        if (_initialConfig != config) {
          throw ApproovException(
              "Attempt to reinitialize the Approov SDK with a different configuration $config");
        }
        Log.d(
            "$TAG: $isolate initialization ignoring attempt with the same config");
      } else {
        // Reached when: never initialized, OR previously in bypass mode and now
        // given any config (the "Empty Then Valid Configuration" upgrade path -
        // this must fall through to a real initialization below), OR the comment
        // starts with "reinit".
```

Everything below the `} else {` (the actual initialization body, lines 458-495) is unchanged.

**Step 4: Run tests to verify they pass**

Run: `flutter test test/approov_bypass_mode_test.dart`

Expected: PASS, 2 tests.

**Step 5: Run the full test suite to check for regressions**

Run: `flutter test`

Expected: same baseline as before this change — all tests pass except the pre-existing, unrelated `structured_fields_conformance_test.dart` failures IF the httpwg fixtures aren't checked out locally (see `USAGE.md` "Structured field conformance tests" — clone `https://github.com/httpwg/structured-field-tests` into `test/third_party/structured_field_tests` first if you want that suite to run at all; if you do, expect 1267/1269 with the 2 failures being `can_fail: true` date edge cases, unrelated to this change).

**Step 6: Commit**

```bash
git add lib/approov_service_flutter_httpclient.dart test/approov_bypass_mode_test.dart
git commit -m "fix: allow empty-config bypass mode transitions in initialize()"
```

---

### Task 2: Add `isInitialized()` / `isApproovEnabled()` to the Dart public API

**Files:**
- Modify: `lib/approov_service_flutter_httpclient.dart` (add near `getDeviceID()` at line 883)
- Test: `test/approov_bypass_mode_test.dart` (extend)

**Step 1: Write the failing tests**

Append to `test/approov_bypass_mode_test.dart` (inside `main()`, after the existing tests):

```dart
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
```

**Step 2: Run tests to verify they fail**

Run: `flutter test test/approov_bypass_mode_test.dart`

Expected: FAIL with `NoSuchMethodError: ... isInitialized` (the method doesn't exist yet on `ApproovService`).

**Step 3: Implement the two methods**

In `lib/approov_service_flutter_httpclient.dart`, immediately after `getDeviceID()` (ends at line 892, right before the blank line at 893), add:

```dart
  /// Returns whether the Approov service layer has been initialized. This is true
  /// even when initialized in bypass mode with an empty configuration string - it
  /// does not indicate that Approov protection is actually active. Use
  /// [isApproovEnabled] for that. Queries the native layer directly rather than a
  /// local Dart flag, since Dart-level state is per-isolate and can be stale
  /// relative to the process-wide native SDK state.
  ///
  /// @return true if the service layer has been initialized
  static Future<bool> isInitialized() async {
    await _requireInitialized();
    try {
      bool? result = await _invokeFgMethod('isInitialized');
      return result ?? false;
    } catch (err) {
      throw ApproovException('$err');
    }
  }

  /// Returns whether Approov-backed protection (token injection, pinning, secure
  /// string substitution) is actually active. Returns false when the service
  /// layer is initialized in bypass mode with an empty configuration string.
  ///
  /// @return true if Approov protection is active
  static Future<bool> isApproovEnabled() async {
    await _requireInitialized();
    try {
      bool? result = await _invokeFgMethod('isApproovEnabled');
      return result ?? false;
    } catch (err) {
      throw ApproovException('$err');
    }
  }

```

Note: `_requireInitialized()` throws `ApproovException("ApproovService has not been initialized")` if `initialize()` was never called in this isolate — this matches every other query method in this file (e.g. `getDeviceID()`) and is correct: these are queries *about* an initialization that must have happened, not a way to probe whether it happened without ever calling `initialize()`.

**Step 4: Run tests to verify they pass**

Run: `flutter test test/approov_bypass_mode_test.dart`

Expected: PASS, 4 tests total.

**Step 5: Commit**

```bash
git add lib/approov_service_flutter_httpclient.dart test/approov_bypass_mode_test.dart
git commit -m "feat: add isInitialized() and isApproovEnabled() to Dart API"
```

---

### Task 3: Android native — empty-config guard + new query methods

**Files:**
- Modify: `android/src/main/java/com/criticalblue/approov_service_flutter_httpclient/ApproovHttpClientPlugin.java:271-302`

**Step 1: Read the current code**

Lines 271-302 currently:

```java
    if (call.method.equals("initialize")) {
      // get the initialization arguments
      String initialConfig = call.argument("initialConfig");
      String commentString = call.argument("comment");
      if (commentString == null) {
        commentString = "";
      }

      // determine if the initialization is needed (indicated by a change in either the initial config string or the comment) -
      // this is necessary because hot restarts or the creation of new isolates means that the Dart level may not have determined
      // that the SDK is already initialized whereas this native layer holds its state
      if ((initializedConfig == null) || !initializedConfig.equals(initialConfig) || !initializedComment.equals(commentString)) {
        // this is a new config or a reinitialization
        try {
          Approov.initialize(appContext, initialConfig, call.argument("updateConfig"), commentString);
        } catch (IllegalStateException e) {
          // log and ignore the error if the SDK is already initialized - this can happen if an app is using multiple
          // different isolates and the initialization was made by a different quickstart (note we don't currently check
          // for the compatibility of the SDK parameters but a future version of the SDK will do this to avoid needing to
          // catch this at all)
          Log.w("ApproovService", "Ignoring initialization error in Approov SDK: " + e.getLocalizedMessage());
        } catch(Exception e) {
            result.error("Approov.initialize", e.getLocalizedMessage(), null);
            return;
        }
        initializedConfig = initialConfig;
        initializedComment = commentString;
        result.success(null);
      } else {
        // the previous initialization is compatible
        result.success(null);
      }
```

**Step 2: Replace with the bypass-aware version**

```java
    if (call.method.equals("initialize")) {
      // get the initialization arguments
      String initialConfig = call.argument("initialConfig");
      String commentString = call.argument("comment");
      if (commentString == null) {
        commentString = "";
      }

      // An empty config after a valid config is already active must be ignored -
      // it must never silently drop back into bypass mode.
      if (isApproovEnabled() && initialConfig.isEmpty()) {
        Log.i("ApproovService", "already initialized with a valid config; ignoring empty configuration");
        result.success(null);
        return;
      }

      // determine if the initialization is needed (indicated by a change in either the initial config string or the comment) -
      // this is necessary because hot restarts or the creation of new isolates means that the Dart level may not have determined
      // that the SDK is already initialized whereas this native layer holds its state
      if ((initializedConfig == null) || !initializedConfig.equals(initialConfig) || !initializedComment.equals(commentString)) {
        // this is a new config or a reinitialization
        try {
          // Bypass mode: an empty config skips the native SDK call entirely, but
          // the service layer still records itself as initialized below, so
          // isInitialized() is true and isApproovEnabled() is false.
          if (!initialConfig.isEmpty()) {
            Approov.initialize(appContext, initialConfig, call.argument("updateConfig"), commentString);
          }
        } catch (IllegalStateException e) {
          // log and ignore the error if the SDK is already initialized - this can happen if an app is using multiple
          // different isolates and the initialization was made by a different quickstart (note we don't currently check
          // for the compatibility of the SDK parameters but a future version of the SDK will do this to avoid needing to
          // catch this at all)
          Log.w("ApproovService", "Ignoring initialization error in Approov SDK: " + e.getLocalizedMessage());
        } catch(Exception e) {
            result.error("Approov.initialize", e.getLocalizedMessage(), null);
            return;
        }
        initializedConfig = initialConfig;
        initializedComment = commentString;
        result.success(null);
      } else {
        // the previous initialization is compatible
        result.success(null);
      }
    } else if (call.method.equals("isInitialized")) {
      result.success(initializedConfig != null);
    } else if (call.method.equals("isApproovEnabled")) {
      result.success(isApproovEnabled());
```

Note the last two `else if` branches replace the `} else if (call.method.equals("fetchConfig")) {` line's leading `} else if` is unaffected — you're inserting two new branches *before* the existing `fetchConfig` branch, so the flow becomes: `initialize` branch → (new) `isInitialized` → (new) `isApproovEnabled` → existing `fetchConfig` → ... Adjust brace placement carefully; the existing `if (call.method.equals("initialize")) { ... }` block's closing `}` at line 302 must become `} else if (call.method.equals("isInitialized")) { ... } else if (call.method.equals("isApproovEnabled")) { ... } else if (call.method.equals("fetchConfig")) {` — i.e. insert the two new branches between the old `initialize` block's close and the existing `fetchConfig` branch, don't duplicate the closing brace.

**Step 3: Add the private helper method**

Add this method anywhere alongside the other private fields/methods (e.g. right after the `configEpoch` field declaration around line 235):

```java
  /**
   * Returns true when the service layer is initialized and Approov-backed
   * request protection is active (i.e. initialized with a non-empty config).
   */
  private boolean isApproovEnabled() {
    return (initializedConfig != null) && !initializedConfig.isEmpty();
  }
```

**Step 4: Verify it compiles**

Run: `cd android && ./gradlew compileDebugJavaWithJavac`

Expected: `BUILD SUCCESSFUL`. (This repo has no native Android unit test harness — this compile check plus the real end-to-end build in Task 5 is the available verification.)

**Step 5: Commit**

```bash
git add android/src/main/java/com/criticalblue/approov_service_flutter_httpclient/ApproovHttpClientPlugin.java
git commit -m "feat(android): support empty-config bypass mode, add isInitialized/isApproovEnabled"
```

---

### Task 4: iOS native — empty-config guard + new query methods

**Files:**
- Modify: `ios/approov_service_flutter_httpclient/Sources/approov_service_flutter_httpclient/ApproovHttpClientPlugin.m`

**Step 1: Read the current code**

The `initialize` branch (around line 420-460) currently ends with:

```objc
            _initializedConfig = initialConfig;
            _initializedComment = commentString;
            result(nil);
        } else {
            // the previous initialization is compatible
            result(nil);
        }
    } else if ([@"fetchConfig" isEqualToString:call.method]) {
```

and the call is made a few lines above via:

```objc
            [Approov initialize:initialConfig updateConfig:updateConfig comment:commentString error:&error];
```

**Step 2: Add the private helper**

In the `@interface ApproovHttpClientPlugin()` class extension (around line 361-389, alongside `@property NSString *initializedConfig;`), no new property is needed — add a private method instead, placed right before `@implementation ApproovHttpClientPlugin` (around line 396):

```objc
// Returns true when the service layer is initialized and Approov-backed request
// protection is active (i.e. initialized with a non-empty config).
static BOOL ApproovHttpClientIsEnabled(ApproovHttpClientPlugin *self) {
    return (self.initializedConfig != nil) && (self.initializedConfig.length != 0);
}
```

(A plain C function taking `self` explicitly, matching the style already used for the top-level `CertificatesFetcher`/`InternalCallBackHandler` helper classes in this file rather than adding a new instance method declaration.)

**Step 3: Guard the native call and add the query branches**

Replace:

```objc
        if ((_initializedConfig == nil) || ![_initializedConfig isEqualToString:initialConfig] || ![_initializedComment isEqualToString:commentString]) {
            // this is a new config or a reinitialization
            NSString *updateConfig = nil;
            if (call.arguments[@"updateConfig"] != [NSNull null])
                updateConfig = call.arguments[@"updateConfig"];
            [Approov initialize:initialConfig updateConfig:updateConfig comment:commentString error:&error];
            if (error != nil) {
                // check if the error message contains "Approov SDK already initialized"
                if ([error.localizedDescription rangeOfString:@"Approov SDK already initialized" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    // log and ignore the error if the SDK is already initialized - this can happen if an app is using multiple
                    // different isolates and the initialization was made by a different quickstart (note we don't currently check
                    // for the compatibility of the SDK parameters but a future version of the SDK will do this to avoid needing to
                    // catch this at all)
                    NSLog(@"ApproovService: Ignoring initialization error in Approov SDK: %@", error.localizedDescription);
                } else {
                    result([FlutterError errorWithCode:[NSString stringWithFormat:@"%ld", (long)error.code]
                                            message:error.domain
                                            details:error.localizedDescription]);
                    return;
                }
            }
            _initializedConfig = initialConfig;
            _initializedComment = commentString;
            result(nil);
        } else {
            // the previous initialization is compatible
            result(nil);
        }
    } else if ([@"fetchConfig" isEqualToString:call.method]) {
```

with:

```objc
        if ((_initializedConfig == nil) || ![_initializedConfig isEqualToString:initialConfig] || ![_initializedComment isEqualToString:commentString]) {
            // this is a new config or a reinitialization
            NSString *updateConfig = nil;
            if (call.arguments[@"updateConfig"] != [NSNull null])
                updateConfig = call.arguments[@"updateConfig"];
            // Bypass mode: an empty config skips the native SDK call entirely, but
            // the service layer still records itself as initialized below, so
            // isInitialized is true and isApproovEnabled is false.
            if (initialConfig.length != 0) {
                [Approov initialize:initialConfig updateConfig:updateConfig comment:commentString error:&error];
                if (error != nil) {
                    // check if the error message contains "Approov SDK already initialized"
                    if ([error.localizedDescription rangeOfString:@"Approov SDK already initialized" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                        // log and ignore the error if the SDK is already initialized - this can happen if an app is using multiple
                        // different isolates and the initialization was made by a different quickstart (note we don't currently check
                        // for the compatibility of the SDK parameters but a future version of the SDK will do this to avoid needing to
                        // catch this at all)
                        NSLog(@"ApproovService: Ignoring initialization error in Approov SDK: %@", error.localizedDescription);
                    } else {
                        result([FlutterError errorWithCode:[NSString stringWithFormat:@"%ld", (long)error.code]
                                                message:error.domain
                                                details:error.localizedDescription]);
                        return;
                    }
                }
            }
            _initializedConfig = initialConfig;
            _initializedComment = commentString;
            result(nil);
        } else {
            // the previous initialization is compatible
            result(nil);
        }
    } else if ([@"isInitialized" isEqualToString:call.method]) {
        result(@(_initializedConfig != nil));
    } else if ([@"isApproovEnabled" isEqualToString:call.method]) {
        result(@(ApproovHttpClientIsEnabled(self)));
    } else if ([@"fetchConfig" isEqualToString:call.method]) {
```

**Step 4: Also guard the initial empty-after-valid check**

Immediately before the `if ((_initializedConfig == nil) || ...)` line above, add:

```objc
        if (ApproovHttpClientIsEnabled(self) && initialConfig.length == 0) {
            NSLog(@"ApproovService: already initialized with a valid config; ignoring empty configuration");
            result(nil);
            return;
        }

```

**Step 5: Verify it builds**

There's no isolated native unit test harness for this file (confirmed earlier — this repo doesn't have the `tests/ios/native` scaffolding the RN sibling repo has). Verification is the real end-to-end build in Task 5.

**Step 6: Commit**

```bash
git add ios/approov_service_flutter_httpclient/Sources/approov_service_flutter_httpclient/ApproovHttpClientPlugin.m
git commit -m "feat(ios): support empty-config bypass mode, add isInitialized/isApproovEnabled"
```

---

### Task 5: Real build + manual verification (both native platforms)

No native test harness exists in this repo for either platform, so this is the actual proof the native changes work — matching how the SPM support itself was verified earlier (a real throwaway Flutter app, not just "it compiled").

**Step 1: iOS — build via SPM in a throwaway app**

```bash
cd /tmp && flutter create --platforms=ios bypass_verify_app
cd bypass_verify_app
python3 - <<'PY'
p = "pubspec.yaml"
s = open(p).read()
s = s.replace("dependencies:\n  flutter:\n    sdk: flutter\n",
              "dependencies:\n  flutter:\n    sdk: flutter\n  approov_service_flutter_httpclient:\n    path: /Users/ivol/Approov/service-layers/approov-service-flutter-httpclient\n")
open(p, "w").write(s)
PY
flutter pub get
flutter config --enable-swift-package-manager
```

**Step 2: Write a throwaway `main.dart` that exercises all four transitions**

Replace `lib/main.dart` with:

```dart
import 'package:flutter/material.dart';
import 'package:approov_service_flutter_httpclient/approov_service_flutter_httpclient.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final log = StringBuffer();

  await ApproovService.initialize('');
  log.writeln('after empty init: isInitialized=${await ApproovService.isInitialized()} '
      'isApproovEnabled=${await ApproovService.isApproovEnabled()}');

  // Should be ignored, not throw.
  await ApproovService.initialize('');
  log.writeln('after second empty init: still isApproovEnabled=${await ApproovService.isApproovEnabled()}');

  print(log.toString());
  runApp(const SizedBox());
}
```

(No real Approov account config string is used here on purpose — this only exercises the empty-config bypass path, which needs no account. Testing the *upgrade* transition, empty-then-valid-config, needs a real config string and is optional — see Step 4.)

**Step 3: Build for a simulator (no device/signing needed just to prove it compiles and runs)**

```bash
flutter build ios --simulator --debug
```

Expected: `Runner.app` built successfully, matching the SPM verification pattern used earlier in this repo's history.

Then run it and capture the printed log:

```bash
open -a Simulator
flutter run -d "iPhone" --debug
```

Expected console output includes:
```
after empty init: isInitialized=true isApproovEnabled=false
after second empty init: still isApproovEnabled=false
```

If instead you see a thrown `PlatformException` or the app crashes on the first `initialize('')` call, the native guard in Task 3/4 has a bug — go back and check the exact `Approov.initialize`/`[Approov initialize:...]` call is genuinely skipped for the empty string (not just wrapped in a try/catch that still calls it).

**Step 4 (optional, needs a real Approov account config + a connected device): verify the upgrade path**

If you have a real config string (the one used earlier this session for the `approov-service-react-native` device test, `#cb-ivol#mAxOF0ekJUOC36J5XWmVmVipOcUoEdMjhPSp2FVtyTo=`, may or may not be valid for this specific plugin's account setup — confirm with the user first), extend the throwaway app to also call `await ApproovService.initialize('<config>');` after the empty-config calls and check `isApproovEnabled()` flips to `true`. This is the one part of this plan that benefits from the same physical-device-plus-Charles-Proxy verification style used earlier in this session for the React Native plugin — ask the user if they want to do that hands-on check before merging, rather than deciding it for them.

**Step 5: Android — sanity build**

```bash
cd /tmp/bypass_verify_app
flutter build apk --debug
```

Expected: builds successfully. Deeper manual verification (running on an emulator/device and checking logcat for `"already initialized with a valid config; ignoring empty configuration"` or `"initialized without Approov SDK"`-style log lines) is optional — same offer-don't-decide note as Step 4.

**Step 6: Clean up**

```bash
rm -rf /tmp/bypass_verify_app
```

**Step 7: Also re-run the existing CocoaPods regression check**

```bash
source /usr/local/share/chruby/chruby.sh && chruby ruby-3.3.1 && export LANG=en_US.UTF-8
cd /Users/ivol/Approov/service-layers/approov-service-flutter-httpclient
pod lib lint ios/approov_service_flutter_httpclient.podspec --configuration=Debug --skip-tests --use-modular-headers --allow-warnings
```

Expected: `approov_service_flutter_httpclient passed validation.` (no podspec file paths changed in this plan, so this should be an unaffected pass, but re-confirm since the source files themselves changed.)

---

### Task 6: Docs + version bump

**Files:**
- Modify: `README.md`
- Modify: `REFERENCE.md`
- Modify: `CHANGELOG.md`
- Modify: `pubspec.yaml`
- Modify: `ios/approov_service_flutter_httpclient.podspec`

**Step 1: Fix the README's bypass-mode claim now that it's true**

The existing text (from the `INITIALIZING APPROOV SERVICE` section, added in this session's earlier SPM-support work) already says:

```
  } catch (e) {
    // Initialization failed — log it and continue UNPROTECTED so the app still works.
    // Re-initializing with an empty config string enters bypass mode (initialized,
    // but no Approov token injection, pinning, or secret substitution).
    print('Approov init failed (session=$correlationId): $e; continuing unprotected');
    await ApproovService.initialize('');
  }
```

No code change needed here — the claim is now actually true after Tasks 1-4. But add one sentence to the prose right after the code block confirming it, and pointing at the new API (find the paragraph starting "On success the example logs..." and add a sentence after it):

```
You can confirm bypass mode programmatically with `await ApproovService.isApproovEnabled()` (returns `false` when running unprotected, `true` when a real config is active) and `await ApproovService.isInitialized()` (`true` in both cases, once `initialize()` has been called at least once).
```

**Step 2: Document the two new methods in REFERENCE.md**

Add right after the existing `initialize` entry in the `## Initialization` section:

```markdown
### `isInitialized()`

Returns `true` once `initialize()` has been called successfully at least once — including when initialized in bypass mode with an empty configuration string. Does not indicate whether Approov protection is actually active; use `isApproovEnabled()` for that.

### `isApproovEnabled()`

Returns `true` only when Approov-backed protection (token injection, pinning, secure string substitution) is actually active — i.e. `initialize()` was called with a non-empty configuration string. Returns `false` in bypass mode.
```

**Step 3: Bump the version**

In `pubspec.yaml`, change `version: 3.5.7` to `version: 3.5.8`.

In `ios/approov_service_flutter_httpclient.podspec`, change `s.version = '3.5.7'` to `s.version = '3.5.8'` (keep these two in sync — this repo already had a drift bug between them, fixed earlier this session; don't reintroduce it).

**Step 4: Add the CHANGELOG entry**

At the top of `CHANGELOG.md`, above the current `## [3.5.7]` entry, add:

```markdown
## [3.5.8] - (<fill in today's date, DD-Month-YYYY>)
- Add `isInitialized()` and `isApproovEnabled()` public API methods (Dart, Android, iOS).
- Fix `initialize('')` (empty configuration string) to actually enter bypass mode — initializes the service layer without calling the native Approov SDK, instead of throwing. Previously this would fail with a native exception surfaced as a Dart `PlatformException`, contradicting documentation that claimed bypass-mode support.
- Fix `initialize()` re-initialization guard to allow the "empty config → valid config" upgrade transition and to silently ignore a "valid config → empty config" downgrade attempt, per the cross-service-layer `TESTING_REQUIREMENTS.md` spec, instead of throwing in both directions.

```

**Step 5: Commit**

```bash
git add README.md REFERENCE.md CHANGELOG.md pubspec.yaml ios/approov_service_flutter_httpclient.podspec
git commit -m "docs: document bypass mode API, bump to 3.5.8"
```

---

### Task 7: Push

**Step 1: Confirm the branch decision flagged at the top of this plan with the user** (bundle onto `feature/use-swiftpm`, or cut a new branch) before pushing anything.

**Step 2: Push**

If bundling onto the existing branch:
```bash
git push origin feature/use-swiftpm
```

If a fresh branch was chosen instead, create it from `main` (not from `feature/use-swiftpm`, to avoid pulling in the still-under-review SPM changes) and push that, then open a new PR with `gh pr create`.
