# approov-service-flutter-httpclient

A wrapper for the iOS [Approov SDK](https://github.com/approov/approov-ios-sdk) and Android [Approov SDK](https://github.com/approov/approov-android-sdk) to enable easy integration when using [`Flutter`](https://flutter.dev) for making the API calls that you wish to protect with Approov. In order to use this you will need a trial or paid [Approov](https://www.approov.io) account.

See the [Quickstart](https://github.com/approov/quickstart-flutter-httpclient) for usage instructions.

## Structured Field Compliance Tests

The HTTP message signing implementation relies on Structured Field values, so we vendor the official [httpwg/structured-field-tests](https://github.com/httpwg/structured-field-tests) fixtures for full test coverage.

Clone the [httpwg/structured-field-tests](https://github.com/httpwg/structured-field-tests), copy the `.json`, `README.md`, `LICENSE.md`, and `serialisation-tests/` assets into `test/third_party/structured_field_tests`, and then run the following to execute the conformance suite:

```
flutter test test/structured_fields_conformance_test.dart
```

The harness focuses on serialization/canonicalization (parsing is not implemented in this package). All JSON fixtures (including `can_fail` advisories and the serialisation edge cases) are exercised; multi-value field inputs are normalised using the HTTP list concatenation rules so they can be compared against the single-value serializer APIs in this package.
