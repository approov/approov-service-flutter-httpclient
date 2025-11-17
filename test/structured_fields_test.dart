import 'dart:typed_data';

import 'package:approov_service_flutter_httpclient/src/structured_fields.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('SfBareItem serialization', () {
    // RFC 8941 §3.2 defines canonical forms for each bare item (integers, decimals, strings, tokens, byte sequences, booleans, dates, display strings)
    // including allowed character sets, decimal precision, and escaping rules that these serialization expectations must satisfy.
    test('integer encodes without modification', () {
      expect(SfBareItem.integer(42).serialize(), '42');
      expect(SfBareItem.integer(-7).serialize(), '-7');
    });

    test('integer boundary values are accepted', () {
      const max = 999999999999999;
      const min = -999999999999999;
      expect(SfBareItem.integer(max).serialize(), '$max');
      expect(SfBareItem.integer(min).serialize(), '$min');
    });

    test('integer beyond boundary throws', () {
      const tooLarge = 1000000000000000;
      const tooSmall = -1000000000000000;
      expect(() => SfBareItem.integer(tooLarge), throwsA(isA<SfFormatException>()));
      expect(() => SfBareItem.integer(tooSmall), throwsA(isA<SfFormatException>()));
    });

    test('decimal encodes canonical representation', () {
      expect(SfBareItem.decimal(1.25).serialize(), '1.25');
      expect(SfBareItem.decimal(SfDecimal.parse('-12.340')).serialize(), '-12.34');
    });

    // Commented out as we do not want to throw an exception in this case currently. This renders the test invalid.
    // test('decimal enforces precision limits', () {
    //   expect(SfBareItem.decimal(123456789012.123).serialize(), '123456789012.123');
    //   expect(() => SfBareItem.decimal(1.2345), throwsA(isA<SfFormatException>()));
    // });

    test('string escapes quotes and backslashes', () {
      expect(SfBareItem.string('say "hi" \\ wave').serialize(), '"say \\"hi\\" \\\\ wave"');
    });

    test('token enforces allowed syntax', () {
      expect(SfBareItem.token(SfToken('Foo/Bar')).serialize(), 'Foo/Bar');
      expect(() => SfToken('1abc'), throwsA(isA<SfFormatException>()));
    });

    test('byte sequence base64 encodes content', () {
      final bytes = Uint8List.fromList([0, 1, 2, 3]);
      expect(SfBareItem.byteSequence(bytes).serialize(), ':AAECAw==:');
    });

    test('boolean serializes using ?0/?1', () {
      expect(SfBareItem.boolean(true).serialize(), '?1');
      expect(SfBareItem.boolean(false).serialize(), '?0');
    });

    test('date serializes with @ prefix', () {
      expect(SfBareItem.date(SfDate.fromSeconds(1659578233)).serialize(), '@1659578233');
    });

    test('display string percent encodes non-ascii', () {
      final display = SfBareItem.displayString(SfDisplayString('über % test'));
      expect(display.serialize(), '%"%c3%bcber %25 test"');
    });

    test('empty string and byte sequence serialize correctly', () {
      expect(SfBareItem.string('').serialize(), '""');
      expect(SfBareItem.byteSequence(Uint8List(0)).serialize(), '::');
    });

    test('long string and token serialize without truncation', () {
      final longString = 'x' * 2048;
      final longToken = 'a' * 1024;
      expect(SfBareItem.string(longString).serialize().length, longString.length + 2);
      expect(SfBareItem.token(SfToken(longToken)).serialize(), longToken);
    });

    test('decimal parse round-trips to canonical string', () {
      final decimal = SfDecimal.parse('42.500');
      expect(decimal.toString(), '42.5');
      expect(SfBareItem.decimal(decimal).serialize(), '42.5');
    });
  });

  // RFC 8941 §3.3 describes how lists, inner lists, and dictionaries serialize, along with parameter syntax (`;key=value` with `true` omitting the `=value` part).
  group('Structured collections', () {
    test('parameters omit explicit true values', () {
      final item = SfItem.string('example', {'flag': true, 'mode': 'test'});
      expect(item.serialize(), '"example";flag;mode="test"');
    });

    test('parameters retain false boolean', () {
      final item = SfItem.string('example', {'flag': false});
      expect(item.serialize(), '"example";flag=?0');
    });

    test('inner list serializes members and parameters', () {
      final inner = SfInnerList(
        [
          SfItem.token('foo'),
          SfItem.integer(10, {'v': 1}),
        ],
        {'tag': 'alpha'},
      );
      expect(inner.serialize(), '(foo 10;v=1);tag="alpha"');
    });

    test('list supports mixed members', () {
      final inner = SfInnerList([SfItem.string('bar')]);
      final list = SfList([
        SfListMember.item(SfItem.integer(1)),
        SfListMember.innerList(inner),
        SfListMember.item(SfItem.boolean(true)),
      ]);
      expect(list.serialize(), '1, ("bar"), ?1');
    });

    test('dictionary serializes values and parameters', () {
      final dictionary = SfDictionary({
        'flag': SfDictionaryMember.booleanTrue({'v': 1}),
        'count': SfDictionaryMember.item(SfItem.integer(4)),
        'list': SfDictionaryMember.innerList(SfInnerList([SfItem.string('x')])),
      });
      expect(dictionary.serialize(), 'flag;v=1, count=4, list=("x")');
    });

    test('empty collections serialize to empty string', () {
      expect(SfInnerList([]).serialize(), '()');
      expect(SfList([]).serialize(), '');
      expect(SfDictionary({}).serialize(), '');
    });
  });

  /// Tests for conversions between Dart types and SfBareItem specifically.
  // RFC 8941 §3.2 describes bare item grammar and canonical formatting rules; this suite ensures `SfBareItem.fromDynamic` coerces Dart types into RFC-accurate bare items and that their serialization matches the documented canonical forms.
  group('SfBareItem conversions', () {
    test('fromDynamic preserves Dart types and round-trips to SF values', () {
      final existingBoolean = SfBareItem.boolean(true);
      final decimalInstance = SfDecimal.parse('2.500');
      final displayString = SfDisplayString('hi!');
      final token = SfToken('sig/1');
      final bytes = Uint8List.fromList([0, 1, 2]);
      final listBytes = [255, 254];
      final contextDateTime = DateTime.utc(2023, 1, 1);
      final fallbackString = 'fallback.parse';

      final expectations = [
        _ConversionExpectation(
          description: 'boolean true becomes the boolean bare item',
          dartValue: true,
          expectedType: SfBareItemType.boolean,
          verifyValue: (item) => expect(item.value, isTrue),
          expectedSerialization: '?1',
        ),
        _ConversionExpectation(
          description: 'boolean false becomes the boolean bare item',
          dartValue: false,
          expectedType: SfBareItemType.boolean,
          verifyValue: (item) => expect(item.value, isFalse),
          expectedSerialization: '?0',
        ),
        _ConversionExpectation(
          description: 'integers stay integers',
          dartValue: 42,
          expectedType: SfBareItemType.integer,
          verifyValue: (item) => expect(item.value, 42),
          expectedSerialization: '42',
        ),
        _ConversionExpectation(
          description: 'doubles round to canonical decimals',
          dartValue: 3.141,
          expectedType: SfBareItemType.decimal,
          verifyValue: (item) =>
              expect((item.value as SfDecimal).scaledValue, 3141),
          expectedSerialization: '3.141',
        ),
        _ConversionExpectation(
          description: 'SfDecimal instances serialize canonically',
          dartValue: decimalInstance,
          expectedType: SfBareItemType.decimal,
          verifyValue: (item) =>
              expect((item.value as SfDecimal).scaledValue, 2500),
          expectedSerialization: '2.5',
        ),
        _ConversionExpectation(
          description: 'plain strings remain sf-strings',
          dartValue: 'plain text',
          expectedType: SfBareItemType.string,
          verifyValue: (item) => expect(item.value, 'plain text'),
          expectedSerialization: '"plain text"',
        ),
        _ConversionExpectation(
          description: 'decimal-like strings round-trip through fallback',
          dartValue: '4.25',
          expectedType: SfBareItemType.decimal,
          verifyValue: (item) =>
              expect((item.value as SfDecimal).scaledValue, 4250),
          expectedSerialization: '4.25',
        ),
        _ConversionExpectation(
          description: 'invalid decimal strings fall back to sf-strings',
          dartValue: fallbackString,
          expectedType: SfBareItemType.string,
          verifyValue: (item) => expect(item.value, fallbackString),
          expectedSerialization: '"fallback.parse"',
        ),
        _ConversionExpectation(
          description: 'SfToken instances stay tokens',
          dartValue: token,
          expectedType: SfBareItemType.token,
          verifyValue: (item) => expect(item.value, 'sig/1'),
          expectedSerialization: 'sig/1',
        ),
        _ConversionExpectation(
          description: 'Uint8List byte sequences serialize with base64',
          dartValue: bytes,
          expectedType: SfBareItemType.byteSequence,
          verifyValue: (item) =>
              expect(item.value, Uint8List.fromList([0, 1, 2])),
          expectedSerialization: ':AAEC:',
        ),
        _ConversionExpectation(
          description: 'List<int> byte sequences serialize with base64',
          dartValue: listBytes,
          expectedType: SfBareItemType.byteSequence,
          verifyValue: (item) =>
              expect(item.value, Uint8List.fromList([255, 254])),
          expectedSerialization: '://4=:',
        ),
        _ConversionExpectation(
          description: 'DateTime values become sf-dates',
          dartValue: contextDateTime,
          expectedType: SfBareItemType.date,
          verifyValue: (item) =>
              expect((item.value as SfDate).seconds, 1672531200),
          expectedSerialization: '@1672531200',
        ),
        _ConversionExpectation(
          description: 'SfDate values stay sf-dates',
          dartValue: SfDate.fromSeconds(0),
          expectedType: SfBareItemType.date,
          verifyValue: (item) => expect((item.value as SfDate).seconds, 0),
          expectedSerialization: '@0',
        ),
        _ConversionExpectation(
          description: 'SfDisplayString instances serialize with percent-encoding',
          dartValue: displayString,
          expectedType: SfBareItemType.displayString,
          verifyValue: (item) =>
              expect((item.value as SfDisplayString).value, 'hi!'),
          expectedSerialization: '%"hi!"',
        ),
        _ConversionExpectation(
          description: 'existing bare items are returned as-is',
          dartValue: existingBoolean,
          expectedType: SfBareItemType.boolean,
          verifyValue: (item) => expect(item, same(existingBoolean)),
          expectedSerialization: '?1',
        ),
      ];

      for (final expectation in expectations) {
        final bareItem = SfBareItem.fromDynamic(expectation.dartValue);
        expect(
          bareItem.type,
          expectation.expectedType,
          reason: expectation.description,
        );
        expectation.verifyValue(bareItem);
        expect(
          bareItem.serialize(),
          expectation.expectedSerialization,
          reason: expectation.description,
        );
      }
    });

    // RFC 8941 §3.2 requires ties-to-even rounding and a fixed thousandth precision; exercise both rounding directions.
    test('fromDynamic rounds ties-to-even decimals for floats', () {
      final evenTie = SfBareItem.fromDynamic(0.0625);
      expect(evenTie.type, SfBareItemType.decimal);
      expect((evenTie.value as SfDecimal).scaledValue, 62);
      expect(evenTie.serialize(), '0.062');

      final oddTie = SfBareItem.fromDynamic(0.1875);
      expect(oddTie.type, SfBareItemType.decimal);
      expect((oddTie.value as SfDecimal).scaledValue, 188);
      expect(oddTie.serialize(), '0.188');
    });

    // Non-finite numbers are outside RFC 8941's available bare item domain; confirm these are rejected rather than serialized.
    test('fromDynamic rejects non-finite floats', () {
      expect(
        () => SfBareItem.fromDynamic(double.nan),
        throwsA(isA<SfFormatException>()),
      );
      expect(
        () => SfBareItem.fromDynamic(double.infinity),
        throwsA(isA<SfFormatException>()),
      );
      expect(
        () => SfBareItem.fromDynamic(double.negativeInfinity),
        throwsA(isA<SfFormatException>()),
      );
    });

    // RFC 8941 §3.2 bounds decimals to ±999,999,999,999,999 / 1000 — verify inputs beyond that range fail fast.
    test('fromDynamic rejects floats outside the supported range', () {
      expect(
        () => SfBareItem.fromDynamic(1e12),
        throwsA(isA<SfFormatException>()),
      );
      expect(
        () => SfBareItem.fromDynamic(-1e12),
        throwsA(isA<SfFormatException>()),
      );
    });
  });

  // RFC 8941 §3.3.1 defines parameters, how true values omit `=value`, and the `;key=value` serialized order—this test makes sure those typed Dart maps become params that both retain their types and emit the proper canonical fragment.
  test('SfParameters from Dart map keeps typed values for signature parameters', () {
    final rawParameters = {
      'mandatory': true,
      'optional': false,
      'count': 5,
      'ratio': 2.5,
      'digest': SfToken('sha-256'),
      'tag': 'value',
      'meta': SfDisplayString('meta%'),
    };
    final params = SfParameters(rawParameters);
    final map = params.asMap();

    expect(map['mandatory']!.type, SfBareItemType.boolean);
    expect(map['mandatory']!.isBooleanTrue, isTrue);
    expect(map['optional']!.type, SfBareItemType.boolean);
    expect(map['optional']!.value, isFalse);
    expect(map['count']!.type, SfBareItemType.integer);
    expect(map['count']!.value, 5);
    expect(map['ratio']!.type, SfBareItemType.decimal);
    expect((map['ratio']!.value as SfDecimal).scaledValue, 2500);
    expect(map['digest']!.type, SfBareItemType.token);
    expect(map['digest']!.value, 'sha-256');
    expect(map['tag']!.type, SfBareItemType.string);
    expect(map['tag']!.value, 'value');
    expect(map['meta']!.type, SfBareItemType.displayString);
    expect((map['meta']!.value as SfDisplayString).value, 'meta%');

    final buffer = StringBuffer()..write('"dummy"');
    params.serializeTo(buffer);
    expect(
      buffer.toString(),
      '"dummy";mandatory;optional=?0;count=5;ratio=2.5;digest=sha-256;tag="value";meta=%"meta%25"',
    );
  });

  // RFC 8941 §3.2/§3.3 constrain token, string, display string, and parameter keys to specific character sets and ranges; these validation tests ensure illegal inputs are rejected before serialization.
  group('Validation', () {
    test('rejects invalid keys in parameters', () {
      expect(() => SfParameters({'Invalid': 'x'}), throwsA(isA<SfFormatException>()));
    });

    test('rejects strings with control characters', () {
      expect(() => SfBareItem.string('hi\n'), throwsA(isA<SfFormatException>()));
    });

    test('rejects display strings with unpaired surrogate', () {
      final highSurrogate = String.fromCharCode(0xD800);
      expect(() => SfDisplayString(highSurrogate), throwsA(isA<SfFormatException>()));
    });
  });
}

class _ConversionExpectation {
  const _ConversionExpectation({
    required this.description,
    required this.dartValue,
    required this.expectedType,
    required this.verifyValue,
    required this.expectedSerialization,
  });

  final String description;
  final dynamic dartValue;
  final SfBareItemType expectedType;
  final void Function(SfBareItem) verifyValue;
  final String expectedSerialization;
}
