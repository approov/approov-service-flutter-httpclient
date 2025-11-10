import 'dart:typed_data';

import 'package:approov_service_flutter_httpclient/src/structured_fields.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('SfBareItem serialization', () {
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
