import 'dart:typed_data';

import 'package:approov_service_flutter_httpclient/src/structured_fields.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('SfBareItem serialization', () {
    test('integer encodes without modification', () {
      expect(SfBareItem.integer(42).serialize(), '42');
      expect(SfBareItem.integer(-7).serialize(), '-7');
    });

    test('decimal encodes canonical representation', () {
      expect(SfBareItem.decimal(1.25).serialize(), '1.25');
      expect(SfBareItem.decimal(SfDecimal.parse('-12.340')).serialize(), '-12.34');
    });

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
