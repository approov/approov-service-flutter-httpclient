import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:approov_service_flutter_httpclient/src/structured_fields.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const fixturesRoot = 'test/third_party/structured_field_tests';
  final rootDirectory = Directory(fixturesRoot);
  if (!rootDirectory.existsSync()) {
    fail(
      'Expected Structured Field fixtures to be checked out at $fixturesRoot. '
      'Run the test preparation script before executing this suite.',
    );
  }

  final conformanceFiles = _collectFixtureFiles(rootDirectory, includeSerialisationTests: false);
  group('Structured Field canonical serialization', () {
    for (final file in conformanceFiles) {
      final relativePath = file.path.substring(rootDirectory.path.length + 1);
      final records = _loadRecords(file);
      group(relativePath, () {
        for (final record in records) {
          final headerType = record.headerType;
          if (record.mustFail || record.expected == null) {
            continue;
          }
          final expectedValue = _expectedSerializedValue(record);
          if (expectedValue == null) {
            test(
              record.name,
              () {},
              skip: 'Canonical form spans multiple header lines; serializer emits single values.',
            );
            continue;
          }
          test(record.name, () {
            final structure = _buildStructure(headerType, record.expected!);
            final serialized = _serializeStructure(headerType, structure);
            expect(serialized, expectedValue);
          });
        }
      });
    }
  });

  final serializationFiles = _collectFixtureFiles(rootDirectory, includeSerialisationTests: true)
      .where((file) => file.path.contains('${Platform.pathSeparator}serialisation-tests${Platform.pathSeparator}'))
      .toList();

  group('Structured Field serialization edge cases', () {
    for (final file in serializationFiles) {
      final relativePath = file.path.substring(rootDirectory.path.length + 1);
      final records = _loadRecords(file);
      group(relativePath, () {
        for (final record in records) {
          if (record.expected == null) continue;
          final expectedValue = _expectedSerializedValue(record);
          test(record.name, () {
            final buildStructure = () => _buildStructure(record.headerType, record.expected!);
            if (record.mustFail) {
              expect(buildStructure, throwsA(isA<SfFormatException>()));
              return;
            }
            final structure = buildStructure();
            final serialized = _serializeStructure(record.headerType, structure);
            expect(serialized, expectedValue ?? '', reason: 'Missing canonical/raw fallback.');
          });
        }
      });
    }
  });
}

class _FixtureRecord {
  _FixtureRecord(this.name, this.headerType, this.expected, this.mustFail, this.canFail,
      this.rawValues, this.canonicalValues);

  final String name;
  final String headerType;
  final dynamic expected;
  final bool mustFail;
  final bool canFail;
  final List<String>? rawValues;
  final List<String>? canonicalValues;
}

List<_FixtureRecord> _loadRecords(File file) {
  final json = jsonDecode(file.readAsStringSync()) as List<dynamic>;
  return json.map((dynamic entry) {
    final map = entry as Map<String, dynamic>;
    return _FixtureRecord(
      map['name'] as String? ?? file.path,
      map['header_type'] as String? ?? 'item',
      map['expected'],
      map['must_fail'] == true,
      map['can_fail'] == true,
      (map['raw'] as List?)?.cast<String>(),
      (map['canonical'] as List?)?.cast<String>(),
    );
  }).toList();
}

List<File> _collectFixtureFiles(Directory root, {required bool includeSerialisationTests}) {
  final files = <File>[];
  for (final entity in root.listSync(recursive: true)) {
    if (entity is! File || !entity.path.endsWith('.json')) continue;
    final isSerialisationTest = entity.path.contains('${Platform.pathSeparator}serialisation-tests${Platform.pathSeparator}');
    final isSchemaFile = entity.path.contains('${Platform.pathSeparator}schema${Platform.pathSeparator}');
    if (isSchemaFile) continue;
    if (!includeSerialisationTests && isSerialisationTest) continue;
    files.add(entity);
  }
  files.sort((a, b) => a.path.compareTo(b.path));
  return files;
}

String? _expectedSerializedValue(_FixtureRecord record) {
  final values = record.canonicalValues ?? record.rawValues;
  if (values == null) return null;
  if (values.isEmpty) return '';
  if (values.length == 1) return values.first;
  // Multiple header field lines collapse into a comma-separated representation for comparison.
  return values.join(', ');
}

Object _buildStructure(String headerType, dynamic expected) {
  switch (headerType.toLowerCase()) {
    case 'item':
      return _itemFromJson(expected as List<dynamic>);
    case 'list':
      return _listFromJson(expected as List<dynamic>);
    case 'dictionary':
      return _dictionaryFromJson(expected as List<dynamic>);
    default:
      throw ArgumentError('Unsupported header type: $headerType');
  }
}

String _serializeStructure(String headerType, Object structure) {
  switch (headerType.toLowerCase()) {
    case 'item':
      return (structure as SfItem).serialize();
    case 'list':
      return (structure as SfList).serialize();
    case 'dictionary':
      return (structure as SfDictionary).serialize();
    default:
      throw ArgumentError('Unsupported header type: $headerType');
  }
}

SfItem _itemFromJson(List<dynamic> json) {
  if (json.length != 2) {
    throw ArgumentError('Invalid SfItem representation: $json');
  }
  final bare = _bareItemFromJson(json[0]);
  final params = _parametersFromJson(json[1] as List<dynamic>?);
  return SfItem(bare, params.isEmpty ? null : params);
}

SfList _listFromJson(List<dynamic> json) {
  final members = <SfListMember>[];
  for (final entry in json) {
    if (entry is List && entry.length == 2 && entry[0] is List) {
      members.add(SfListMember.innerList(_innerListFromJson(entry)));
    } else if (entry is List) {
      members.add(SfListMember.item(_itemFromJson(entry)));
    } else {
      throw ArgumentError('Invalid list member: $entry');
    }
  }
  return SfList(members);
}

SfInnerList _innerListFromJson(List<dynamic> json) {
  if (json.length != 2) {
    throw ArgumentError('Invalid inner list representation: $json');
  }
  final itemsList = json[0] as List<dynamic>;
  final items = itemsList.map((dynamic entry) => _itemFromJson(entry as List<dynamic>)).toList();
  final params = _parametersFromJson(json[1] as List<dynamic>?);
  return SfInnerList(items, params.isEmpty ? null : params);
}

SfDictionary _dictionaryFromJson(List<dynamic> json) {
  final entries = LinkedHashMap<String, SfDictionaryMember>();
  for (final entry in json) {
    if (entry is! List || entry.length != 2) {
      throw ArgumentError('Invalid dictionary entry: $entry');
    }
    final key = entry[0] as String;
    final value = entry[1] as List<dynamic>;
    entries[key] = _dictionaryMemberFromJson(value);
  }
  return SfDictionary(entries);
}

SfDictionaryMember _dictionaryMemberFromJson(List<dynamic> json) {
  if (json.length != 2) {
    throw ArgumentError('Invalid dictionary member: $json');
  }
  final value = json[0];
  if (value is List) {
    return SfDictionaryMember.innerList(_innerListFromJson(json));
  }
  final params = _parametersFromJson(json[1] as List<dynamic>?);
  if (value == true) {
    return SfDictionaryMember.booleanTrue(params.isEmpty ? null : params);
  }
  final item = _itemFromJson(json);
  return SfDictionaryMember.item(item);
}

Map<String, SfBareItem> _parametersFromJson(List<dynamic>? json) {
  if (json == null || json.isEmpty) {
    return const <String, SfBareItem>{};
  }
  final map = <String, SfBareItem>{};
  for (final entry in json) {
    if (entry is! List || entry.length != 2) {
      throw ArgumentError('Invalid parameter entry: $entry');
    }
    final key = entry[0] as String;
    final value = _bareItemFromJson(entry[1]);
    map[key] = value;
  }
  return map;
}

SfBareItem _bareItemFromJson(dynamic json) {
  if (json is SfBareItem) return json;
  if (json is int) return SfBareItem.integer(json);
  if (json is double) return SfBareItem.decimal(json);
  if (json is bool) return SfBareItem.boolean(json);
  if (json is String) return SfBareItem.string(json);
  if (json is Map<String, dynamic>) {
    switch (json['__type']) {
      case 'token':
        return SfBareItem.token(SfToken(json['value'] as String));
      case 'binary':
        return SfBareItem.byteSequence(_decodeBase32(json['value'] as String));
      case 'date':
        return SfBareItem.date(json['value'] as int);
      case 'displaystring':
        return SfBareItem.displayString(SfDisplayString(json['value'] as String));
    }
  }
  throw ArgumentError('Unsupported bare item representation: $json');
}

const _base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
final Map<int, int> _base32Lookup = <int, int>{
  for (var i = 0; i < _base32Alphabet.length; i++)
    _base32Alphabet.codeUnitAt(i): i,
};

Uint8List _decodeBase32(String input) {
  final sanitized = input.replaceAll('=', '').toUpperCase();
  var bits = 0;
  var value = 0;
  final output = <int>[];
  for (final unit in sanitized.codeUnits) {
    final digit = _base32Lookup[unit];
    if (digit == null) {
      throw SfFormatException('Invalid base32 character: ${String.fromCharCode(unit)}');
    }
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.add((value >> bits) & 0xff);
    }
  }
  return Uint8List.fromList(output);
}
