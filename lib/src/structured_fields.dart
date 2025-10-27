import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

/// Exception thrown when Structured Field values fail validation.
class SfFormatException extends FormatException {
  SfFormatException(String message, [dynamic source])
      : super(message, source);
}

enum _CharType { alphaLower, alphaUpper, digit }

bool _isLowerAlpha(int codeUnit) =>
    codeUnit >= 0x61 && codeUnit <= 0x7a; // a-z

bool _isUpperAlpha(int codeUnit) =>
    codeUnit >= 0x41 && codeUnit <= 0x5a; // A-Z

bool _isAlpha(int codeUnit) => _isLowerAlpha(codeUnit) || _isUpperAlpha(codeUnit);

bool _isDigit(int codeUnit) => codeUnit >= 0x30 && codeUnit <= 0x39;

bool _isTchar(int codeUnit) {
  if (_isAlpha(codeUnit) || _isDigit(codeUnit)) return true;
  const allowed = {
    0x21, // !
    0x23, // #
    0x24, // $
    0x25, // %
    0x26, // &
    0x27, // '
    0x2a, // *
    0x2b, // +
    0x2d, // -
    0x2e, // .
    0x5e, // ^
    0x5f, // _
    0x60, // `
    0x7c, // |
    0x7e, // ~
  };
  return allowed.contains(codeUnit);
}

void _validateKey(String key) {
  if (key.isEmpty) {
    throw SfFormatException('Structured Field parameter and dictionary keys must not be empty');
  }
  final codeUnits = key.codeUnits;
  for (var index = 0; index < codeUnits.length; index++) {
    final unit = codeUnits[index];
    final isValid = index == 0
        ? (unit == 0x2a /* * */ || _isLowerAlpha(unit))
        : (_isLowerAlpha(unit) || _isDigit(unit) || unit == 0x5f /* _ */ || unit == 0x2d /* - */ || unit == 0x2e /* . */ || unit == 0x2a /* * */);
    if (!isValid) {
      throw SfFormatException('Invalid character "${String.fromCharCode(unit)}" in key "$key" at position $index');
    }
  }
}

void _validateString(String value) {
  for (var index = 0; index < value.length; index++) {
    final unit = value.codeUnitAt(index);
    if (unit < 0x20 || unit == 0x7f || unit > 0x7f) {
      throw SfFormatException(
        'Invalid character 0x${unit.toRadixString(16).padLeft(2, '0')} in sf-string at position $index',
      );
    }
  }
}

void _validateToken(String value) {
  if (value.isEmpty) {
    throw SfFormatException('sf-token must not be empty');
  }
  final codeUnits = value.codeUnits;
  for (var index = 0; index < codeUnits.length; index++) {
    final unit = codeUnits[index];
    final isValid = index == 0
        ? (_isAlpha(unit) || unit == 0x2a /* * */)
        : (_isTchar(unit) || unit == 0x3a /* : */ || unit == 0x2f /* / */);
    if (!isValid) {
      throw SfFormatException(
        'Invalid character "${String.fromCharCode(unit)}" in sf-token "$value" at position $index',
      );
    }
  }
}

void _validateDisplayString(String value) {
  for (final rune in value.runes) {
    if (rune >= 0xd800 && rune <= 0xdfff) {
      throw SfFormatException('Display strings must not contain surrogate code points');
    }
    if (rune < 0x0 || rune > 0x10ffff) {
      throw SfFormatException('Invalid Unicode scalar value 0x${rune.toRadixString(16)} in display string');
    }
  }
}

/// Represents an sf-token value.
class SfToken {
  SfToken(String value) : value = value {
    _validateToken(value);
  }

  final String value;
}

/// Represents a display string bare item.
class SfDisplayString {
  SfDisplayString(String value) : value = value {
    _validateDisplayString(value);
  }

  final String value;
}

/// Represents a decimal bare item using a fixed three-digit scale.
class SfDecimal {
  SfDecimal._(this._scaledValue);

  factory SfDecimal.fromNum(num value) {
    final scaled = value * 1000;
    final rounded = scaled.round();
    if ((scaled - rounded).abs() > 1e-9) {
      throw SfFormatException('Decimals must have at most three fractional digits: $value');
    }
    return SfDecimal._checked(rounded);
  }

  factory SfDecimal.parse(String value) {
    if (!RegExp(r'^-?[0-9]{1,12}\.[0-9]{1,3}$').hasMatch(value)) {
      throw SfFormatException('Invalid decimal format: $value');
    }
    final negative = value.startsWith('-');
    final parts = value.substring(negative ? 1 : 0).split('.');
    final integral = int.parse(parts[0]);
    final fractional = int.parse(parts[1].padRight(3, '0'));
    final scaled = (integral * 1000 + fractional) * (negative ? -1 : 1);
    return SfDecimal._checked(scaled);
  }

  static SfDecimal _checked(int scaled) {
    const max = 999999999999999;
    if (scaled.abs() > max) {
      throw SfFormatException('Decimal magnitude exceeds allowed range');
    }
    return SfDecimal._(scaled);
  }

  final int _scaledValue;

  int get scaledValue => _scaledValue;

  double toDouble() => _scaledValue / 1000.0;

  @override
  String toString() {
    final sign = _scaledValue < 0 ? '-' : '';
    final absValue = _scaledValue.abs();
    final integral = absValue ~/ 1000;
    var fractional = (absValue % 1000).toString().padLeft(3, '0');
    while (fractional.length > 1 && fractional.endsWith('0')) {
      fractional = fractional.substring(0, fractional.length - 1);
    }
    return '$sign$integral.$fractional';
  }
}

/// Represents a Date bare item storing seconds since Unix epoch.
class SfDate {
  SfDate.fromSeconds(int seconds) : seconds = seconds {
    _validateRange(seconds);
  }

  factory SfDate.fromDateTime(DateTime dateTime) {
    final utc = dateTime.toUtc();
    final seconds = utc.millisecondsSinceEpoch ~/ 1000;
    return SfDate.fromSeconds(seconds);
  }

  final int seconds;

  DateTime toUtcDateTime() => DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);

  static void _validateRange(int seconds) {
    const min = -62135596800; // year 0001
    const max = 253402214400; // year 9999
    if (seconds < min || seconds > max) {
      throw SfFormatException('Date value $seconds is outside the supported range');
    }
  }
}

/// Enumeration of bare item types.
enum SfBareItemType {
  integer,
  decimal,
  string,
  token,
  byteSequence,
  boolean,
  date,
  displayString,
}

/// Represents a bare item per RFC 9651.
class SfBareItem {
  const SfBareItem._(this.type, this.value);

  factory SfBareItem.integer(int value) {
    const min = -999999999999999;
    const max = 999999999999999;
    if (value < min || value > max) {
      throw SfFormatException('Integer magnitude exceeds allowed range: $value');
    }
    return SfBareItem._(SfBareItemType.integer, value);
  }

  factory SfBareItem.decimal(dynamic value) {
    if (value is SfDecimal) {
      return SfBareItem._(SfBareItemType.decimal, value);
    } else if (value is num) {
      return SfBareItem._(SfBareItemType.decimal, SfDecimal.fromNum(value));
    } else if (value is String) {
      return SfBareItem._(SfBareItemType.decimal, SfDecimal.parse(value));
    }
    throw SfFormatException('Unsupported value for decimal bare item: ${value.runtimeType}');
  }

  factory SfBareItem.string(String value) {
    _validateString(value);
    return SfBareItem._(SfBareItemType.string, value);
  }

  factory SfBareItem.token(SfToken token) =>
      SfBareItem._(SfBareItemType.token, token.value);

  factory SfBareItem.byteSequence(Uint8List value) =>
      SfBareItem._(SfBareItemType.byteSequence, Uint8List.fromList(value));

  factory SfBareItem.boolean(bool value) =>
      SfBareItem._(SfBareItemType.boolean, value);

  factory SfBareItem.date(dynamic value) {
    if (value is SfDate) {
      return SfBareItem._(SfBareItemType.date, value);
    } else if (value is DateTime) {
      return SfBareItem._(SfBareItemType.date, SfDate.fromDateTime(value));
    } else if (value is int) {
      return SfBareItem._(SfBareItemType.date, SfDate.fromSeconds(value));
    }
    throw SfFormatException('Unsupported value for date bare item: ${value.runtimeType}');
  }

  factory SfBareItem.displayString(SfDisplayString value) =>
      SfBareItem._(SfBareItemType.displayString, value);

  factory SfBareItem.fromDynamic(dynamic value) {
    if (value is SfBareItem) return value;
    if (value is bool) return SfBareItem.boolean(value);
    if (value is int) return SfBareItem.integer(value);
    if (value is SfDecimal || value is num || value is String && value.contains('.')) {
      try {
        return SfBareItem.decimal(value);
      } on SfFormatException {
        if (value is String) {
          return SfBareItem.string(value);
        }
        rethrow;
      }
    }
    if (value is SfToken) return SfBareItem.token(value);
    if (value is SfDisplayString) return SfBareItem.displayString(value);
    if (value is Uint8List) return SfBareItem.byteSequence(value);
    if (value is List<int>) return SfBareItem.byteSequence(Uint8List.fromList(value));
    if (value is DateTime || value is SfDate) {
      return SfBareItem.date(value);
    }
    if (value is String) return SfBareItem.string(value);
    throw SfFormatException('Unsupported value for bare item: ${value.runtimeType}');
  }

  final SfBareItemType type;
  final Object value;

  bool get isBooleanTrue => type == SfBareItemType.boolean && value == true;

  void serializeTo(StringBuffer buffer) {
    switch (type) {
      case SfBareItemType.integer:
        buffer.write(value as int);
      case SfBareItemType.decimal:
        buffer.write((value as SfDecimal).toString());
      case SfBareItemType.string:
        buffer.write('"');
        final stringValue = value as String;
        for (var index = 0; index < stringValue.length; index++) {
          final char = stringValue[index];
          if (char == '\\' || char == '"') {
            buffer.write('\\');
          }
          buffer.write(char);
        }
        buffer.write('"');
      case SfBareItemType.token:
        buffer.write(value as String);
      case SfBareItemType.byteSequence:
        buffer
          ..write(':')
          ..write(base64Encode(value as Uint8List))
          ..write(':');
      case SfBareItemType.boolean:
        buffer.write((value as bool) ? '?1' : '?0');
      case SfBareItemType.date:
        buffer
          ..write('@')
          ..write((value as SfDate).seconds.toString());
      case SfBareItemType.displayString:
        buffer.write(_encodeDisplayString(value as SfDisplayString));
    }
  }

  String serialize() {
    final buffer = StringBuffer();
    serializeTo(buffer);
    return buffer.toString();
  }

  static String _encodeDisplayString(SfDisplayString display) {
    final buffer = StringBuffer()..write('%"');
    final bytes = utf8.encode(display.value);
    for (final byte in bytes) {
      if (byte == 0x25 || byte == 0x22 || byte < 0x20 || byte > 0x7e) {
        buffer
          ..write('%')
          ..write(byte.toRadixString(16).padLeft(2, '0'));
      } else {
        buffer.write(String.fromCharCode(byte));
      }
    }
    buffer.write('"');
    return buffer.toString();
  }
}

/// Represents the parameters attached to an Item or Inner List.
class SfParameters {
  SfParameters._(this._entries);

  factory SfParameters([Map<String, dynamic>? entries]) {
    if (entries == null || entries.isEmpty) {
      return SfParameters._(UnmodifiableMapView<String, SfBareItem>(LinkedHashMap()));
    }
    final map = LinkedHashMap<String, SfBareItem>();
    entries.forEach((key, value) {
      _validateKey(key);
      map[key] = SfBareItem.fromDynamic(value);
    });
    return SfParameters._(UnmodifiableMapView<String, SfBareItem>(map));
  }

  final Map<String, SfBareItem> _entries;

  bool get isEmpty => _entries.isEmpty;

  Map<String, SfBareItem> asMap() => _entries;

  void serializeTo(StringBuffer buffer) {
    _entries.forEach((key, value) {
      buffer
        ..write(';')
        ..write(key);
      if (!value.isBooleanTrue) {
        buffer.write('=');
        value.serializeTo(buffer);
      }
    });
  }
}

/// Represents an sf-item.
class SfItem {
  SfItem(this.bareItem, [Map<String, dynamic>? parameters])
      : parameters = SfParameters(parameters);

  factory SfItem.string(String value, [Map<String, dynamic>? parameters]) =>
      SfItem(SfBareItem.string(value), parameters);

  factory SfItem.token(String value, [Map<String, dynamic>? parameters]) =>
      SfItem(SfBareItem.token(SfToken(value)), parameters);

  factory SfItem.boolean(bool value, [Map<String, dynamic>? parameters]) =>
      SfItem(SfBareItem.boolean(value), parameters);

  factory SfItem.integer(int value, [Map<String, dynamic>? parameters]) =>
      SfItem(SfBareItem.integer(value), parameters);

  factory SfItem.decimal(dynamic value, [Map<String, dynamic>? parameters]) =>
      SfItem(SfBareItem.decimal(value), parameters);

  factory SfItem.byteSequence(Uint8List value, [Map<String, dynamic>? parameters]) =>
      SfItem(SfBareItem.byteSequence(value), parameters);

  factory SfItem.date(dynamic value, [Map<String, dynamic>? parameters]) =>
      SfItem(SfBareItem.date(value), parameters);

  factory SfItem.displayString(String value, [Map<String, dynamic>? parameters]) =>
      SfItem(SfBareItem.displayString(SfDisplayString(value)), parameters);

  final SfBareItem bareItem;
  final SfParameters parameters;

  void serializeTo(StringBuffer buffer) {
    bareItem.serializeTo(buffer);
    parameters.serializeTo(buffer);
  }

  String serialize() {
    final buffer = StringBuffer();
    serializeTo(buffer);
    return buffer.toString();
  }
}

/// Represents an inner list per RFC 9651.
class SfInnerList {
  SfInnerList(List<SfItem> items, [Map<String, dynamic>? parameters])
      : items = List<SfItem>.unmodifiable(items),
        parameters = SfParameters(parameters);

  final List<SfItem> items;
  final SfParameters parameters;

  void serializeTo(StringBuffer buffer) {
    buffer.write('(');
    for (var index = 0; index < items.length; index++) {
      if (index > 0) buffer.write(' ');
      items[index].serializeTo(buffer);
    }
    buffer.write(')');
    parameters.serializeTo(buffer);
  }

  String serialize() {
    final buffer = StringBuffer();
    serializeTo(buffer);
    return buffer.toString();
  }
}

/// Represents a list member (either an Item or inner list).
class SfListMember {
  SfListMember.item(SfItem item)
      : item = item,
        innerList = null;

  SfListMember.innerList(SfInnerList innerList)
      : item = null,
        innerList = innerList;

  final SfItem? item;
  final SfInnerList? innerList;

  void serializeTo(StringBuffer buffer) {
    if (item != null) {
      item!.serializeTo(buffer);
    } else {
      innerList!.serializeTo(buffer);
    }
  }
}

/// Represents an sf-list.
class SfList {
  SfList(List<SfListMember> members)
      : members = List<SfListMember>.unmodifiable(members);

  final List<SfListMember> members;

  String serialize() {
    final buffer = StringBuffer();
    for (var index = 0; index < members.length; index++) {
      if (index > 0) buffer.write(', ');
      members[index].serializeTo(buffer);
    }
    return buffer.toString();
  }
}

/// Represents a dictionary member that can be either a value or boolean true with parameters.
class SfDictionaryMember {
  SfDictionaryMember.booleanTrue([Map<String, dynamic>? parameters])
      : item = null,
        innerList = null,
        parameters = SfParameters(parameters);

  SfDictionaryMember.item(SfItem item)
      : item = item,
        innerList = null,
        parameters = null;

  SfDictionaryMember.innerList(SfInnerList innerList)
      : item = null,
        innerList = innerList,
        parameters = null;

  final SfItem? item;
  final SfInnerList? innerList;
  final SfParameters? parameters;

  void serializeTo(StringBuffer buffer) {
    if (item != null) {
      buffer.write('=');
      item!.serializeTo(buffer);
    } else if (innerList != null) {
      buffer.write('=');
      innerList!.serializeTo(buffer);
    } else if (parameters != null && !parameters!.isEmpty) {
      parameters!.serializeTo(buffer);
    }
  }
}

/// Represents an sf-dictionary.
class SfDictionary {
  SfDictionary(Map<String, SfDictionaryMember> entries)
      : _entries = UnmodifiableMapView<String, SfDictionaryMember>(
            LinkedHashMap.fromEntries(entries.entries.map((entry) {
          _validateKey(entry.key);
          return MapEntry(entry.key, entry.value);
        })));

  final Map<String, SfDictionaryMember> _entries;

  Map<String, SfDictionaryMember> asMap() => _entries;

  String serialize() {
    final buffer = StringBuffer();
    var index = 0;
    _entries.forEach((key, member) {
      if (index > 0) buffer.write(', ');
      buffer.write(key);
      member.serializeTo(buffer);
      index++;
    });
    return buffer.toString();
  }
}
