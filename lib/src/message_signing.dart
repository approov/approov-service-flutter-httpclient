import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Signature algorithms supported by the Approov message signing flow.
enum SignatureAlgorithm {
  hmacSha256,
  ecdsaP256Sha256,
}

/// Represents a HTTP Structured Field string item with optional parameters.
class SfStringItem {
  SfStringItem(this.value, [Map<String, String>? parameters])
      : parameters = LinkedHashMap.of(parameters ?? const {});

  final String value;
  final LinkedHashMap<String, String> parameters;

  String serialize() {
    final buffer = StringBuffer();
    buffer.write(_serializeSfString(value));
    parameters.forEach((key, v) {
      buffer.write(';');
      buffer.write(key);
      buffer.write('=');
      buffer.write(_serializeSfString(v));
    });
    return buffer.toString();
  }
}

/// Holds configuration for message signature parameters, mirroring the Swift implementation.
class SignatureParameters {
  SignatureParameters()
      : _componentIdentifiers = <SfStringItem>[],
        _parameters = LinkedHashMap<String, dynamic>();

  SignatureParameters.copy(SignatureParameters other)
      : _componentIdentifiers = List<SfStringItem>.from(other._componentIdentifiers),
        _parameters = LinkedHashMap<String, dynamic>.of(other._parameters),
        debugMode = other.debugMode,
        algorithm = other.algorithm;

  final List<SfStringItem> _componentIdentifiers;
  final LinkedHashMap<String, dynamic> _parameters;

  bool debugMode = false;
  SignatureAlgorithm algorithm = SignatureAlgorithm.hmacSha256;

  List<SfStringItem> get componentIdentifiers => List.unmodifiable(_componentIdentifiers);

  void addComponentIdentifier(String identifier, {Map<String, String>? parameters}) {
    final normalized = identifier.startsWith('@') ? identifier : identifier.toLowerCase();
    if (_componentIdentifiers.any((item) => item.value == normalized && _parametersMatch(item.parameters, parameters))) {
      return;
    }
    _componentIdentifiers.add(SfStringItem(normalized, parameters));
  }

  bool _parametersMatch(Map<String, String> existing, Map<String, String>? candidate) {
    if (candidate == null || candidate.isEmpty) return existing.isEmpty;
    if (existing.length != candidate.length) return false;
    for (final entry in candidate.entries) {
      if (existing[entry.key] != entry.value) return false;
    }
    return true;
  }

  void setAlg(String value) {
    _parameters['alg'] = value;
  }

  void setCreated(int timestampSeconds) {
    _parameters['created'] = timestampSeconds;
  }

  void setExpires(int timestampSeconds) {
    _parameters['expires'] = timestampSeconds;
  }

  void setKeyId(String keyId) {
    _parameters['keyid'] = keyId;
  }

  void setNonce(String nonce) {
    _parameters['nonce'] = nonce;
  }

  void setTag(String tag) {
    _parameters['tag'] = tag;
  }

  String signatureLabel() {
    switch (algorithm) {
      case SignatureAlgorithm.ecdsaP256Sha256:
        return 'install';
      case SignatureAlgorithm.hmacSha256:
      default:
        return 'account';
    }
  }

  SfStringItem signatureParamsIdentifier() => SfStringItem('@signature-params');

  String serializeComponentValue() {
    final buffer = StringBuffer();
    buffer.write('(');
    for (var i = 0; i < _componentIdentifiers.length; i++) {
      if (i > 0) buffer.write(' ');
      buffer.write(_componentIdentifiers[i].serialize());
    }
    buffer.write(')');
    _parameters.forEach((key, value) {
      buffer.write(';');
      buffer.write(key);
      buffer.write('=');
      buffer.write(_serializeParameter(value));
    });
    return buffer.toString();
  }
}

class SignatureParametersFactory {
  SignatureParametersFactory();

  SignatureParameters? _baseParameters;
  String? _bodyDigestAlgorithm;
  bool _bodyDigestRequired = false;
  bool _useAccountMessageSigning = true;
  bool _addCreated = false;
  int _expiresLifetimeSeconds = 0;
  bool _addApproovTokenHeader = false;
  final List<String> _optionalHeaders = <String>[];
  bool _debugMode = false;

  SignatureParametersFactory setBaseParameters(SignatureParameters base) {
    _baseParameters = SignatureParameters.copy(base);
    return this;
  }

  SignatureParametersFactory setBodyDigestConfig(String? algorithm, {required bool required}) {
    if (algorithm != null &&
        algorithm != SignatureDigest.sha256.identifier &&
        algorithm != SignatureDigest.sha512.identifier) {
      throw ArgumentError('Unsupported body digest algorithm: $algorithm');
    }
    _bodyDigestAlgorithm = algorithm;
    _bodyDigestRequired = required;
    return this;
  }

  SignatureParametersFactory setUseInstallMessageSigning() {
    _useAccountMessageSigning = false;
    return this;
  }

  SignatureParametersFactory setUseAccountMessageSigning() {
    _useAccountMessageSigning = true;
    return this;
  }

  SignatureParametersFactory setAddCreated(bool addCreated) {
    _addCreated = addCreated;
    return this;
  }

  SignatureParametersFactory setExpiresLifetime(int seconds) {
    _expiresLifetimeSeconds = seconds;
    return this;
  }

  SignatureParametersFactory setAddApproovTokenHeader(bool add) {
    _addApproovTokenHeader = add;
    return this;
  }

  SignatureParametersFactory addOptionalHeaders(List<String> headers) {
    for (final header in headers) {
      final normalized = header.toLowerCase();
      if (!_optionalHeaders.contains(normalized)) {
        _optionalHeaders.add(normalized);
      }
    }
    return this;
  }

  SignatureParametersFactory setDebugMode(bool debugMode) {
    _debugMode = debugMode;
    return this;
  }

  SignatureParameters build(ApproovSigningContext context) {
    final params = _baseParameters != null ? SignatureParameters.copy(_baseParameters!) : SignatureParameters();
    params.debugMode = _debugMode;
    params.algorithm = _useAccountMessageSigning ? SignatureAlgorithm.hmacSha256 : SignatureAlgorithm.ecdsaP256Sha256;
    params.setAlg(_useAccountMessageSigning ? 'hmac-sha256' : 'ecdsa-p256-sha256');

    final now = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    if (_addCreated) params.setCreated(now);
    if (_expiresLifetimeSeconds > 0) params.setExpires(now + _expiresLifetimeSeconds);

    if (_addApproovTokenHeader) {
      final tokenHeader = context.tokenHeaderName;
      if (tokenHeader != null && context.hasField(tokenHeader)) {
        params.addComponentIdentifier(tokenHeader);
      }
    }

    for (final header in _optionalHeaders) {
      if (!context.hasField(header)) continue;
      if (header == 'content-length') {
        final hasBodyBytes = context.bodyBytes != null && context.bodyBytes!.isNotEmpty;
        final contentLengthValue = context.getComponentValue(SfStringItem('content-length'));
        final shouldIncludeContentLength =
            hasBodyBytes || (contentLengthValue != null && contentLengthValue.trim() != '0');
        if (!shouldIncludeContentLength) {
          // Dart's HttpClient drops an automatic "Content-Length: 0" header for GETs,
          // so skip signing it to keep the canonical representation aligned with the
          // transmitted request.
          continue;
        }
      }
      params.addComponentIdentifier(header);
    }

    if (_bodyDigestAlgorithm != null) {
      final digestHeader =
          context.ensureContentDigest(SignatureDigest.fromIdentifier(_bodyDigestAlgorithm!), required: _bodyDigestRequired);
      if (digestHeader != null) {
        params.addComponentIdentifier('content-digest');
      }
    }

    return params;
  }

  static SignatureParametersFactory generateDefaultFactory({SignatureParameters? overrideBase}) {
    final base = overrideBase ??
        (SignatureParameters()
          ..addComponentIdentifier('@method')
          ..addComponentIdentifier('@target-uri'));
    return SignatureParametersFactory()
        .setBaseParameters(base)
        .setUseInstallMessageSigning()
        .setAddCreated(true)
        .setExpiresLifetime(15)
        .setAddApproovTokenHeader(true)
        .addOptionalHeaders(const ['authorization', 'content-length', 'content-type'])
        .setBodyDigestConfig(SignatureDigest.sha256.identifier, required: false);
  }
}

class SignatureBaseBuilder {
  SignatureBaseBuilder(this.params, this.context);

  final SignatureParameters params;
  final ApproovSigningContext context;

  String createSignatureBase() {
    final buffer = StringBuffer();
    for (final component in params.componentIdentifiers) {
      final value = context.getComponentValue(component);
      if (value == null) {
        throw StateError('Missing component value for ${component.value}');
      }
      buffer.write(component.serialize());
      buffer.write(': ');
      buffer.writeln(value);
    }
    final signatureParamsItem = params.signatureParamsIdentifier();
    buffer.write(signatureParamsItem.serialize());
    buffer.write(': ');
    buffer.write(params.serializeComponentValue());
    return buffer.toString();
  }
}

enum SignatureDigest {
  sha256('sha-256'),
  sha512('sha-512');

  const SignatureDigest(this.identifier);
  final String identifier;

  static SignatureDigest fromIdentifier(String id) {
    return SignatureDigest.values.firstWhere(
      (value) => value.identifier == id,
      orElse: () => throw ArgumentError('Unsupported digest identifier: $id'),
    );
  }
}

class ApproovSigningContext {
  ApproovSigningContext({
    required this.requestMethod,
    required this.uri,
    required Map<String, List<String>> headers,
    required this.bodyBytes,
    required this.tokenHeaderName,
    this.onSetHeader,
    this.onAddHeader,
  }) : _headers = LinkedHashMap<String, List<String>>.fromEntries(
            headers.entries.map((entry) => MapEntry(entry.key.toLowerCase(), List<String>.from(entry.value))));

  final String requestMethod;
  final Uri uri;
  final Uint8List? bodyBytes;
  final String? tokenHeaderName;
  final LinkedHashMap<String, List<String>> _headers;

  final void Function(String name, String value)? onSetHeader;
  final void Function(String name, String value)? onAddHeader;

  bool hasField(String name) => _headers.containsKey(name.toLowerCase());

  void setHeader(String name, String value) {
    _headers[name.toLowerCase()] = <String>[value];
    onSetHeader?.call(name, value);
  }

  void addHeader(String name, String value) {
    _headers.putIfAbsent(name.toLowerCase(), () => <String>[]).add(value);
    onAddHeader?.call(name, value);
  }

  String? getComponentValue(SfStringItem component) {
    final identifier = component.value;
    if (identifier.startsWith('@')) {
      switch (identifier) {
        case '@method':
          return requestMethod.toUpperCase();
        case '@authority':
          return _authority();
        case '@scheme':
          return uri.scheme;
        case '@target-uri':
          return uri.toString();
        case '@request-target':
          return _requestTarget();
        case '@path':
          return uri.path.isEmpty ? '/' : uri.path;
        case '@query':
          return uri.hasQuery ? uri.query : '';
        case '@query-param':
          final name = component.parameters['name'];
          if (name == null) {
            throw StateError('Missing name parameter for @query-param');
          }
          return _queryParameterValue(name);
        default:
          throw StateError('Unknown derived component: $identifier');
      }
    } else {
      final values = _headers[identifier.toLowerCase()];
      if (values == null || values.isEmpty) return null;
      return _combineFieldValues(values);
    }
  }

  String? ensureContentDigest(SignatureDigest digest, {required bool required}) {
    if (bodyBytes == null) {
      return required ? throw StateError('Body digest required but body is not available') : null;
    }
    final bytes = switch (digest) {
      SignatureDigest.sha256 => sha256.convert(bodyBytes!).bytes,
      SignatureDigest.sha512 => sha512.convert(bodyBytes!).bytes,
    };
    final headerValue = '${digest.identifier}=:${base64Encode(bytes)}:';
    setHeader('Content-Digest', headerValue);
    return headerValue;
  }

  String _authority() {
    if ((uri.scheme == 'http' && uri.port == 80) || (uri.scheme == 'https' && uri.port == 443) || (uri.port == 0)) {
      return uri.host;
    }
    return '${uri.host}:${uri.port}';
  }

  String _requestTarget() {
    final path = uri.path.isEmpty ? '/' : uri.path;
    if (!uri.hasQuery) return path;
    return '$path?${uri.query}';
  }

  String? _queryParameterValue(String name) {
    final values = uri.queryParametersAll[name];
    if (values == null) return null;
    if (values.length > 1) return null;
    return values.isEmpty ? '' : values.first;
  }

  String _combineFieldValues(List<String> values) {
    final cleaned = values.map((value) {
      final trimmed = value.trim();
      return trimmed.replaceAll(RegExp(r'\s*\r\n\s*'), ' ');
    }).toList();
    return cleaned.join(', ');
  }

  Map<String, List<String>> snapshotHeaders() => LinkedHashMap.of(_headers);
}

class ApproovMessageSigning {
  SignatureParametersFactory? _defaultFactory;
  final Map<String, SignatureParametersFactory> _hostFactories = {};

  ApproovMessageSigning setDefaultFactory(SignatureParametersFactory factory) {
    _defaultFactory = factory;
    return this;
  }

  ApproovMessageSigning putHostFactory(String host, SignatureParametersFactory factory) {
    _hostFactories[host] = factory;
    return this;
  }

  SignatureParametersFactory? _factoryForHost(String host) {
    return _hostFactories[host] ?? _defaultFactory;
  }

  SignatureParameters? buildParametersFor(Uri uri, ApproovSigningContext context) {
    final factory = _factoryForHost(uri.host);
    if (factory == null) return null;
    return factory.build(context);
  }
}

String _serializeParameter(dynamic value) {
  if (value is String) {
    return _serializeSfString(value);
  } else if (value is int) {
    return value.toString();
  } else if (value is bool) {
    return value ? '?1' : '?0';
  } else if (value is Uint8List) {
    return ':${base64Encode(value)}:';
  } else {
    throw ArgumentError('Unsupported parameter type: ${value.runtimeType}');
  }
}

String _serializeSfString(String value) {
  final escaped = value.replaceAll('\\', r'\\').replaceAll('"', r'\"');
  return '"$escaped"';
}
