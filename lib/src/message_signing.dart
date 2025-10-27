import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'structured_fields.dart';

/// Signature algorithms supported by the Approov message signing flow.
enum SignatureAlgorithm {
  hmacSha256,
  ecdsaP256Sha256,
}

SfItem _buildComponentIdentifier(String value, Map<String, dynamic>? parameters) {
  return SfItem.string(value, parameters);
}

String _componentIdentifierValue(SfItem item) {
  final bareItem = item.bareItem;
  if (bareItem.type != SfBareItemType.string) {
    throw StateError('Component identifiers must be sf-string values');
  }
  return bareItem.value as String;
}

/// Holds configuration for message signature parameters, mirroring the Swift implementation.
class SignatureParameters {
  SignatureParameters()
      : _componentIdentifiers = <SfItem>[],
        _parameters = LinkedHashMap<String, SfBareItem>();

  SignatureParameters.copy(SignatureParameters other)
      : _componentIdentifiers = List<SfItem>.from(other._componentIdentifiers),
        _parameters = LinkedHashMap<String, SfBareItem>.from(other._parameters),
        debugMode = other.debugMode,
        algorithm = other.algorithm;

  final List<SfItem> _componentIdentifiers;
  final LinkedHashMap<String, SfBareItem> _parameters;

  bool debugMode = false;
  SignatureAlgorithm algorithm = SignatureAlgorithm.hmacSha256;

  List<SfItem> get componentIdentifiers => List.unmodifiable(_componentIdentifiers);

  void addComponentIdentifier(String identifier, {Map<String, dynamic>? parameters}) {
    final normalized = identifier.startsWith('@') ? identifier : identifier.toLowerCase();
    final candidateParameters = SfParameters(parameters);
    if (_componentIdentifiers.any(
      (item) =>
          _componentIdentifierMatches(item, normalized, candidateParameters),
    )) {
      return;
    }
    _componentIdentifiers.add(_buildComponentIdentifier(normalized, parameters));
  }

  bool _componentIdentifierMatches(SfItem item, String value, SfParameters candidate) {
    if (_componentIdentifierValue(item) != value) return false;
    return _parametersMatch(item.parameters, candidate);
  }

  bool _parametersMatch(SfParameters existing, SfParameters candidate) {
    final existingMap = existing.asMap();
    final candidateMap = candidate.asMap();
    if (existingMap.length != candidateMap.length) return false;
    for (final entry in candidateMap.entries) {
      final existingValue = existingMap[entry.key];
      if (existingValue == null) return false;
      if (existingValue.serialize() != entry.value.serialize()) return false;
    }
    return true;
  }

  void setAlg(String value) {
    _parameters['alg'] = SfBareItem.string(value);
  }

  void setCreated(int timestampSeconds) {
    _parameters['created'] = SfBareItem.integer(timestampSeconds);
  }

  void setExpires(int timestampSeconds) {
    _parameters['expires'] = SfBareItem.integer(timestampSeconds);
  }

  void setKeyId(String keyId) {
    _parameters['keyid'] = SfBareItem.string(keyId);
  }

  void setNonce(String nonce) {
    _parameters['nonce'] = SfBareItem.string(nonce);
  }

  void setTag(String tag) {
    _parameters['tag'] = SfBareItem.string(tag);
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

  SfItem signatureParamsIdentifier() => _buildComponentIdentifier('@signature-params', null);

  String serializeComponentValue() {
    final parameters = _parameters.isEmpty ? null : _parameters;
    return SfInnerList(_componentIdentifiers, parameters).serialize();
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
        final contentLengthValue = context.getComponentValue(SfItem.string('content-length'));
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
        throw StateError('Missing component value for ${_componentIdentifierValue(component)}');
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

  String? getComponentValue(SfItem component) {
    final identifier = _componentIdentifierValue(component);
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
          final paramValue = component.parameters.asMap()['name'];
          if (paramValue == null) {
            throw StateError('Missing name parameter for @query-param');
          }
          if (paramValue.type != SfBareItemType.string) {
            throw StateError('name parameter for @query-param must be an sf-string');
          }
          return _queryParameterValue(paramValue.value as String);
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
      if (required) {
        throw StateError('Body digest required but body is not available');
      }
      return null;
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
