import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'structured_fields.dart';

/// Builds a component identifier item with optional Structured Fields parameters.
SfItem _buildComponentIdentifier(
    String value, Map<String, dynamic>? parameters) {
  return SfItem.string(value, parameters);
}

/// Extracts the string value from a Structured Field component identifier.
String _componentIdentifierValue(SfItem item) {
  final bareItem = item.bareItem;
  if (bareItem.type != SfBareItemType.string) {
    throw StateError('Component identifiers must be sf-string values');
  }
  return bareItem.value as String;
}

/// Holds configuration for message signature parameters, mirroring the Swift implementation.
class SignatureParameters {
  /// Creates an empty set of signature parameters.
  SignatureParameters()
      : _componentIdentifiers = <SfItem>[],
        _parameters = LinkedHashMap<String, SfBareItem>();

  /// Creates a deep copy of another `SignatureParameters` instance.
  SignatureParameters.copy(SignatureParameters other)
      : _componentIdentifiers = List<SfItem>.from(other._componentIdentifiers),
        _parameters = LinkedHashMap<String, SfBareItem>.from(other._parameters),
        debugMode = other.debugMode;

  final List<SfItem> _componentIdentifiers;
  final LinkedHashMap<String, SfBareItem> _parameters;

  bool debugMode = false;

  /// Returns the configured signing algorithm identifier (`alg` parameter), if any.
  String? get algorithmIdentifier {
    final algItem = _parameters['alg'];
    if (algItem == null) return null;
    if (algItem.type != SfBareItemType.string) {
      throw StateError('alg parameter must be an sf-string');
    }
    return algItem.value as String;
  }

  /// The ordered list of Structured Field components that will be signed.
  List<SfItem> get componentIdentifiers =>
      List.unmodifiable(_componentIdentifiers);

  /// Adds a component identifier to the signature, avoiding duplicates.
  void addComponentIdentifier(String identifier,
      {Map<String, dynamic>? parameters}) {
    final normalized =
        identifier.startsWith('@') ? identifier : identifier.toLowerCase();
    final candidateParameters = SfParameters(parameters);
    // Skip adding duplicate component identifiers that only differ in letter case or parameter identity.
    if (_componentIdentifiers.any(
      (item) =>
          _componentIdentifierMatches(item, normalized, candidateParameters),
    )) {
      return;
    }
    _componentIdentifiers
        .add(_buildComponentIdentifier(normalized, parameters));
  }

  /// Returns whether the candidate `SfItem` matches an existing component.
  bool _componentIdentifierMatches(
      SfItem item, String value, SfParameters candidate) {
    if (_componentIdentifierValue(item) != value) return false;
    return _parametersMatch(item.parameters, candidate);
  }

  /// Compares two Structured Field parameter sets for equality.
  bool _parametersMatch(SfParameters existing, SfParameters candidate) {
    final existingMap = existing.asMap();
    final candidateMap = candidate.asMap();
    // Structured Field parameters are only equal when both name and serialized value match.
    if (existingMap.length != candidateMap.length) return false;
    for (final entry in candidateMap.entries) {
      final existingValue = existingMap[entry.key];
      if (existingValue == null) return false;
      if (existingValue.serialize() != entry.value.serialize()) return false;
    }
    return true;
  }

  /// Sets the `alg` parameter that advertises the signing algorithm. hmac-sha256 / ecdsa-p256-sha256
  void setAlg(String value) {
    _parameters['alg'] = SfBareItem.string(value);
  }

  /// Records the `created` timestamp parameter in seconds.
  void setCreated(int timestampSeconds) {
    _parameters['created'] = SfBareItem.integer(timestampSeconds);
  }

  /// Records the `expires` timestamp parameter in seconds.
  void setExpires(int timestampSeconds) {
    _parameters['expires'] = SfBareItem.integer(timestampSeconds);
  }

  /// Sets the `keyid` parameter to identify the signing key.
  void setKeyId(String keyId) {
    _parameters['keyid'] = SfBareItem.string(keyId);
  }

  /// Sets the `nonce` parameter used for replay protection.
  void setNonce(String nonce) {
    _parameters['nonce'] = SfBareItem.string(nonce);
  }

  /// Sets the optional `tag` parameter carried with the signature.
  void setTag(String tag) {
    _parameters['tag'] = SfBareItem.string(tag);
  }

  /// Returns the Structured Field identifier used for the `Signature-Params` entry.
  SfItem signatureParamsIdentifier() =>
      _buildComponentIdentifier('@signature-params', null);

  /// Serializes the signature parameters into the canonical inner list representation.
  String serializeComponentValue() {
    final parameters = _parameters.isEmpty ? null : _parameters;
    return SfInnerList(_componentIdentifiers, parameters).serialize();
  }
}

/// Configures how signature parameters are generated for requests.
class SignatureParametersFactory {
  /// Creates a factory for building `SignatureParameters` instances.
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

  /// Seeds the factory with base parameters that are cloned per build.
  SignatureParametersFactory setBaseParameters(SignatureParameters base) {
    _baseParameters = SignatureParameters.copy(base);
    return this;
  }

  /// Configures body digest requirements and the hashing algorithm.
  SignatureParametersFactory setBodyDigestConfig(String? algorithm,
      {required bool required}) {
    if (algorithm != null &&
        algorithm != SignatureDigest.sha256.identifier &&
        algorithm != SignatureDigest.sha512.identifier) {
      throw ArgumentError('Unsupported body digest algorithm: $algorithm');
    }
    _bodyDigestAlgorithm = algorithm;
    _bodyDigestRequired = required;
    return this;
  }

  /// Switches signing to the install (ECDSA) key path.
  SignatureParametersFactory setUseInstallMessageSigning() {
    _useAccountMessageSigning = false;
    return this;
  }

  /// Switches signing to the account (HMAC) key path.
  SignatureParametersFactory setUseAccountMessageSigning() {
    _useAccountMessageSigning = true;
    return this;
  }

  /// Enables or disables emitting the `created` parameter.
  SignatureParametersFactory setAddCreated(bool addCreated) {
    _addCreated = addCreated;
    return this;
  }

  /// Sets the validity window for the `expires` parameter.
  SignatureParametersFactory setExpiresLifetime(int seconds) {
    _expiresLifetimeSeconds = seconds;
    return this;
  }

  /// Controls whether the Approov token header is added to the component list.
  SignatureParametersFactory setAddApproovTokenHeader(bool add) {
    _addApproovTokenHeader = add;
    return this;
  }

  /// Adds additional headers to sign when present on the request.
  SignatureParametersFactory addOptionalHeaders(List<String> headers) {
    for (final header in headers) {
      final normalized = header.toLowerCase();
      if (!_optionalHeaders.contains(normalized)) {
        _optionalHeaders.add(normalized);
      }
    }
    return this;
  }

  /// Enables or disables debug mode on the produced parameters.
  SignatureParametersFactory setDebugMode(bool debugMode) {
    _debugMode = debugMode;
    return this;
  }

  /// Builds a concrete parameter set for the supplied signing context.
  SignatureParameters build(ApproovSigningContext context) {
    final params = _baseParameters != null
        ? SignatureParameters.copy(_baseParameters!)
        : SignatureParameters();
    params.debugMode = _debugMode;
    params.setAlg(
        _useAccountMessageSigning ? 'hmac-sha256' : 'ecdsa-p256-sha256');

    final now = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    if (_addCreated) params.setCreated(now);
    if (_expiresLifetimeSeconds > 0)
      params.setExpires(now + _expiresLifetimeSeconds);

    if (_addApproovTokenHeader) {
      final tokenHeader = context.tokenHeaderName;
      if (tokenHeader != null && context.hasField(tokenHeader)) {
        params.addComponentIdentifier(tokenHeader);
      }
    }

    for (final header in _optionalHeaders) {
      if (!context.hasField(header)) continue;
      if (header == 'content-length') {
        final hasBodyBytes =
            context.bodyBytes != null && context.bodyBytes!.isNotEmpty;
        final contentLengthValue =
            context.getComponentValue(SfItem.string('content-length'));
        // Avoid signing Content-Length: 0 to mirror how Dart's HttpClient elides that header on the wire.
        final shouldIncludeContentLength = hasBodyBytes ||
            (contentLengthValue != null && contentLengthValue.trim() != '0');
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
      final digestHeader = context.ensureContentDigest(
          SignatureDigest.fromIdentifier(_bodyDigestAlgorithm!),
          required: _bodyDigestRequired);
      if (digestHeader != null) {
        params.addComponentIdentifier('content-digest');
      }
    }

    return params;
  }

  /// Generates the default Approov configuration, optionally layering on an override base.
  static SignatureParametersFactory generateDefaultFactory(
      {SignatureParameters? overrideBase}) {
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
        .addOptionalHeaders(const [
      'authorization',
      'content-length',
      'content-type'
    ]).setBodyDigestConfig(SignatureDigest.sha256.identifier, required: false);
  }
}

/// Builds canonical signature base strings from parameters and request context.
class SignatureBaseBuilder {
  /// Creates a builder that canonicalizes the parameters for signing.
  SignatureBaseBuilder(this.params, this.context);

  final SignatureParameters params;
  final ApproovSigningContext context;

  /// Produces the canonical signature base string for the configured context.
  String createSignatureBase() {
    // Serialize each signed component and the signature parameters into the canonical signature base string.
    final buffer = StringBuffer();
    for (final component in params.componentIdentifiers) {
      final value = context.getComponentValue(component);
      if (value == null) {
        throw StateError(
            'Missing component value for ${_componentIdentifierValue(component)}');
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

  /// Looks up a digest configuration by its HTTP identifier.
  static SignatureDigest fromIdentifier(String id) {
    return SignatureDigest.values.firstWhere(
      (value) => value.identifier == id,
      orElse: () => throw ArgumentError('Unsupported digest identifier: $id'),
    );
  }
}

/// Holds the HTTP request data required for canonical signing.
class ApproovSigningContext {
  /// Captures the request metadata and header snapshot for signing.
  ApproovSigningContext({
    required this.requestMethod,
    required this.uri,
    required Map<String, List<String>> headers,
    required this.bodyBytes,
    required this.tokenHeaderName,
    this.onSetHeader,
    this.onAddHeader,
  }) : _headers = LinkedHashMap<String, List<String>>.fromEntries(
            headers.entries.map((entry) => MapEntry(
                entry.key.toLowerCase(), List<String>.from(entry.value))));

  final String requestMethod;
  final Uri uri;
  final Uint8List? bodyBytes;
  final String? tokenHeaderName;
  final LinkedHashMap<String, List<String>> _headers;

  final void Function(String name, String value)? onSetHeader;
  final void Function(String name, String value)? onAddHeader;

  /// Returns true when a header with the provided name is present.
  bool hasField(String name) => _headers.containsKey(name.toLowerCase());

  /// Sets a header to a single canonical value, replacing any previous entry.
  void setHeader(String name, String value) {
    _headers[name.toLowerCase()] = <String>[value];
    onSetHeader?.call(name, value);
  }

  /// Adds an additional header value while keeping existing ones intact.
  void addHeader(String name, String value) {
    _headers.putIfAbsent(name.toLowerCase(), () => <String>[]).add(value);
    onAddHeader?.call(name, value);
  }

  /// Resolves the canonical value for a Structured Field component.
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
            throw StateError(
                'name parameter for @query-param must be an sf-string');
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

  /// Ensures the `Content-Digest` header exists by hashing the request body.
  String? ensureContentDigest(SignatureDigest digest,
      {required bool required}) {
    if (bodyBytes == null) {
      if (required) {
        throw StateError('Body digest required but body is not available');
      }
      return null;
    }
    // RFC-compliant digest header uses base64-encoded hash surrounded by colons, e.g. sha-256=:...:
    final bytes = switch (digest) {
      SignatureDigest.sha256 => sha256.convert(bodyBytes!).bytes,
      SignatureDigest.sha512 => sha512.convert(bodyBytes!).bytes,
    };
    final headerValue = '${digest.identifier}=:${base64Encode(bytes)}:';
    setHeader('Content-Digest', headerValue);
    return headerValue;
  }

  /// Returns the authority component normalized per HTTP request rules.
  String _authority() {
    if ((uri.scheme == 'http' && uri.port == 80) ||
        (uri.scheme == 'https' && uri.port == 443) ||
        (uri.port == 0)) {
      return uri.host;
    }
    return '${uri.host}:${uri.port}';
  }

  /// Builds the request-target pseudo-component used by HTTP signatures.
  String _requestTarget() {
    final path = uri.path.isEmpty ? '/' : uri.path;
    if (!uri.hasQuery) return path;
    return '$path?${uri.query}';
  }

  /// Extracts a single query parameter value, returning null when ambiguous.
  String? _queryParameterValue(String name) {
    final values = uri.queryParametersAll[name];
    if (values == null) return null;
    if (values.length > 1) return null;
    return values.isEmpty ? '' : values.first;
  }

  /// Collapses folded header lines into a single comma-separated value.
  String _combineFieldValues(List<String> values) {
    final cleaned = values.map((value) {
      final trimmed = value.trim();
      // Collapse line folding and excess whitespace to keep a stable canonical field value.
      return trimmed.replaceAll(RegExp(r'\s*\r\n\s*'), ' ');
    }).toList();
    return cleaned.join(', ');
  }

  /// Returns a copy of the tracked headers map for inspection or replay.
  Map<String, List<String>> snapshotHeaders() => LinkedHashMap.of(_headers);
}

/// Coordinates signature parameter factories across different hosts.
class ApproovMessageSigning {
  SignatureParametersFactory? _defaultFactory;
  final Map<String, SignatureParametersFactory> _hostFactories = {};

  /// Sets the fallback factory used when a host-specific one is absent.
  ApproovMessageSigning setDefaultFactory(SignatureParametersFactory factory) {
    _defaultFactory = factory;
    return this;
  }

  /// Registers a signature parameters factory for a specific host.
  ApproovMessageSigning putHostFactory(
      String host, SignatureParametersFactory factory) {
    _hostFactories[host] = factory;
    return this;
  }

  /// Looks up the factory to use for the provided host.
  SignatureParametersFactory? _factoryForHost(String host) {
    return _hostFactories[host] ?? _defaultFactory;
  }

  /// Builds signature parameters for the supplied URI if a factory is configured.
  SignatureParameters? buildParametersFor(
      Uri uri, ApproovSigningContext context) {
    final factory = _factoryForHost(uri.host);
    if (factory == null) return null;
    return factory.build(context);
  }
}
