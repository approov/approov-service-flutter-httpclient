/*
 * Copyright (c) 2022 CriticalBlue Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:core';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';
import 'package:collection/collection.dart';
import 'package:enum_to_string/enum_to_string.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/services.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart' as httpio;
import 'package:logger/logger.dart';
import 'package:pem/pem.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mutex/mutex.dart';

// logger
final Logger Log = Logger();

/// Potential status results from an Approov fetch attempt
enum _TokenFetchStatus {
  SUCCESS, // token was successfully received
  NO_NETWORK, // there is no token because there is no network connectivity currently
  MITM_DETECTED, // there is no token because there is a Man-In-The-Middle (MITM) to the Approov cloud service
  POOR_NETWORK, // no token could be obtained due to poor network connectivity
  NO_APPROOV_SERVICE, // no token could be obtained, perhaps because Approov services are down
  BAD_URL, // provided URL was not https or otherwise in the correct format
  UNKNOWN_URL, // provided URL is not one that one configured for Approov
  UNPROTECTED_URL, // provided URL does not need an Approov token
  NO_NETWORK_PERMISSION, // app does not have ACCESS_NETWORK_STATE or INTERNET permission
  MISSING_LIB_DEPENDENCY, // app is missing a needed library dependency
  INTERNAL_ERROR, // there has been an internal error in the SDK
  REJECTED, // indicates a custom JWT or secure string fetch has been rejected because Approov attestation fails
  DISABLED, // indicates that a custom JWT or secure string fetch fails because the feature is not enabled
  UNKNOWN_KEY, // indicates an attempt to fetch a secure string that has not been defined
  BAD_KEY, // indicates an attempt to fetch a secure string with a bad key
  BAD_PAYLOAD // indicates an attempt to fetch a custom JWT with a bad payload
}

/// Results from an Approov token fetch
class _TokenFetchResult {
  // Status of the last Approov token fetch
  _TokenFetchStatus tokenFetchStatus = _TokenFetchStatus.INTERNAL_ERROR;

  // Token string of the last Approov fetch. This may be an empty string if the fetch did not succeed or wasn't to fetch a token.
  String token = "";

  // Secure string of the last Approov fetch. This may be an null if the fetch did not succeed or wasn't to fetch a secure string.
  String? secureString = null;

  // An Attestation Response Code (ARC) providing details of the device properties. This is the empty string if no ARC
  // was obtained.
  String ARC = "";

  // Any rejection reasons describing why Approov attestation has failed. This is a comma separated list of device properties, or
  // an empty string for a pass or if the feature is not enabled.
  String rejectionReasons = "";

  // Indicates whether a new configuration is available from fetchConfig()
  bool isConfigChanged = false;

  // Indicates whether current user APIs must be updated to reflect a new version available from getPins(). Calling
  // getPins() will clear this flag for the next Approov token fetch.
  bool isForceApplyPins = false;

  // Measurement configuration if the last token fetch was to perform an integrity measurement and was successful.
  Uint8List measurementConfig = Uint8List(0);

  // Loggable Approov token string.
  String loggableToken = "";

  /// Convenience constructor to generate the results from a results map from the underlying platform call.
  ///
  /// @param tokenFetchResultMap holds the results of the fetch
  _TokenFetchResult.fromTokenFetchResultMap(Map tokenFetchResultMap) {
    _TokenFetchStatus? newTokenFetchStatus = EnumToString.fromString(
        _TokenFetchStatus.values, tokenFetchResultMap["TokenFetchStatus"]);
    if (newTokenFetchStatus != null) tokenFetchStatus = newTokenFetchStatus;
    token = tokenFetchResultMap["Token"];
    String? newSecureString = tokenFetchResultMap["SecureString"];
    if (newSecureString != null) secureString = newSecureString;
    ARC = tokenFetchResultMap["ARC"];
    rejectionReasons = tokenFetchResultMap["RejectionReasons"];
    isConfigChanged = tokenFetchResultMap["IsConfigChanged"];
    isForceApplyPins = tokenFetchResultMap["IsForceApplyPins"];
    Uint8List? newMeasurementConfig = tokenFetchResultMap["MeasurementConfig"];
    if (newMeasurementConfig != null) measurementConfig = newMeasurementConfig;
    loggableToken = tokenFetchResultMap["LoggableToken"];
  }
}

/// ApproovException is thrown if there is an error from Approov.
class ApproovException implements Exception {
  // cause of the exception
  String? cause;

  /// ApproovExeception constructs a new Approov exception.
  ///
  /// @param cause is a message giving the cause of the exception
  ApproovException(String cause) {
    this.cause = cause;
  }
}

/// ApproovNetworkException indicates an exception caused by networking conditions which is likely to be
/// temporary so a user initiated retry should be performed.
class ApproovNetworkException extends ApproovException {
  /// ApproovNetworkException constructs a new exception as a result of a temporary networking issue.
  ///
  /// @param cause is a message giving the cause of the exception
  ApproovNetworkException(String cause) : super(cause) {}
}

/// ApproovRejectionException provides additional information if the app has been rejected by Approov.
class ApproovRejectionException extends ApproovException {
  // provides a code of the app state for support purposes
  String? arc;

  // provides a comma separated list of rejection reasons (if the feature is enabled in Approov)
  String? rejectionReasons;

  /// ApproovRejectionException constructs a new exception as a result of an app rejection.
  ///
  /// @param cause is a message giving the cause of the exception
  /// @param arc is the code that can be used for support purposes
  /// @param rejectionReasons may provide a comma separated list of rejection reasons
  ApproovRejectionException(String cause, String arc, String rejectionReasons)
      : super(cause) {
    this.arc = arc;
    this.rejectionReasons = rejectionReasons;
  }
}

// ApproovService is a singleton for managing the underlying Approov SDK itself. It provides a number of user accessible
// methods and management for its configuration.
class ApproovService {
  // logging tag
  static const String TAG = "ApproovService";

  // channel for communicating with the platform specific layers
  static const MethodChannel _channel =
      const MethodChannel('approov_service_flutter_httpclient');

  // header that will be added to Approov enabled requests
  static const String APPROOV_HEADER = "Approov-Token";

  // any prefix to be added before the Approov token, such as "Bearer "
  static const String APPROOV_TOKEN_PREFIX = "";

  // mutex to control access to initialization
  static final _initMutex = Mutex();

  // header used when adding the Approov Token to network requests
  static String _approovTokenHeader = APPROOV_HEADER;

  // prefix for the above header (like Bearer)
  static String _approovTokenPrefix = APPROOV_TOKEN_PREFIX;

  // indicates whether the Approov SDK has been initialized
  static bool _isInitialized = false;

  // initial configuration string provided
  static String? _initialConfig = null;

  // optional comment provided during initialization
  static String? _initialComment = null;

  // true if the interceptor should proceed on network failures and not add an Approov token
  static bool _proceedOnNetworkFail = false;

  // any header to be used for binding in Approov tokens or null if not set
  static String? _bindingHeader = null;

  // map of headers that should have their values substituted for secure strings, mapped to their
  // required prefixes
  static Map<String, String> _substitutionHeaders = {};

  // map of URL regexs that should be excluded from any Approov protection, mapped to the regular expressions
  static Map<String, RegExp> _exclusionURLRegexs = {};

  // cached host certificates obtaining from probing the relevant host domains
  static Map<String, List<Uint8List>?> _hostCertificates =
      Map<String, List<Uint8List>?>();

  /// Internal method to initialize the Approov SDK if needed using a previously provided initial configuration string.
  /// Initialization is performed lazily based on the first actual use of the underlying SDK. This is necessary due to
  /// asynchronous nature of Dart execution which makes it difficult to guarantee that initialization is cemplete before
  /// the first operation otherwise.
  ///
  /// @throws ApproovException if initialization could not be completed
  static Future<void> _initializeIfRequired() async {
    // protect the initialization in a critical section to avoid multiple initializations
    await _initMutex.protect(() async {
      // only perform the initialization if required
      if (!_isInitialized) {
        // check an initial configuration has been supplied
        if (_initialConfig == null)
          throw ApproovException("ApproovService has not been initialized");

        // perform the actual initialization
        try {
          // initialize the Approov SDK
          Map<String, dynamic> arguments = <String, dynamic>{
            "initialConfig": _initialConfig,
            "updateConfig": "auto",
            "comment": null,
          };
          await _channel.invokeMethod('initialize', arguments);
          // Use the comment string to initialize now immediately with the non null string
          if (_initialComment != null) {
            arguments["comment"] = _initialComment;
            await _channel.invokeMethod('initialize', arguments);
          }
          // set the user property to represent the framework being used
          // set the user property
          arguments = <String, dynamic>{
            "property": "approov-service-flutter-httpclient",
          };
          await _channel.invokeMethod('setUserProperty', arguments);

          // initialization was successful
          _isInitialized = true;
        } catch (err) {
          throw ApproovException('$err');
        }
      }
    });
  }

  /// Provide the initialization config for the Approov SDK. This must be called prior to any other methods on the
  /// ApproovService. This does not actually initialize the SDK at this point, as this is done lazily on the first
  /// actual use of the SDK. If an initial configuration has been provided previously and this one is different then
  /// an error is thrown.
  ///
  /// @param config is the configuration string
  /// @param comment is an optional comment used during initialization. It is safe to use null
  /// @throws ApproovException if the provided configuration is not valid
  static Future<void> initialize(String config, [String? comment]) async {
    if (_initialConfig == null) Log.d("$TAG: initialize $config");
    if ((_initialConfig != null) && (config != _initialConfig))
      throw ApproovException(
          "Attempt to reinitialize the Approov SDK with a different configuration $config");
    _initialConfig = config;
    _initialComment = comment;
  }

  /// Sets a flag indicating if the network interceptor should proceed anyway if it is
  /// not possible to obtain an Approov token due to a networking failure. If this is set
  /// then your backend API can receive calls without the expected Approov token header
  /// being added, or without header/query parameter substitutions being made. Note that
  /// this should be used with caution because it may allow a connection to be established
  /// before any dynamic pins have been received via Approov, thus potentially opening the
  /// channel to a MitM.
  ///
  /// @param proceed is true if Approov networking fails should allow continuation
  static void setProceedOnNetworkFail(bool proceed) {
    Log.d("$TAG: setProceedOnNetworkFail $proceed");
    _proceedOnNetworkFail = proceed;
  }

  /// Sets a development key indicating that the app is a development version and it should
  /// pass attestation even if the app is not registered or it is running on an emulator. The
  /// development key value can be rotated at any point in the account if a version of the app
  /// containing the development key is accidentally released. This is primarily
  /// used for situations where the app package must be modified or resigned in
  /// some way as part of the testing process.
  ///
  /// @param devKey is the development key to be used
  /// @throws ApproovException if there was a problem
  static Future<void> setDevKey(String devKey) async {
    Log.d("$TAG: setDevKey");
    await _initializeIfRequired();
    final Map<String, dynamic> arguments = <String, dynamic>{
      "devKey": devKey,
    };
    try {
      await _channel.invokeMethod('setDevKey', arguments);
    } catch (err) {
      throw ApproovException('$err');
    }
  }

  /// Sets the header that the Approov token is added on, as well as an optional
  /// prefix String (such as "Bearer "). By default the token is provided on
  /// "Approov-Token" with no prefix.
  ///
  /// @param header is the header to place the Approov token on
  /// @param prefix is any prefix String for the Approov token header
  static void setApproovHeader(String header, String prefix) {
    Log.d("$TAG: setApproovHeader $header $prefix");
    _approovTokenHeader = header;
    _approovTokenPrefix = prefix;
  }

  /// Sets a binding header that must be present on all requests using the Approov service. A
  /// header should be chosen whose value is unchanging for most requests (such as an
  /// Authorization header). A hash of the header value is included in the issued Approov tokens
  /// to bind them to the value. This may then be verified by the backend API integration. This
  /// method should typically only be called once.
  ///
  /// @param header is the header to use for Approov token binding
  static void setBindingHeader(String header) {
    Log.d("$TAG: setBindingHeader $header");
    _bindingHeader = header;
  }

  /// Adds the name of a header which should be subject to secure strings substitution. This
  /// means that if the header is present then the value will be used as a key to look up a
  /// secure string value which will be substituted into the header value instead. This allows
  /// easy migration to the use of secure strings. Note that this should be done on initialization
  /// rather than for every request as it will require a new OkHttpClient to be built. A required
  /// prefix may be specified to deal with cases such as the use of "Bearer " prefixed before values
  /// in an authorization header.
  ///
  /// @param header is the header to be marked for substitution
  /// @param requiredPrefix is any required prefix to the value being substituted or null if not required
  static void addSubstitutionHeader(String header, String? requiredPrefix) {
    Log.d("$TAG: addSubstitutionHeader $header");
    if (requiredPrefix == null)
      _substitutionHeaders[header] = "";
    else
      _substitutionHeaders[header] = requiredPrefix;
  }

  /// Removes a header previously added using addSubstitutionHeader.
  ///
  /// @param header is the header to be removed for substitution
  static void removeSubstitutionHeader(String header) {
    Log.d("$TAG: removeSubstitutionHeader $header");
    _substitutionHeaders.remove(header);
  }

  /// Adds an exclusion URL regular expression. If a URL for a request matches this regular expression
  /// then it will not be subject to any Approov protection. Note that this facility must be used with
  /// EXTREME CAUTION due to the impact of dynamic pinning. Pinning may be applied to all domains added
  /// using Approov, and updates to the pins are received when an Approov fetch is performed. If you
  /// exclude some URLs on domains that are protected with Approov, then these will be protected with
  /// Approov pins but without a path to update the pins until a URL is used that is not excluded. Thus
  /// you are responsible for ensuring that there is always a possibility of calling a non-excluded
  /// URL, or you should make an explicit call to fetchToken if there are persistent pinning failures.
  /// Conversely, use of those option may allow a connection to be established before any dynamic pins
  /// have been received via Approov, thus potentially opening the channel to a MitM.
  ///
  /// @param urlRegex is the regular expression that will be compared against URLs to exclude them
  static void addExclusionURLRegex(String urlRegex) {
    Log.d("$TAG: addExclusionURLRegex $urlRegex");
    try {
      RegExp regExp = RegExp(urlRegex);
      _exclusionURLRegexs[urlRegex] = regExp;
      Log.d("$TAG: addExclusionURLRegex $urlRegex");
    } on FormatException catch (e) {
      Log.d("$TAG: addExclusionURLRegex $urlRegex: ${e.message}");
    }
  }

  /// Removes an exclusion URL regular expression previously added using addExclusionURLRegex.
  ///
  /// @param urlRegex is the regular expression that will be compared against URLs to exclude them
  static void removeExclusionURLRegex(String urlRegex) {
    Log.d("$TAG: removeExclusionURLRegex $urlRegex");
    _exclusionURLRegexs.remove(urlRegex);
  }

  /// Prefetches to lower the effective latency of a subsequent token or secure string fetch by
  /// starting the operation earlier so the subsequent fetch should be able to use cached data.
  /// You should call this without using "await" so it can happen asynchronously.
  static void prefetch() async {
    try {
      await _initializeIfRequired();
      _TokenFetchResult result =
          await ApproovService._fetchApproovToken("approov.io");
      if ((result.tokenFetchStatus == _TokenFetchStatus.SUCCESS) ||
          (result.tokenFetchStatus == _TokenFetchStatus.UNKNOWN_URL) ||
          (result.tokenFetchStatus == _TokenFetchStatus.UNPROTECTED_URL))
        Log.d("$TAG: prefetch success");
      else
        Log.d("$TAG: prefetch failure: ${result.tokenFetchStatus.name}");
    } on ApproovException catch (e) {
      Log.e("$TAG: prefetch: exception ${e.cause}");
    }
  }

  /// Performs a precheck to determine if the app will pass attestation. This requires secure
  /// strings to be enabled for the account, although no strings need to be set up. This will
  /// likely require network access so may take some time to complete. It should always be called
  /// with await to allow capture of any ApproovException thrown, if the precheck fails or if there
  /// is some other problem. ApproovRejectionException is thrown if the app has failed Approov checks
  /// or ApproovNetworkException for networking issues where a user initiated retry of the operation
  /// should be allowed. An ApproovRejectionException may provide additional information about the
  /// cause of the rejection.
  ///
  /// @throws ApproovException if there was a problem
  static Future<void> precheck() async {
    // try and fetch a non-existent secure string in order to check for a rejection
    await _initializeIfRequired();
    final Map<String, dynamic> arguments = <String, dynamic>{
      "key": "precheck-dummy-key",
      "newDef": null,
    };
    _TokenFetchResult fetchResult;
    try {
      Map fetchResultMap =
          await _channel.invokeMethod('fetchSecureStringAndWait', arguments);
      fetchResult = _TokenFetchResult.fromTokenFetchResultMap(fetchResultMap);
      Log.d("$TAG: precheck: ${fetchResult.tokenFetchStatus.name}");
    } catch (err) {
      throw ApproovException('$err');
    }

    // process the returned Approov status
    if (fetchResult.tokenFetchStatus == _TokenFetchStatus.REJECTED)
      // if the request is rejected then we provide a special exception with additional information
      throw new ApproovRejectionException(
          "precheck: ${fetchResult.tokenFetchStatus.name}: ${fetchResult.ARC} ${fetchResult.rejectionReasons}",
          fetchResult.ARC,
          fetchResult.rejectionReasons);
    else if ((fetchResult.tokenFetchStatus == _TokenFetchStatus.NO_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.POOR_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.MITM_DETECTED))
      // we are unable to get the secure string due to network conditions so the request can
      // be retried by the user later
      throw new ApproovNetworkException(
          "precheck: ${fetchResult.tokenFetchStatus.name}");
    else if ((fetchResult.tokenFetchStatus != _TokenFetchStatus.SUCCESS) &&
        (fetchResult.tokenFetchStatus != _TokenFetchStatus.UNKNOWN_KEY))
      // we are unable to get the secure string due to a more permanent error
      throw new ApproovException(
          "precheck: ${fetchResult.tokenFetchStatus.name}");
  }

  /// Gets the device ID used by Approov to identify the particular device that the SDK is running on. Note that
  /// different Approov apps on the same device will return a different ID. Moreover, the ID may be changed by an
  /// uninstall and reinstall of the app.
  ///
  /// @return String representation of the device ID
  static Future<String> getDeviceID() async {
    await _initializeIfRequired();
    try {
      String deviceID = await _channel.invokeMethod('getDeviceID');
      Log.d("$TAG: getDeviceID: $deviceID");
      return deviceID;
    } catch (err) {
      throw ApproovException('$err');
    }
  }

  /// Sets a hash of the given data value into any future Approov tokens obtained in the 'pay' claim. If the data values
  /// are transmitted to the API backend along with the Approov token then this allows the backend to check that the
  /// data value was indeed known to the app at the time of the token fetch and hasn't been spoofed. If the data is the
  /// same as any previous one set then the token does not need to be updated. Otherwise the next token fetch causes a
  /// new attestation to fetch a new token. Note that this should not be done frequently due to the additional latency on
  /// token fetching that will be caused. The hash appears in the 'pay' claim of the Approov token as a base64 encoded
  /// string of the SHA256 hash of the data. Note that the data is hashed locally and never sent to the Approov cloud service.
  ///
  /// @param data is the data whose SHA256 hash is to be included in future Approov tokens
  /// @throws ApproovException if there was a problem
  static Future<void> setDataHashInToken(String data) async {
    Log.d("$TAG: setDataHashInToken");
    await _initializeIfRequired();
    final Map<String, dynamic> arguments = <String, dynamic>{
      "data": data,
    };
    try {
      await _channel.invokeMethod('setDataHashInToken', arguments);
    } catch (err) {
      throw ApproovException('$err');
    }
  }

  /// Initiates a request to obtain an Approov token and other results. If an Approov token fetch has been completed
  /// previously and the tokens are unexpired then this may return the same one without a need to perform a network
  /// transaction. Note though that the caller should never cache the Approov token as it may become invalidated at any point.
  ///
  /// If a new Approov token is required then a more extensive app measurement is performed that involves communicating
  /// with the Approov cloud service. Thus this method may take up to several seconds to complete. Note that if the
  /// attestation is rejected by the Approov cloud service then a token is still returned, it just won't be signed
  /// with the correct signature so the failure is detected when any API, to which the token is presented, verifies it.
  ///
  /// All calls must provide a URL which provides the high level domain of the API to which the Approov token is going
  /// to be sent. Different API domains will have different Approov tokens associated with them so it is important that
  /// the Approov token is only sent to requests for that domain. If the domain has not been configured using the Approov
  /// CLI then an ApproovException is thrown. Note that there are various other reasons that an ApproovException might also
  /// be thrown. If the fetch fails due to a networking issue, and should be retried at some later point, then an
  /// ApproovNetworkException is thrown.
  ///
  /// @param url provides the top level domain URL for which a token is being fetched
  /// @return results of fetching a token
  /// @throws ApproovException if there was a problem
  static Future<String> fetchToken(String url) async {
    // fetch the Approov token
    _TokenFetchResult fetchResult = await _fetchApproovToken(url);
    Log.d("$TAG: fetchToken for $url: ${fetchResult.loggableToken}");

    // check the status of Approov token fetch
    if ((fetchResult.tokenFetchStatus == _TokenFetchStatus.SUCCESS) ||
        (fetchResult.tokenFetchStatus ==
            _TokenFetchStatus.NO_APPROOV_SERVICE)) {
      // we successfully obtained a token so provide it, or provide an empty one on complete Approov service failure
      return fetchResult.token;
    } else if ((fetchResult.tokenFetchStatus == _TokenFetchStatus.NO_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.POOR_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.MITM_DETECTED)) {
      // we are unable to get an Approov token due to network conditions so the request can
      // be retried by the user later
      throw new ApproovNetworkException(
          "fetchToken for $url: ${fetchResult.tokenFetchStatus.name}");
    } else {
      // we have failed to get an Approov token with a more serious permanent error
      throw ApproovException(
          "fetchToken for $url: ${fetchResult.tokenFetchStatus.name}");
    }
  }

  /// Gets the signature for the given message. This uses an account specific message signing key that is
  /// transmitted to the SDK after a successful token fetch if the facility is enabled for the account and
  /// the token is received from the primary (rather than failover) Approov cloud. Note
  /// that if the attestation failed then the signing key provided is actually random so that the
  /// signature will be incorrect. An Approov token should always be included in the message
  /// being signed and sent alongside this signature to prevent replay attacks.
  ///
  /// @param the message for which to et the signature
  /// @return base64 encoded signature of the message, or null if no signing key is available
  /// @throws ApproovException if there was a problem
  static Future<String> getMessageSignature(String message) async {
    Log.d("$TAG: getMessageSignature");
    await _initializeIfRequired();
    final Map<String, dynamic> arguments = <String, dynamic>{
      "message": message,
    };
    try {
      String messageSignature =
          await _channel.invokeMethod('getMessageSignature', arguments);
      return messageSignature;
    } catch (err) {
      throw ApproovException('$err');
    }
  }

  /// Fetches a secure string with the given key. If newDef is not null then a
  /// secure string for the particular app instance may be defined. In this case the
  /// new value is returned as the secure string. Use of an empty string for newDef removes
  /// the string entry. Note that this call may require network transaction and thus may take some
  /// time. You should always call with await. If the attestation fails for any reason then an
  /// ApproovException is thrown. This will be ApproovRejectionException if the app has failed
  /// Approov checks or ApproovNetworkException for networking issues where a user initiated retry
  /// of the operation should be allowed. Note that the returned string should NEVER be cached by
  /// your app, you should call this function when it is needed.
  ///
  /// @param key is the secure string key to be looked up
  /// @param newDef is any new definition for the secure string, or null for lookup only
  /// @return secure string (should not be cached by your app) or null if it was not defined
  /// @throws ApproovException if there was a problem
  static Future<String?> fetchSecureString(String key, String? newDef) async {
    // determine the type of operation as the values themselves cannot be logged
    String type = "lookup";
    if (newDef != null) type = "definition";

    // fetch the secure string synchronously from the platform layer
    await _initializeIfRequired();
    final Map<String, dynamic> arguments = <String, dynamic>{
      "key": key,
      "newDef": newDef,
    };
    _TokenFetchResult fetchResult;
    try {
      Map fetchResultMap =
          await _channel.invokeMethod('fetchSecureStringAndWait', arguments);
      fetchResult = _TokenFetchResult.fromTokenFetchResultMap(fetchResultMap);
      Log.d(
          "$TAG: fetchSecureString $type: $key, ${fetchResult.tokenFetchStatus.name}");
    } catch (err) {
      throw ApproovException('$err');
    }

    // process the returned Approov status
    if (fetchResult.tokenFetchStatus == _TokenFetchStatus.REJECTED)
      // if the request is rejected then we provide a special exception with additional information
      throw new ApproovRejectionException(
          "fetchSecureString $type for $key: ${fetchResult.tokenFetchStatus.name}: ${fetchResult.ARC} ${fetchResult.rejectionReasons}",
          fetchResult.ARC,
          fetchResult.rejectionReasons);
    else if ((fetchResult.tokenFetchStatus == _TokenFetchStatus.NO_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.POOR_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.MITM_DETECTED))
      // we are unable to get the secure string due to network conditions so the request can
      // be retried by the user later
      throw new ApproovNetworkException(
          "fetchSecureString $type for $key: ${fetchResult.tokenFetchStatus.name}");
    else if ((fetchResult.tokenFetchStatus != _TokenFetchStatus.SUCCESS) &&
        (fetchResult.tokenFetchStatus != _TokenFetchStatus.UNKNOWN_KEY))
      // we are unable to get the secure string due to a more permanent error
      throw new ApproovException(
          "fetchSecureString $type for $key: ${fetchResult.tokenFetchStatus.name}");
    return fetchResult.secureString;
  }

  /// Fetches a custom JWT with the given payload. Note that this call will require network
  /// transaction and thus will take some time. It should always be called with await.
  /// If the attestation fails for any reason then an ApproovException is thrown. This will be
  /// ApproovRejectionException if the app has failed Approov checks or ApproovNetworkException
  /// for networking issues where a user initiated retry of the operation should be allowed.
  ///
  /// @param payload is the marshaled JSON object for the claims to be included
  /// @return custom JWT string
  /// @throws ApproovException if there was a problem
  static Future<String> fetchCustomJWT(String payload) async {
    // fetch the custom JWT from the platform layer
    await _initializeIfRequired();
    final Map<String, dynamic> arguments = <String, dynamic>{
      "payload": payload,
    };
    _TokenFetchResult fetchResult;
    try {
      Map fetchResultMap =
          await _channel.invokeMethod('fetchCustomJWTAndWait', arguments);
      fetchResult = _TokenFetchResult.fromTokenFetchResultMap(fetchResultMap);
      Log.d("$TAG: fetchCustomJWT: ${fetchResult.tokenFetchStatus.name}");
    } catch (err) {
      throw ApproovException('$err');
    }

    // process the returned Approov status
    if (fetchResult.tokenFetchStatus == _TokenFetchStatus.REJECTED)
      // if the request is rejected then we provide a special exception with additional information
      throw new ApproovRejectionException(
          "fetchCustomJWT: ${fetchResult.tokenFetchStatus.name}: ${fetchResult.ARC} ${fetchResult.rejectionReasons}",
          fetchResult.ARC,
          fetchResult.rejectionReasons);
    else if ((fetchResult.tokenFetchStatus == _TokenFetchStatus.NO_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.POOR_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.MITM_DETECTED))
      // we are unable to get the custom JWT due to network conditions so the request can
      // be retried by the user later
      throw new ApproovNetworkException(
          "fetchCustomJWT: ${fetchResult.tokenFetchStatus.name}");
    else if (fetchResult.tokenFetchStatus != _TokenFetchStatus.SUCCESS)
      // we are unable to get the custom JWT due to a more permanent error
      throw new ApproovException(
          "fetchCustomJWT: ${fetchResult.tokenFetchStatus.name}");

    // provide the custom JWT
    return fetchResult.token;
  }

  /// Fetches the current configuration for the SDK. Normally this method returns the latest configuration that is
  /// available and is cached in the SDK. Thus the method will return quickly. However, if this method is called when
  /// there has been no prior call to fetch an Approov token then a network request to the Approov cloud service will be
  /// made to obtain any latest configuration update. The maximum timeout period is set to be quite short but the caller
  /// must be aware that this delay may occur.
  ///
  /// @return String representation of the configuration
  /// @throws ApproovException if there was a problem
  static Future<String> _fetchConfig() async {
    await _initializeIfRequired();
    try {
      String config = await _channel.invokeMethod('fetchConfig');
      return config;
    } catch (err) {
      throw ApproovException('$err');
    }
  }

  /// Fetches the pins from the current configuration of the SDK. This is returned as a map from URL domain (hostname
  /// only) to the possible pins for that domain. If there is no map entry for a domain then that indicates that the
  /// connection is not specifically pinned, or managed trust roots should be used if they are present (keyed from the
  /// "*" domain). The type of pin requested determines the data in each of the pins. This is typically the base64 encoding
  /// of the hash of some aspect of the certificate. A connection is considered to be valid if any certificate in the chain
  /// presented is one with the same hash as one in the array of hashes.
  ///
  /// @param pinType is the type of pinning information that is required
  /// @return Map from domain to the list of strings providing the pins
  /// @throws ApproovException if there was a problem
  static Future<Map> _getPins(String pinType) async {
    await _initializeIfRequired();
    final Map<String, dynamic> arguments = <String, dynamic>{
      "pinType": pinType,
    };
    try {
      Map pins = await _channel.invokeMethod('getPins', arguments);
      return pins;
    } catch (err) {
      throw ApproovException('$err');
    }
  }

  /// Internal method for fetching an Approov token from the SDK.
  ///
  /// @param url provides the top level domain URL for which a token is being fetched
  /// @return results of fetching a token
  /// @throws ApproovException if there was a problem
  static Future<_TokenFetchResult> _fetchApproovToken(String url) async {
    await _initializeIfRequired();
    final Map<String, dynamic> arguments = <String, dynamic>{
      "url": url,
    };
    try {
      Map tokenFetchResultMap =
          await _channel.invokeMethod('fetchApproovTokenAndWait', arguments);
      _TokenFetchResult tokenFetchResult =
          _TokenFetchResult.fromTokenFetchResultMap(tokenFetchResultMap);
      return tokenFetchResult;
    } catch (err) {
      throw ApproovException('$err');
    }
  }

  /// Substitutes the given query parameter in the Uri. If no substitution is made then the
  /// original Uri is returned, otherwise a new one is constructed with the revised query
  /// parameter value. Since this modifies the Uri itself this must be done before making the
  /// request. If it is not currently possible to fetch secure strings token due to
  /// networking issues then ApproovNetworkException is thrown and a user initiated retry of the
  /// operation should be allowed. ApproovRejectionException may be thrown if the attestation
  /// fails and secure strings cannot be obtained. Other ApproovExecptions represent a more
  /// permanent error condition.
  ///
  /// @param uri is the Uri being analyzed for substitution
  /// @param queryParameter is the parameter to be potentially substituted
  /// @return Uri passed in, or modified with a new Uri if required
  /// @throws ApproovException if it is not possible to obtain secure strings for substitution
  static Future<Uri> substituteQueryParam(
      Uri uri, String queryParameter) async {
    String? queryValue = uri.queryParameters[queryParameter];
    if (queryValue != null) {
      // check if the URL matches one of the exclusion regexs and just return the provided Uri if so
      String url = uri.toString();
      for (RegExp regExp in _exclusionURLRegexs.values) {
        if (regExp.hasMatch(url)) return uri;
      }

      // perform SDK initialization if required
      await _initializeIfRequired();

      // we have found an occurrence of the query parameter to be replaced so we look up the existing
      // value as a key for a secure string
      final Map<String, dynamic> arguments = <String, dynamic>{
        "key": queryValue,
        "newDef": null,
      };
      _TokenFetchResult fetchResult;
      try {
        Map fetchResultMap =
            await _channel.invokeMethod('fetchSecureStringAndWait', arguments);
        fetchResult = _TokenFetchResult.fromTokenFetchResultMap(fetchResultMap);
        Log.d(
            "$TAG: substituting query parameter $queryParameter: ${fetchResult.tokenFetchStatus.name}");
      } catch (err) {
        throw ApproovException('$err');
      }

      // process the returned Approov status
      if (fetchResult.tokenFetchStatus == _TokenFetchStatus.SUCCESS) {
        // perform a query substitution
        Map<String, String> updatedParams =
            Map<String, String>.from(uri.queryParameters);
        updatedParams[queryParameter] = fetchResult.secureString!;
        return uri.replace(queryParameters: updatedParams);
      } else if (fetchResult.tokenFetchStatus == _TokenFetchStatus.REJECTED)
        // if the request is rejected then we provide a special exception with additional information
        throw new ApproovRejectionException(
            "Query parameter substitution for $queryParameter: ${fetchResult.tokenFetchStatus.name}: ${fetchResult.ARC} ${fetchResult.rejectionReasons}",
            fetchResult.ARC,
            fetchResult.rejectionReasons);
      else if ((fetchResult.tokenFetchStatus == _TokenFetchStatus.NO_NETWORK) ||
          (fetchResult.tokenFetchStatus == _TokenFetchStatus.POOR_NETWORK) ||
          (fetchResult.tokenFetchStatus == _TokenFetchStatus.MITM_DETECTED)) {
        // we are unable to get the secure string due to network conditions so the request can
        // be retried by the user later - unless this is overridden
        if (!_proceedOnNetworkFail)
          throw new ApproovNetworkException(
              "Query parameter substitution for $queryParameter: ${fetchResult.tokenFetchStatus.name}");
      } else if (fetchResult.tokenFetchStatus != _TokenFetchStatus.UNKNOWN_KEY)
        // we have failed to get a secure string with a more serious permanent error
        throw new ApproovException(
            "Query parameter substitution for $queryParameter: ${fetchResult.tokenFetchStatus.name}");
    }
    return uri;
  }

  /// Adds Approov to the given request by adding the Approov token in a header. If a binding header has been specified
  /// then this should be available. If it is not currently possible to fetch an Approov token (typically due to no or
  /// poor network) then an ApproovNetworkException is thrown and a later retry should be made. Other failures will
  /// result in an ApproovException. Note that if substitution headers have been setup then this method also examines
  /// the headers and remaps them to the substituted value if they correspond to a secure string set in Approov. Note that
  // in this  case it is possible for the method to fail with an ApproovRejectionException, which may provide additional
  /// information about the reason for the rejection.
  ///
  /// @param request is the HttpClientRequest to which Approov is being added
  /// @throws ApproovException if it is not possible to obtain an Approov token or perform required header substitutions
  static Future<void> _updateRequest(HttpClientRequest request) async {
    // check if the URL matches one of the exclusion regexs and just return if so
    String url = request.uri.toString();
    for (RegExp regExp in _exclusionURLRegexs.values) {
      if (regExp.hasMatch(url)) return;
    }

    // perform SDK initialization if required
    await _initializeIfRequired();

    // update the data hash based on any token binding header that is present
    String? bindingHeader = _bindingHeader;
    if (bindingHeader != null) {
      String? headerValue = request.headers.value(bindingHeader);
      if (headerValue != null) setDataHashInToken(headerValue);
    }

    // request an Approov token for the host domain
    String host = request.uri.host;
    _TokenFetchResult fetchResult = await _fetchApproovToken(host);

    // provide information about the obtained token or error (note "approov token -check" can
    // be used to check the validity of the token and if you use token annotations they
    // will appear here to determine why a request is being rejected)
    Log.d("$TAG: updateRequest for $host: ${fetchResult.loggableToken}");

    // if there was a configuration change we clear it by fetching the new config and clearing
    // all the cached certificates which will force re-evaluation for new connections
    if (fetchResult.isConfigChanged) {
      await _fetchConfig();
      _removeAllCertificates();
      Log.d("$TAG: updateRequest, dynamic configuration update");
    }

    // if a pin update is forced then this indicates the pins have been updated since the last time they
    // where read, or that we never had any valid pins when the pinned client was created so we cannot allow
    // the update to complete as this could leak an Approov token via an unpinned connection
    if (fetchResult.isForceApplyPins)
      throw new ApproovNetworkException("Forced pin update required");

    // check the status of Approov token fetch
    if (fetchResult.tokenFetchStatus == _TokenFetchStatus.SUCCESS) {
      // we successfully obtained a token so add it to the header for the request
      request.headers.set(
          _approovTokenHeader, _approovTokenPrefix + fetchResult.token,
          preserveHeaderCase: true);
    } else if ((fetchResult.tokenFetchStatus == _TokenFetchStatus.NO_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.POOR_NETWORK) ||
        (fetchResult.tokenFetchStatus == _TokenFetchStatus.MITM_DETECTED)) {
      // we are unable to get an Approov token due to network conditions so the request can
      // be retried by the user later - unless overridden
      if (!_proceedOnNetworkFail)
        throw new ApproovNetworkException(
            "Approov token fetch for $host: ${fetchResult.tokenFetchStatus.name}");
    } else if ((fetchResult.tokenFetchStatus !=
            _TokenFetchStatus.NO_APPROOV_SERVICE) &&
        (fetchResult.tokenFetchStatus != _TokenFetchStatus.UNKNOWN_URL) &&
        (fetchResult.tokenFetchStatus != _TokenFetchStatus.UNPROTECTED_URL)) {
      // we have failed to get an Approov token with a more serious permanent error
      throw ApproovException(
          "Approov token fetch for $host: ${fetchResult.tokenFetchStatus.name}");
    }

    // we only continue additional processing if we had a valid status from Approov, to prevent additional delays
    // by trying to fetch from Approov again and this also protects against header substiutions in domains not
    // protected by Approov and therefore potentially subject to a MitM
    if ((fetchResult.tokenFetchStatus != _TokenFetchStatus.SUCCESS) &&
        (fetchResult.tokenFetchStatus != _TokenFetchStatus.UNPROTECTED_URL))
      return;

    // we now deal with any header substitutions, which may require further fetches but these
    // should be using cached results
    for (MapEntry entry in _substitutionHeaders.entries) {
      String header = entry.key;
      String prefix = entry.value;
      String? value = request.headers.value(header);
      if ((value != null) &&
          value.startsWith(prefix) &&
          (value.length > prefix.length)) {
        // perform the request to get the secure string for the header value
        final Map<String, dynamic> arguments = <String, dynamic>{
          "key": value.substring(prefix.length),
          "newDef": null,
        };
        _TokenFetchResult fetchResult;
        try {
          Map fetchResultMap = await _channel.invokeMethod(
              'fetchSecureStringAndWait', arguments);
          fetchResult =
              _TokenFetchResult.fromTokenFetchResultMap(fetchResultMap);
          Log.d(
              "$TAG: updateRequest substituting header $header: ${fetchResult.tokenFetchStatus.name}");
        } catch (err) {
          throw ApproovException('$err');
        }

        // process the returned Approov status
        if (fetchResult.tokenFetchStatus == _TokenFetchStatus.SUCCESS)
          // substitute the header value
          request.headers.set(header, prefix + fetchResult.secureString!,
              preserveHeaderCase: true);
        else if (fetchResult.tokenFetchStatus == _TokenFetchStatus.REJECTED)
          // if the request is rejected then we provide a special exception with additional information
          throw new ApproovRejectionException(
              "Header substitution for $header: ${fetchResult.tokenFetchStatus.name}: ${fetchResult.ARC} ${fetchResult.rejectionReasons}",
              fetchResult.ARC,
              fetchResult.rejectionReasons);
        else if ((fetchResult.tokenFetchStatus ==
                _TokenFetchStatus.NO_NETWORK) ||
            (fetchResult.tokenFetchStatus == _TokenFetchStatus.POOR_NETWORK) ||
            (fetchResult.tokenFetchStatus == _TokenFetchStatus.MITM_DETECTED)) {
          // we are unable to get the secure string due to network conditions so the request can
          // be retried by the user later - unless overridden
          if (!_proceedOnNetworkFail)
            throw new ApproovNetworkException(
                "Header substitution for $header: ${fetchResult.tokenFetchStatus.name}");
        } else if (fetchResult.tokenFetchStatus !=
            _TokenFetchStatus.UNKNOWN_KEY)
          // we are unable to get the secure string due to a more permanent error
          throw new ApproovException(
              "Header substitution for $header: ${fetchResult.tokenFetchStatus.name}");
      }
    }
  }

  /// Retrieves the certificates in the chain for the specified host. These are obtained at the platform level and we
  /// cache them so subsequent requests don't require another probe.
  ///
  /// @param host is the URL specifying the host for which to retrieve the certificates (e.g. "www.example.com")
  /// @return a list of certificates (each as a Uint8list) for the host specified in the URL, null if an error occurred,
  /// or an empty list if no suitable certificates are available.
  static Future<List<Uint8List>?> _getHostCertificates(Uri url) async {
    final Map<String, dynamic> arguments = <String, dynamic>{
      "url": url.toString(),
    };
    List<Uint8List>? hostCertificates = _hostCertificates[url.host];
    if (hostCertificates == null) {
      try {
        // fetch the certificates using the platform layer
        List fetchedHostCertificates =
            await _channel.invokeMethod('fetchHostCertificates', arguments);
        if ((fetchedHostCertificates != null) &&
            (fetchedHostCertificates.length != 0)) {
          hostCertificates = [];
          for (final cert in fetchedHostCertificates) {
            hostCertificates.add(cert as Uint8List);
          }

          // cache the obtained host certificates
          _hostCertificates[url.host] = hostCertificates;
        }
      } catch (err) {
        // do not throw an exception, but let the function return null
      }
    }
    return hostCertificates;
  }

  /// Removes the certificates for the specified host from the cache. This causes them to be retrieved over the
  /// network the next time _getHostCertificates() is called.
  ///
  /// @param host is the host for which to remove the certificates (e.g. "www.example.com")
  static Future<void> _removeCertificates(String host) async {
    _hostCertificates[host] = null;
  }

  /// Removes all certificates from the cache. This is required when the Approov pins change.
  static Future<void> _removeAllCertificates() async {
    _hostCertificates.clear();
  }

  /// Computes the SHA256 digest of the Subject Public Key Info (SPKI) of an ASN1.DER encoded certificate.
  ///
  /// @param certificate for which to compute the SPKI digest
  /// @return the SHA256 digest of the certificate's SPKI
  static Digest _spkiSha256Digest(Uint8List certificate) {
    ASN1Parser asn1Parser = ASN1Parser(certificate);
    ASN1Sequence signedCert = asn1Parser.nextObject() as ASN1Sequence;
    ASN1Sequence cert = signedCert.elements[0] as ASN1Sequence;
    ASN1Sequence spki = cert.elements[6] as ASN1Sequence;
    Digest spkiDigest = sha256.convert(spki.encodedBytes);
    return spkiDigest;
  }

  /// Gets all certificates of a host that match the Approov pins for that host. A match is determined by comparing
  /// the certificate's SPKI's SHA256 digest with the Approov pins. We firstly get the certificate chain for the
  /// host (which may have been previously cached) and then we restrict it to those corresponding to pinned
  /// certifificates.
  ///
  /// @param url of the host that is being pinned
  /// @param approovPins is the set of pins for the host as configured in Approov
  /// @return a list of host certificates that match the Approov pins
  static Future<List<Uint8List>> _hostPinCertificates(
      Uri url, Set<String> approovPins) async {
    // get certificates for host
    List<Uint8List>? hostCertificates =
        await ApproovService._getHostCertificates(url);
    if (hostCertificates == null) {
      // if there are none then we return an empty list, which will cause a failure when we try and connect
      Log.d("$TAG: Cannot get certificates for $url");
      return [];
    }

    // collect only those certificates for pinning that match the Approov pins
    String info = "Certificate chain for $url: ";
    bool isFirst = true;
    List<Uint8List> hostPinCerts = [];
    for (final cert in hostCertificates) {
      Uint8List serverSpkiSha256Digest =
          Uint8List.fromList(_spkiSha256Digest(cert).bytes);
      if (!isFirst) info += ", ";
      isFirst = false;
      info += base64.encode(serverSpkiSha256Digest);
      for (final pin in approovPins) {
        if (ListEquality().equals(base64.decode(pin), serverSpkiSha256Digest)) {
          hostPinCerts.add(cert);
          info += " pinned";
        }
      }
    }
    Log.d("$TAG: $info");
    return hostPinCerts;
  }

  /// Create a security context that enforces pinning to host certificates whose SPKI SHA256 digest match an Approov
  /// pin. If no certificates match, the security context does not contain any host certificates and creating a TLS
  /// connection to the host will fail. These certificates that match a pin are set to the trusted certificates for the
  /// security context so that connections are restricted to ensure one of those certificates is present.
  ///
  /// @param url of the host that is being pinned
  /// @param approovPins is the set of pins for the host as configured in Approov
  /// @return a security context that enforces pinning by using the host certificates that match the pins set in Approov
  static Future<SecurityContext> _pinnedSecurityContext(
      Uri url, Set<String> approovPins) async {
    // determine the list of X.509 ASN.1 DER host certificates that match any Approov pins for the host - if this
    // returns an empty list then nothing will be trusted
    List<Uint8List> pinCerts =
        await ApproovService._hostPinCertificates(url, approovPins);

    // add the certificates to create the security context of trusted certs
    SecurityContext securityContext = SecurityContext(withTrustedRoots: false);
    for (final pinCert in pinCerts) {
      String pemCertificate = PemCodec(PemLabel.certificate).encode(pinCert);
      Uint8List pemCertificatesBytes = AsciiEncoder().convert(pemCertificate);
      securityContext.setTrustedCertificatesBytes(pemCertificatesBytes);
    }
    Log.d(
        "$TAG: Pinned security context with ${pinCerts.length} trusted certs, from ${approovPins.length} possible pins");
    return securityContext;
  }
}

/// Possible write operations that may need to be placed in the pending list
enum _WriteOpType {
  unknown,
  add,
  addError,
  write,
  writeAll,
  writeCharCode,
  writeln
}

/// Holds a pending write operation that must be delayed because issuing it immediately
/// would cause the headers to become immutable, but it is not possible to update the headers
/// because this can only be done in an async method that returns a Future to ensure that the
/// caller will wait for it to be completed.
class _PendingWriteOp {
  // state held for an individual pending write operation
  _WriteOpType type = _WriteOpType.unknown;
  List<int>? data;
  Object? error;
  StackTrace? stackTrace;
  Object? object;
  Iterable? objects;
  String? separator;
  int charCode = 0;

  void add(List<int> data) {
    this.type = _WriteOpType.add;
    this.data = data;
  }

  void addError(Object error, [StackTrace? stackTrace]) {
    this.type = _WriteOpType.addError;
    this.error = error;
    this.stackTrace = stackTrace;
  }

  void write(Object? object) {
    this.type = _WriteOpType.write;
    this.object = object;
  }

  void writeAll(Iterable objects, [String separator = ""]) {
    this.type = _WriteOpType.writeAll;
    this.objects = objects;
    this.separator = separator;
  }

  void writeCharCode(int charCode) {
    this.type = _WriteOpType.writeCharCode;
    this.charCode = charCode;
  }

  void writeln([Object? object = ""]) {
    this.type = _WriteOpType.writeln;
    this.object = object;
  }

  void performOperation(HttpClientRequest delegateRequest) {
    switch (type) {
      case _WriteOpType.add:
        delegateRequest.add(data!);
        break;
      case _WriteOpType.addError:
        delegateRequest.addError(error!, stackTrace);
        break;
      case _WriteOpType.write:
        delegateRequest.write(object);
        break;
      case _WriteOpType.writeAll:
        delegateRequest.writeAll(objects!, separator!);
        break;
      case _WriteOpType.writeCharCode:
        delegateRequest.writeCharCode(charCode);
        break;
      case _WriteOpType.writeln:
        delegateRequest.writeln(object);
        break;
    }
  }
}

/// Approov version of an HttpClientRequest, which delegates to an HttpClientRequest provided by the standard HttpClient. This
/// is necessary because Approov needs to be able to read, add and modify outgoing headers. This cannot be done at the time
/// of initial connection since the headers will not have been added at this time, and these are required for the token binding
/// and secret protection options (where a placeholder value in a header is replaced by the actual secret). Things are complicated
/// by the fact that headers are only mutable until anything is written to the body. Thus the headers are updated just before any
/// operation that updates the body. This is further limited by the fact that the updates can only be done on functions that return
/// a future (since the Approov fetch is an asynchronous operation), so some operaions have to be delayed until a suitable method is
/// called, knowing that in the worst case it can be performed when "close" is called.
class _ApproovHttpClientRequest implements HttpClientRequest {
  // request to be delegated to
  late HttpClientRequest _delegateRequest;

  // list of write operations (that update the body of the request) which have been delayed until there
  // is a possibility of updating the headers in the request with Approov
  List<_PendingWriteOp> _pendingWriteOps = <_PendingWriteOp>[];

  // true if the request has been updated with Approov related headers
  bool _requestUpdated = false;

  // Construct a new _ApproovHttpClientRequest that delegates to the given request. This adds Approov as late as possible while
  // the headers are still mutable.
  //
  // @param request is the HttpClientRequest to be delegated to
  _ApproovHttpClientRequest(HttpClientRequest request) {
    _delegateRequest = request;
  }

  // Updates the request if that is required. This may require the headers to be updated and therefore it cannot be
  // done after write operations to the body which make the headers immutable (as they may have already been transmitted).
  // Thus pending write operations are held and issue after the header updates.
  Future _updateRequestIfRequired() async {
    if (!_requestUpdated) {
      // update the request while the headers can still be mutated
      await ApproovService._updateRequest(_delegateRequest);
      _requestUpdated = true;

      // now perform any pending write operations
      for (final pendingWriteOp in _pendingWriteOps) {
        pendingWriteOp.performOperation(_delegateRequest);
      }
      _pendingWriteOps = <_PendingWriteOp>[];
    }
  }

  @override
  set bufferOutput(bool _bufferOutput) =>
      _delegateRequest.bufferOutput = _bufferOutput;
  @override
  bool get bufferOutput => _delegateRequest.bufferOutput;

  @override
  HttpConnectionInfo? get connectionInfo => _delegateRequest.connectionInfo;

  @override
  set contentLength(int _contentLength) =>
      _delegateRequest.contentLength = _contentLength;
  @override
  int get contentLength => _delegateRequest.contentLength;

  @override
  List<Cookie> get cookies => _delegateRequest.cookies;

  @override
  Future<HttpClientResponse> get done => _delegateRequest.done;

  @override
  set encoding(Encoding _encoding) => _delegateRequest.encoding = _encoding;
  @override
  Encoding get encoding => _delegateRequest.encoding;

  @override
  set followRedirects(bool _followRedirects) =>
      _delegateRequest.followRedirects = _followRedirects;
  @override
  bool get followRedirects => _delegateRequest.followRedirects;

  @override
  HttpHeaders get headers => _delegateRequest.headers;

  @override
  set maxRedirects(int _maxRedirects) =>
      _delegateRequest.maxRedirects = _maxRedirects;
  @override
  int get maxRedirects => _delegateRequest.maxRedirects;

  @override
  String get method => _delegateRequest.method;

  @override
  set persistentConnection(bool _persistentConnection) =>
      _delegateRequest.persistentConnection = _persistentConnection;
  @override
  bool get persistentConnection => _delegateRequest.persistentConnection;

  @override
  Uri get uri => _delegateRequest.uri;

  @override
  void abort([Object? exception, StackTrace? stackTrace]) {
    _delegateRequest.abort(exception, stackTrace);
  }

  @override
  void add(List<int> data) {
    if (_requestUpdated)
      _delegateRequest.add(data);
    else {
      _PendingWriteOp pendingWriteOp = new _PendingWriteOp();
      pendingWriteOp.add(data);
      _pendingWriteOps.add(pendingWriteOp);
    }
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {
    if (_requestUpdated)
      _delegateRequest.addError(error, stackTrace);
    else {
      _PendingWriteOp pendingWriteOp = new _PendingWriteOp();
      pendingWriteOp.addError(error, stackTrace);
      _pendingWriteOps.add(pendingWriteOp);
    }
  }

  @override
  Future addStream(Stream<List<int>> stream) async {
    await _updateRequestIfRequired();
    return _delegateRequest.addStream(stream);
  }

  @override
  Future<HttpClientResponse> close() async {
    await _updateRequestIfRequired();
    return _delegateRequest.close();
  }

  @override
  Future flush() async {
    await _updateRequestIfRequired();
    return _delegateRequest.flush();
  }

  @override
  void write(Object? object) {
    if (_requestUpdated)
      _delegateRequest.write(object);
    else {
      _PendingWriteOp pendingWriteOp = new _PendingWriteOp();
      pendingWriteOp.write(object);
      _pendingWriteOps.add(pendingWriteOp);
    }
  }

  @override
  void writeAll(Iterable objects, [String separator = ""]) {
    if (_requestUpdated)
      _delegateRequest.writeAll(objects, separator);
    else {
      _PendingWriteOp pendingWriteOp = new _PendingWriteOp();
      pendingWriteOp.writeAll(objects, separator);
      _pendingWriteOps.add(pendingWriteOp);
    }
  }

  @override
  void writeCharCode(int charCode) {
    if (_requestUpdated)
      _delegateRequest.writeCharCode(charCode);
    else {
      _PendingWriteOp pendingWriteOp = new _PendingWriteOp();
      pendingWriteOp.writeCharCode(charCode);
      _pendingWriteOps.add(pendingWriteOp);
    }
  }

  @override
  void writeln([Object? object = ""]) {
    if (_requestUpdated)
      _delegateRequest.writeln(object);
    else {
      _PendingWriteOp pendingWriteOp = new _PendingWriteOp();
      pendingWriteOp.writeln(object);
      _pendingWriteOps.add(pendingWriteOp);
    }
  }
}

/// ApproovHttpClient is a drop-in replacement for the Dart IO library's HttpClient. If Approov is configured to protect
/// an API on a host, then an ApproovHTTPClient will automatically set up pinning and add relevant headers for a request,
/// and also provide secret substitution if required. Otherwise the behaviour of ApproovHttpClient is the same as for the
/// Dart IO library's HttpClient.
class ApproovHttpClient implements HttpClient {
  // logging tag
  static const String TAG = "ApproovHttpClient";

  // internal HttpClient delegate, will be rebuilt if pinning fails (or pins change). It is not set to a pinned
  // HttpClient initially, but this is just used to hold any state updates that might occur before a connection
  // request forces a pinned HttpClient to be used.
  HttpClient _delegatePinnedHttpClient = HttpClient();

  // any future delegated pinned HttpClient that is currently being created - this is used to force serialization
  // of delegate creation in case there are many open operations in flight concurrently
  Future<HttpClient>? _futureDelegatePinnedHttpClient;

  // the host to which the delegate pinned HttpClient delegate is connected and, optionally, pinning. Used to detect when to
  // re-create the delegate pinned HttpClient.
  String? _connectedHost;

  // indicates whether the ApproovHttpClient has been closed by calling close().
  bool _isClosed = false;

  // state required to implement getters and setters required by the HttpClient interface
  Future<bool> Function(Uri url, String scheme, String? realm)? _authenticate;
  Future<ConnectionTask<Socket>> Function(
      Uri url, String? proxyHost, int? proxyPort)? _connectionFactory;
  void Function(String line)? _keyLog;
  final List _credentials = [];
  String Function(Uri url)? _findProxy;
  Future<bool> Function(String host, int port, String scheme, String? realm)?
      _authenticateProxy;
  final List _proxyCredentials = [];
  bool Function(X509Certificate cert, String host, int port)?
      _badCertificateCallback;

  /// Pinning failure callback function for the badCertificateCallback of HttpClient. This is called if the pinning
  /// certificate check failed, which can indicate a certificate update on the server or a Man-in-the-Middle (MitM)
  /// attack. It invalidates the certificates for the given host so they will be refreshed and the communication with
  /// the server can be re-established for the case of a certificate update. Returns false to prevent the request to
  /// be sent for the case of a MitM attack.
  ///
  /// @param cert is the certificate which could not be authenticated
  /// @param host is the host name of the server to which the request is being sent
  /// @param port is the port of the server
  bool _pinningFailureCallback(X509Certificate cert, String host, int port) {
    Function(X509Certificate cert, String host, int port)?
        badCertificateCallback = _badCertificateCallback;
    if (badCertificateCallback != null) {
      // call the user defined function for its side effects only (as we are going to reject anyway)
      badCertificateCallback(cert, host, port);
    }

    // reset host certificates and delegate pinned HttpClient connected host to force them to be recreated
    Log.d("$TAG: Pinning failure callback for $host");
    ApproovService._removeCertificates(host);
    _connectedHost = null;
    return false;
  }

  /// Create an HTTP client with pinning enabled for the given host if so configured in Approov. The state for the new
  /// HTTP client is copied from the current delegate.
  ///
  /// @param url for which to set up pinning
  /// @return the new HTTP client
  Future<HttpClient> _createPinnedHttpClient(Uri url) async {
    // fetch an Approov token to get the latest configuration - but note we do not fail if a token fetch was not possible
    _TokenFetchResult fetchResult =
        await ApproovService._fetchApproovToken(url.host);
    Log.d(
        "$TAG: pinning setup fetch token for ${url.host}: ${fetchResult.tokenFetchStatus.name}");

    // if the config has changed (and therefore pins may have updated) then clear any cached certificates - fetching the
    // config clears the config changed state)
    if (fetchResult.isConfigChanged) {
      await ApproovService._fetchConfig();
      ApproovService._removeAllCertificates();
    }

    // get pins from Approov - note that it is still possible at this point if the token fetch failed that no pins
    // have are available, in which case we detect that at the time we are processing a request to add Approov
    Map allPins = await ApproovService._getPins("public-key-sha256");

    // if we didn't manage to fetch a token before then it is possible we have never fetched a token and therefore
    // not have any available pins - we force another token fetch in that case so that we can check
    bool forceNoConnection = false;
    if ((fetchResult.tokenFetchStatus != _TokenFetchStatus.SUCCESS) &&
        (fetchResult.tokenFetchStatus != _TokenFetchStatus.UNKNOWN_URL)) {
      // perform another attempted token fetch
      fetchResult = await ApproovService._fetchApproovToken(url.host);
      Log.d(
          "$TAG: pinning setup retry fetch token for ${url.host}: ${fetchResult.tokenFetchStatus.name}");

      // if we are forced to update pins then this likely means that no pins were ever fetched and in this
      // case we must force a no connection when so that another fetched can be tried again - this is because
      // once a connection is made it might not be dropped until the app is executed so there is no possibility
      // to retry and get the pins without restarting the app
      forceNoConnection = fetchResult.isForceApplyPins;
    }

    // get any pins defined for the host domain
    List pins = List.empty();
    if ((allPins != null) && (allPins[url.host] != null)) {
      // get the pins for the host
      pins = (allPins[url.host] as List);

      // if there are no pins for the host domain then we use any associated with the managed trust roots instead - note
      // this means that this will only be applied to domains added in Approov
      if (pins.isEmpty && (allPins["*"] != null)) pins = (allPins["*"] as List);
    }

    // construct a new http client
    HttpClient? newHttpClient;
    if (forceNoConnection) {
      // we have been unable to obtain the pins so we need to force the client to not connect
      // by not trusting anything - this will give us a further opportunity to fetch pins again
      // later when network connectivity may have resumed
      SecurityContext securityContext =
          SecurityContext(withTrustedRoots: false);
      newHttpClient = HttpClient(context: securityContext);
      Log.d("$TAG: forcing no connection for ${url.host}");
    } else if (pins.isEmpty)
      // if there are no pins then we can just use a standard http client
      newHttpClient = HttpClient();
    else {
      // create HttpClient with pinning enabled by determining the particular certificates we should trust
      Set<String> approovPins = HashSet();
      for (final pin in pins) {
        approovPins.add(pin);
      }
      SecurityContext securityContext =
          await ApproovService._pinnedSecurityContext(url, approovPins);
      newHttpClient = HttpClient(context: securityContext);
    }

    // remember the connected host so we don't have to repeat this for connections to the same host
    _connectedHost = url.host;

    // copy state from old HttpClient to the new one, including state held on this class which cannot be retrieved
    HttpClient? oldHttpClient = _delegatePinnedHttpClient;
    if (oldHttpClient != null) {
      newHttpClient.idleTimeout = oldHttpClient.idleTimeout;
      newHttpClient.connectionTimeout = oldHttpClient.connectionTimeout;
      newHttpClient.maxConnectionsPerHost = oldHttpClient.maxConnectionsPerHost;
      newHttpClient.autoUncompress = oldHttpClient.autoUncompress;
      newHttpClient.authenticate = _authenticate;
      newHttpClient.connectionFactory = _connectionFactory;
      newHttpClient.keyLog = _keyLog;
      for (var credential in _credentials) {
        newHttpClient.addCredentials(
            credential[0], credential[1], credential[2]);
      }
      newHttpClient.findProxy = _findProxy;
      newHttpClient.authenticateProxy = _authenticateProxy;
      for (var proxyCredential in _proxyCredentials) {
        newHttpClient.addProxyCredentials(proxyCredential[0],
            proxyCredential[1], proxyCredential[2], proxyCredential[3]);
      }
      newHttpClient.badCertificateCallback = _pinningFailureCallback;
    }

    // provide the new http client with a pinned security context
    return newHttpClient;
  }

  // Don't allow use of the default constructor without an initial configuration.
  ApproovHttpClient._() {}

  // Constructor for a custom Approov HttpClient. The config can be obtained using the Approov CLI or is also available in
  // the original onboarding email.
  //
  // @param initialConfig is the config string for the account
  ApproovHttpClient(String initialConfig, [String? initialComment]) : super() {
    ApproovService.initialize(initialConfig, initialComment);
  }

  @override
  Future<HttpClientRequest> open(
      String method, String host, int port, String path) async {
    // serialize if we are already creating a future delegate pinned http client - we
    // might be able to use that if it is for the same host
    if (_futureDelegatePinnedHttpClient != null) {
      await _futureDelegatePinnedHttpClient;
    }

    // if already closed then just delegate
    if (_isClosed) {
      return _delegatePinnedHttpClient.open(method, host, port, path);
    }

    // if we have an active connection to a different host we need to tear down the delegate
    // pinned HttpClient and create a new one with the correct pinning
    if (_connectedHost != host) {
      Uri url = Uri(scheme: "https", host: host, port: port, path: path);
      Future<HttpClient> futureDelegatePinnedHttpClient =
          _createPinnedHttpClient(url);
      _futureDelegatePinnedHttpClient = futureDelegatePinnedHttpClient;
      HttpClient httpClient = await futureDelegatePinnedHttpClient;
      _futureDelegatePinnedHttpClient = null;
      _delegatePinnedHttpClient.close();
      _delegatePinnedHttpClient = httpClient;
    }

    // delegate the open operation to the pinned http client and then wrap the provided HttpClientRequest
    return _delegatePinnedHttpClient
        .open(method, host, port, path)
        .then((request) {
      return _ApproovHttpClientRequest(request);
    });
  }

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    // serialize if we are already creating a future delegate pinned http client - we
    // might be able to use that if it is for the same host
    if (_futureDelegatePinnedHttpClient != null) {
      await _futureDelegatePinnedHttpClient;
    }

    // if already closed then just delegate
    if (_isClosed) {
      return _delegatePinnedHttpClient.openUrl(method, url);
    }

    // if we have an active connection to a different host we need to tear down the delegate
    // pinned HttpClient and create a new one with the correct pinning
    if (_connectedHost != url.host) {
      Future<HttpClient> futureDelegatePinnedHttpClient =
          _createPinnedHttpClient(url);
      _futureDelegatePinnedHttpClient = futureDelegatePinnedHttpClient;
      HttpClient httpClient = await futureDelegatePinnedHttpClient;
      _futureDelegatePinnedHttpClient = null;
      _delegatePinnedHttpClient.close();
      _delegatePinnedHttpClient = httpClient;
    }

    // delegate the open operation to the pinned http client and then wrap the provided HttpClientRequest
    return _delegatePinnedHttpClient.openUrl(method, url).then((request) {
      return _ApproovHttpClientRequest(request);
    });
  }

  @override
  Future<HttpClientRequest> get(String host, int port, String path) =>
      open("get", host, port, path);

  @override
  Future<HttpClientRequest> getUrl(Uri url) => openUrl("get", url);

  @override
  Future<HttpClientRequest> post(String host, int port, String path) =>
      open("post", host, port, path);

  @override
  Future<HttpClientRequest> postUrl(Uri url) => openUrl("post", url);

  @override
  Future<HttpClientRequest> put(String host, int port, String path) =>
      open("put", host, port, path);

  @override
  Future<HttpClientRequest> putUrl(Uri url) => openUrl("put", url);

  @override
  Future<HttpClientRequest> delete(String host, int port, String path) =>
      open("delete", host, port, path);

  @override
  Future<HttpClientRequest> deleteUrl(Uri url) => openUrl("delete", url);

  @override
  Future<HttpClientRequest> head(String host, int port, String path) =>
      open("head", host, port, path);

  @override
  Future<HttpClientRequest> headUrl(Uri url) => openUrl("head", url);

  @override
  Future<HttpClientRequest> patch(String host, int port, String path) =>
      open("patch", host, port, path);

  @override
  Future<HttpClientRequest> patchUrl(Uri url) => openUrl("patch", url);

  @override
  set idleTimeout(Duration timeout) =>
      _delegatePinnedHttpClient.idleTimeout = timeout;
  @override
  Duration get idleTimeout => _delegatePinnedHttpClient.idleTimeout;

  @override
  set connectionTimeout(Duration? timeout) =>
      _delegatePinnedHttpClient.connectionTimeout = timeout;
  @override
  Duration? get connectionTimeout =>
      _delegatePinnedHttpClient.connectionTimeout;

  @override
  set maxConnectionsPerHost(int? maxConnections) =>
      _delegatePinnedHttpClient.maxConnectionsPerHost = maxConnections;
  @override
  int? get maxConnectionsPerHost =>
      _delegatePinnedHttpClient.maxConnectionsPerHost;

  @override
  set autoUncompress(bool autoUncompress) =>
      _delegatePinnedHttpClient.autoUncompress = autoUncompress;
  @override
  bool get autoUncompress => _delegatePinnedHttpClient.autoUncompress;

  @override
  set userAgent(String? userAgent) =>
      _delegatePinnedHttpClient.userAgent = userAgent;
  @override
  String? get userAgent => _delegatePinnedHttpClient.userAgent;

  @override
  set authenticate(Future<bool> f(Uri url, String scheme, String? realm)?) {
    _authenticate = f;
    _delegatePinnedHttpClient.authenticate = f;
  }

  @override
  set connectionFactory(
      Future<ConnectionTask<Socket>> f(
          Uri url, String? proxyHost, int? proxyPort)?) {
    _connectionFactory = f;
    _delegatePinnedHttpClient.connectionFactory = f;
  }

  @override
  set keyLog(void f(String line)?) {
    _keyLog = f;
    _delegatePinnedHttpClient.keyLog = f;
  }

  @override
  void addCredentials(
      Uri url, String realm, HttpClientCredentials credentials) {
    _credentials.add({url, realm, credentials});
    _delegatePinnedHttpClient.addCredentials(url, realm, credentials);
  }

  @override
  set findProxy(String f(Uri url)?) {
    _findProxy = f;
    _delegatePinnedHttpClient.findProxy = f;
  }

  @override
  set authenticateProxy(
      Future<bool> f(String host, int port, String scheme, String? realm)?) {
    _authenticateProxy = f;
    _delegatePinnedHttpClient.authenticateProxy = f;
  }

  @override
  void addProxyCredentials(
      String host, int port, String realm, HttpClientCredentials credentials) {
    _proxyCredentials.add({host, port, realm, credentials});
    _delegatePinnedHttpClient.addProxyCredentials(
        host, port, realm, credentials);
  }

  @override
  set badCertificateCallback(
      bool callback(X509Certificate cert, String host, int port)?) {
    _badCertificateCallback = callback;
  }

  @override
  void close({bool force: false}) async {
    if (_delegatePinnedHttpClient != null) {
      _delegatePinnedHttpClient.close(force: force);
      _isClosed = true;
    }
  }
}

// ApproovClient is a drop-in replacement for client from the Flutter http package (https://pub.dev/packages/http).
// This class is designed to be composable. This makes it easy for external libraries to work with one another to add
// behavior to it. Libraries wishing to add behavior should create a subclass of BaseClient that wraps an ApproovClient
// and adds the desired behavior.
class ApproovClient extends http.BaseClient {
  // logging tag
  static const String TAG = "ApproovClient";

  // initial configuration to supply to delegate ApproovHttpClients
  late String _initialConfig;

  // optional comment string to use alongside initial configuration
  String? _initialComment;

  // internal client delegate used to perform the actual requests
  http.Client? _delegateClient;

  // DOn't allow construction of an ApproovClient without an initial configuration.
  ApproovClient._() {}

  // Constructor for a custom Approov client. The config can be obtained using the Approov CLI or is also available in
  // the original onboarding email.
  //
  // @param initialConfig is the config string for the account
  // @param initialComment is an optional comment string to use alongside the initial configuration
  ApproovClient(String initialConfig, [String? initialComment]) : super() {
    _initialConfig = initialConfig;
    _initialComment = initialComment;
    ApproovService.initialize(initialConfig, initialComment);
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    // construct the client delegate on demand
    http.Client? delegateClient = _delegateClient;
    if (delegateClient == null) {
      ApproovHttpClient httpClient =
          ApproovHttpClient(_initialConfig, _initialComment);
      delegateClient = httpio.IOClient(httpClient);
      _delegateClient = delegateClient;
    }

    // now send using the delegate http client
    return delegateClient.send(request);
  }

  @override
  void close() {
    http.Client? delegateClient = _delegateClient;
    if (delegateClient != null) {
      delegateClient.close();
      _delegateClient = null;
    }
  }
}
