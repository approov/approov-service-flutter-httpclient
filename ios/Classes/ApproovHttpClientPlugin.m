/**
* Copyright (c) 2022-2025 Approov Ltd.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
* associated documentation files (the "Software"), to deal in the Software without restriction,
* including without limitation the rights to use, copy, modify, merge, publish, distribute,
* sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or
* substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
* NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
* DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
* OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#import "ApproovHttpClientPlugin.h"
#import "Approov/Approov.h"

// Timeout in seconds for a getting the host certificates
static const NSTimeInterval FETCH_CERTIFICATES_TIMEOUT = 3;

// Definition for a special class to fetch host certificates by implementing a NSURLSessionTaskDelegate that
// is called upon initial connection to get the certificates but the connection is dropped at that point.
@interface CertificatesFetcher: NSObject<NSURLSessionTaskDelegate>

/**
 * Initialize ready to fetch certificates for a host.
 *
 * @param transactionID is the transaction ID to use for the fetch
 * @param channel is the FlutterMethodChannel to use any callback to Flutter or nil if not required
 */
- (nullable instancetype)initWithTransactionID:(NSString *)transactionID channel:(FlutterMethodChannel *)channel;

/**
 * Fetches the certificates for a host by setting up an HTTPS GET request and harvests the certificates
 * that are obtained by the NSURLSessionTaskDelegate protocol. The certificates are then provided back to
 * the Dart Flutter layer using a callback. A transaction ID is used to identify the request.
 *
 * @param url is the URL to be used for the lookup
 */
- (void)fetchWithURL:(NSURL *_Nonnull)url;

/**
 * Get the result from the certificate fetch, waiting if the result is not yet available.
 *
 * @return result map provided after connection
 */
- (NSDictionary *)getResult;

// NSString of the transaction ID for the fetch
@property NSString *transactionID;

// FlutterMethodChannel to use for any callback to Flutter or nil if no callback is needed
@property FlutterMethodChannel *channel;

// NSURLSession to use for the certificate fetch
@property NSURLSession *session;

// Host certificates that were fetched
@property NSArray<FlutterStandardTypedData *> *hostCertificates;

// Dispatch group to indicate when the fetch is complete
@property dispatch_group_t group;

// The results from the fetch operation
@property NSMutableDictionary *results;

@end

// Implementation of the CertificatesFetcher which obtains certificate chains for a particular domain
// in order to implement the pinning.
@implementation CertificatesFetcher

// see interface for documentation
- (nullable instancetype)initWithTransactionID:(NSString *)transactionID channel:(FlutterMethodChannel *)channel
{
    self = [super init];
    if (self) {
        // hold the parameters for when the request is made
        _transactionID = transactionID;
        _channel = channel;
        _results = [NSMutableDictionary dictionary];

        // create the Session for the subsequent request
        NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        sessionConfig.timeoutIntervalForResource = FETCH_CERTIFICATES_TIMEOUT;
        _session = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:nil];

        // create a dispatch group and enter it to determine when the fetch is complete
        _group = dispatch_group_create();
        dispatch_group_enter(_group);
    }
    return self;
}

// see interface for documentation
- (void)fetchWithURL:(NSURL *_Nonnull)url
{
    // create the request
    NSMutableURLRequest *certFetchRequest = [NSMutableURLRequest requestWithURL:url];
    [certFetchRequest setTimeoutInterval:FETCH_CERTIFICATES_TIMEOUT];
    [certFetchRequest setHTTPMethod:@"GET"];

    // get session task to issue the request and write back the results to the Flutter Dart layer
    NSURLSessionDataTask *certFetchTask = [_session dataTaskWithRequest:certFetchRequest
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error)
        {
            // we expect error cancelled because URLSession:task:didReceiveChallenge:completionHandler: always deliberately
            // fails the challenge because we don't need the request to succeed to retrieve the certificates
            self->_results[@"TransactionID"] = self->_transactionID;
            if (error == nil) {
                // if no error occurred, the certificate check of the NSURLSessionTaskDelegate protocol has not been called.
                // Don't provide any host certificates.
                self->_results[@"Error"] = @"Failed to get host certificates";
            } else if (error.code != NSURLErrorCancelled) {
                // if an error other than NSURLErrorCancelled occurred, don't return any host certificates
                self->_results[@"Error"] = [NSString stringWithFormat:@"Failed to get host certificates with error: %@",
                    error.localizedDescription];
            } else {
                // the host certificates have been collected by the URLSession:task:didReceiveChallenge:completionHandler: method
                self->_results[@"Certificates"] = self->_hostCertificates;
            }

            // leave the dispatch group to indicate that the results are available
            dispatch_group_leave(self->_group);

            // send the results back to the Flutter layer if required, but we can only do this on the main thread
            if (self->_channel != nil) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self->_channel invokeMethod:@"response" arguments:self->_results];
                });
            }
        }];

    // Make the request
    [certFetchTask resume];
}

// see interface for documentation
- (NSDictionary *)getResult {
    dispatch_group_wait(_group, DISPATCH_TIME_FOREVER);
    return _results;
}

// Collect the host certificates using the certificate check of the NSURLSessionTaskDelegate protocol
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    // ignore any requests that are not related to server trust
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
        return;

    // check we have a server trust
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    if (!serverTrust) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // check the validity of the server trust
    if (@available(iOS 12.0, *)) {
        if (!SecTrustEvaluateWithError(serverTrust, nil)) {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return;
        }
    }
    else {
        SecTrustResultType result;
        OSStatus status = SecTrustEvaluate(serverTrust, &result);
        if (errSecSuccess != status) {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return;
        }
    }

    // collect all the certs in the chain
    CFIndex certCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray<FlutterStandardTypedData *> *certs = [NSMutableArray arrayWithCapacity:(NSUInteger)certCount];
    for (int certIndex = 0; certIndex < certCount; certIndex++) {
        // get the chain certificate - note that this function is deprecated from iOS 15 but the
        // replacement function is only available from iOS 15 and has a very different interface so
        // we can't use it yet
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(serverTrust, certIndex);
        if (!cert) {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return;
        }
        NSData *certData = (NSData *) CFBridgingRelease(SecCertificateCopyData(cert));
        FlutterStandardTypedData *certFSTD = [FlutterStandardTypedData typedDataWithBytes:certData];
        [certs addObject:certFSTD];
    }

    // set the host certs to be returned
    _hostCertificates = certs;

    // fail the challenge as we only wanted the certificates
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

@end

// Definition for a utility class for providing a callback handler for receiving an Approov fetch
// result on an internal asynchronous request.
@interface InternalCallBackHandler: NSObject

/**
 * Initialize ready to handle asynchronous results.
 *
 * @param transactionID is the transaction ID to use for the fetch
 * @param channel is the FlutterMethodChannel to use any callback to Flutter or nil if not required
 * @param configEpoch is the configuration epoch that the fetch was made within
 */
- (nullable instancetype)initWithTransactionID:(NSString *)transactionID channel:(FlutterMethodChannel *)channel configEpoch:(int)configEpoch;

/**
 * Provides string mappings for the token fetch status with strings that are compatible with the common dart layer. This
 * uses the Android style.
 *
 * @param approovTokenFetchStatus the fetch status from the iOS Approov SDK
 * @return string representation of the status
 */
- (nonnull NSString *)stringFromApproovTokenFetchStatus:(ApproovTokenFetchStatus)approovTokenFetchStatus;

/**
 * Posts the result from the Approov SDK for an asynchronous fetch operation.
 *
 * @param tokenFetchResult is the result of the asynchronous fetch
 */
- (void)postWithTokenFetchResult:(ApproovTokenFetchResult *_Nonnull)tokenFetchResult;

/**
 * Get the result from fetch operation, waiting if the result is not yet available.
 *
 * @return result map provided from the result
 */
- (NSDictionary *)getResult;

// NSString of the transaction ID for the fetch
@property NSString *transactionID;

// FlutterMethodChannel to use for any callback to Flutter or nil if no callback is needed
@property FlutterMethodChannel *channel;

// configuration epoch that the fetch was made within
@property int configEpoch;

// Dispatch group to indicate when the fetch is complete
@property dispatch_group_t group;

// The results from the fetch operation
@property NSMutableDictionary *results;

@end

// Implementation for a utility class for providing a callback handler for receiving an Approov fetch
// result on an internal asynchronous request.
@implementation InternalCallBackHandler

// see interface for documentation
- (nullable instancetype)initWithTransactionID:(NSString *)transactionID channel:(FlutterMethodChannel *)channel configEpoch:(int)configEpoch
{
    self = [super init];
    if (self) {
        _transactionID = transactionID;
        _channel = channel;
        _configEpoch = configEpoch;
        _group = dispatch_group_create();
        _results = [NSMutableDictionary dictionary];
        dispatch_group_enter(_group);
    }
    return self;
}

// see interface for documentation
- (nonnull NSString *)stringFromApproovTokenFetchStatus:(ApproovTokenFetchStatus)approovTokenFetchStatus
{
    switch (approovTokenFetchStatus) {
        case ApproovTokenFetchStatusSuccess:
            return @"SUCCESS";
        case ApproovTokenFetchStatusNoNetwork:
            return @"NO_NETWORK";
        case ApproovTokenFetchStatusMITMDetected:
            return @"MITM_DETECTED";
        case ApproovTokenFetchStatusPoorNetwork:
            return @"POOR_NETWORK";
        case ApproovTokenFetchStatusNoApproovService:
            return @"NO_APPROOV_SERVICE";
        case ApproovTokenFetchStatusBadURL:
            return @"BAD_URL";
        case ApproovTokenFetchStatusUnknownURL:
            return @"UNKNOWN_URL";
        case ApproovTokenFetchStatusUnprotectedURL:
            return @"UNPROTECTED_URL";
        case ApproovTokenFetchStatusNotInitialized:
            return @"NOT_INITIALIZED";
        case ApproovTokenFetchStatusRejected:
            return @"REJECTED";
        case ApproovTokenFetchStatusDisabled:
            return @"DISABLED";
        case ApproovTokenFetchStatusUnknownKey:
            return @"UNKNOWN_KEY";
        case ApproovTokenFetchStatusBadKey:
            return @"BAD_KEY";
        case ApproovTokenFetchStatusBadPayload:
            return @"BAD_PAYLOAD";
        case ApproovTokenFetchStatusInternalError:
            return @"INTERNAL_ERROR";
        default:
            return @"UNKNOWN";
    }
}

// see interface for documentation
- (void)postWithTokenFetchResult:(ApproovTokenFetchResult *_Nonnull)tokenFetchResult
{
    // collect the results from the fetch
    _results[@"TransactionID"] = _transactionID;
    _results[@"TokenFetchStatus"] = [self stringFromApproovTokenFetchStatus:tokenFetchResult.status];
    if (tokenFetchResult.token != nil)
        _results[@"Token"] = tokenFetchResult.token;
    if (tokenFetchResult.secureString != nil)
        _results[@"SecureString"] = tokenFetchResult.secureString;
    if ( tokenFetchResult.ARC != nil)
        _results[@"ARC"] = tokenFetchResult.ARC;
    if (tokenFetchResult.rejectionReasons != nil)
        _results[@"RejectionReasons"] = tokenFetchResult.rejectionReasons;
    _results[@"IsConfigChanged"] = [NSNumber numberWithBool:tokenFetchResult.isConfigChanged];
    _results[@"IsForceApplyPins"] = [NSNumber numberWithBool:tokenFetchResult.isForceApplyPins];
    if (tokenFetchResult.measurementConfig != nil)
        _results[@"MeasurementConfig"] = tokenFetchResult.measurementConfig;
    if (tokenFetchResult.loggableToken != nil)
        _results[@"LoggableToken"] = tokenFetchResult.loggableToken;
    _results[@"ConfigEpoch"] = [NSNumber numberWithInt:_configEpoch];

    // leave the dispatch group to indicate that the results are available
    dispatch_group_leave(_group);

    // send the results back to the Flutter layer if required, but we can only do this on the main thread
    if (_channel != nil) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self->_channel invokeMethod:@"response" arguments:self->_results];
        });
    }
}

// see interface for documentation
- (NSDictionary *)getResult {
    dispatch_group_wait(_group, DISPATCH_TIME_FOREVER);
    return _results;
}

@end

@interface ApproovHttpClientPlugin()

// The method channel to use for the foreground communication with Flutter. This is used for all operations
// from the Dart root isolate including any callbacks to the Dart layer.
@property FlutterMethodChannel *fgChannel;

// The method channel to use for the background communication with Flutter. This is for operations that may block
// for some period called from background isolates and thus it uses a background task queue.
@property FlutterMethodChannel *bgChannel;

// Provides any prior initial configuration supplied, to allow a reinitialization caused by
// a hot restart if the configuration is the same or nil if not initialized.
@property NSString *initializedConfig;

// Provides any prior initial comment supplied, or empty string if none was provided
@property NSString *initializedComment;

// Counter for the configuration epoch that is incremented whenever the configuration is fetched. This keeps
// track of dynamic configuration changes and the state is held in the platform layer as we want this to work
// across multiple different isolates which have independent Dart level state.
@property int configEpoch;

// Active set of callback handlers to the Approov SDK - accessess to this must be protected as it could be
// accessed from multiple threads
@property NSMutableDictionary<NSString*, InternalCallBackHandler*> *activeCallBackHandlers;

// Active set of certificate fetches - accessess to this must be protected as it could be
// accessed from multiple threads
@property NSMutableDictionary<NSString*, CertificatesFetcher*> *activeCertFetches;  

@end

// ApproovHttpClientPlugin provides the bridge to the Approov SDK itself. Methods are initiated using the
// MethodChannel to call various methods within the SDK. A facility is also provided to probe the certificates
// presented on any particular URL to implement the pinning.
@implementation ApproovHttpClientPlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
    FlutterMethodChannel *fgChannel = [[FlutterMethodChannel alloc]
                 initWithName: @"approov_service_flutter_httpclient_fg"
              binaryMessenger: [registrar messenger]
                        codec: [FlutterStandardMethodCodec sharedInstance]];
    NSObject<FlutterTaskQueue>* taskQueue = [[registrar messenger] makeBackgroundTaskQueue];
    FlutterMethodChannel *bgChannel = [[FlutterMethodChannel alloc]
                 initWithName: @"approov_service_flutter_httpclient_bg"
              binaryMessenger: [registrar messenger]
                        codec: [FlutterStandardMethodCodec sharedInstance]
                    taskQueue: taskQueue];
    ApproovHttpClientPlugin* instance = [[ApproovHttpClientPlugin alloc] init];
    instance.fgChannel = fgChannel;
    [registrar addMethodCallDelegate:instance channel:fgChannel];
    instance.bgChannel = bgChannel;
    [registrar addMethodCallDelegate:instance channel:bgChannel];
    instance.configEpoch = 0;
    instance.activeCallBackHandlers = [NSMutableDictionary dictionary];
    instance.activeCertFetches = [NSMutableDictionary dictionary];
}

- (void)handleMethodCall:(FlutterMethodCall *)call result:(FlutterResult)result {
    if ([@"initialize" isEqualToString:call.method]) {
        // get the initialization arguments
        NSError* error = nil;
        NSString *initialConfig = call.arguments[@"initialConfig"];
        NSString *commentString = nil;
        if (call.arguments[@"comment"] != [NSNull null])
            commentString = call.arguments[@"comment"];
        else
            commentString = @"";

        // determine if the initialization is needed (indicated by a change in either the initial config string or the comment) -
        // this is necessary because hot restarts or the creation of new isolates means that the Dart level may not have determined
        // that the SDK is already initialized whereas this native layer holds its state
        if ((_initializedConfig == nil) || ![_initializedConfig isEqualToString:initialConfig] || ![_initializedComment isEqualToString:commentString]) {
            // this is a new config or a reinitialization
            NSString *updateConfig = nil;
            if (call.arguments[@"updateConfig"] != [NSNull null])
                updateConfig = call.arguments[@"updateConfig"];
            [Approov initialize:initialConfig updateConfig:updateConfig comment:commentString error:&error];
            if (error != nil) {
                // check if the error message contains "Approov SDK already initialized"
                if ([error.localizedDescription rangeOfString:@"Approov SDK already initialized" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    // log and ignore the error if the SDK is already initialized - this can happen if an app is using multiple
                    // different isolates and the initialization was made by a different quickstart (note we don't currently check
                    // for the compatibility of the SDK parameters but a future version of the SDK will do this to avoid needing to
                    // catch this at all)
                    NSLog(@"ApproovService: Ignoring initialization error in Approov SDK: %@", error.localizedDescription);
                } else {
                    result([FlutterError errorWithCode:[NSString stringWithFormat:@"%ld", (long)error.code]
                                            message:error.domain
                                            details:error.localizedDescription]);
                    return;
                }
            }
            _initializedConfig = initialConfig;
            _initializedComment = commentString;
            result(nil);
        } else {
            // the previous initialization is compatible
            result(nil);
        }
    } else if ([@"fetchConfig" isEqualToString:call.method]) {
        _configEpoch++;
        result([Approov fetchConfig]);
    } else if ([@"getConfigEpoch" isEqualToString:call.method]) {
        result([NSNumber numberWithInt:_configEpoch]);
    } else if ([@"getDeviceID" isEqualToString:call.method]) {
        result([Approov getDeviceID]);
    } else if ([@"getPins" isEqualToString:call.method]) {
        result([Approov getPins:call.arguments[@"pinType"]]);
    } else if ([@"setDataHashInToken" isEqualToString:call.method]) {
        [Approov setDataHashInToken:call.arguments[@"data"]];
        result(nil);
    } else if ([@"setDevKey" isEqualToString:call.method]) {
        [Approov setDevKey:call.arguments[@"devKey"]];
        result(nil);
    } else if ([@"getMessageSignature" isEqualToString:call.method]) {
    @try {
      result([Approov getMessageSignature:call.arguments[@"message"]]);
    }
    @catch (NSException *exception) {
      result([FlutterError errorWithCode:@"Approov.getMessageSignature"
                                 message:exception.reason
                                 details:nil]);
    }
    } else if ([@"getAccountMessageSignature" isEqualToString:call.method]) {
    @try {
      if ([Approov respondsToSelector:@selector(getAccountMessageSignature:)]) {
        result([Approov getAccountMessageSignature:call.arguments[@"message"]]);
      } else {
        result([Approov getMessageSignature:call.arguments[@"message"]]);
      }
    }
    @catch (NSException *exception) {
      result([FlutterError errorWithCode:@"Approov.getAccountMessageSignature"
                                 message:exception.reason
                                 details:nil]);
    }
    } else if ([@"getInstallMessageSignature" isEqualToString:call.method]) {
    @try {
      result([Approov getInstallMessageSignature:call.arguments[@"message"]]);
    }
    @catch (NSException *exception) {
            result([FlutterError errorWithCode:@"Approov.getInstallMessageSignature"
                                       message:exception.reason
                                       details:nil]);
        }
    } else if ([@"setUserProperty" isEqualToString:call.method]) {
        [Approov setUserProperty:call.arguments[@"property"]];
        result(nil);
    } else if ([@"fetchHostCertificates" isEqualToString:call.method]) {
        NSString *urlString = call.arguments[@"url"];
        NSURL *url = [NSURL URLWithString:urlString];
        if (url == nil) {
            // return an error if the URL is invalid
            result([FlutterError errorWithCode:[NSString stringWithFormat:@"%d", -1]
                message:NSURLErrorDomain
                details:[NSString stringWithFormat:@"Fetch host certificates invalid URL: %@", urlString]]);
        } else {
            // start the certificate fetch process asynchronously
            NSString *transactionID = call.arguments[@"transactionID"];
            BOOL performCallBack = [call.arguments[@"performCallBack"] isEqualToString:@"YES"];
            CertificatesFetcher *certFetcher = [[CertificatesFetcher alloc]
                initWithTransactionID:transactionID channel:(performCallBack ? _fgChannel : nil)];
            [certFetcher fetchWithURL:url];
            if (!performCallBack) {
                @synchronized(_activeCertFetches) {
                    [_activeCertFetches setObject:certFetcher forKey:transactionID];
                }
            }
            result(nil);
        }
    } else if ([@"waitForHostCertificates" isEqualToString:call.method]) {
        NSString *transactionID = call.arguments[@"transactionID"];
        CertificatesFetcher *certFetcher = nil;
        @synchronized(_activeCertFetches) {
            certFetcher = [_activeCertFetches objectForKey:transactionID];
        }
        if (certFetcher == nil) {
            result([FlutterError errorWithCode:[NSString stringWithFormat:@"%d", -1]
                message:@"ApproovService has no active certificate fetch"
                details:@"No active certificate fetch for transaction ID"]);
        } else {
            @synchronized(_activeCertFetches) {
                [_activeCertFetches removeObjectForKey:transactionID];
            }
            NSDictionary *certResults = [certFetcher getResult];
            result(certResults);
        }
    } else if ([@"fetchApproovToken" isEqualToString:call.method]) {
        NSString *transactionID = call.arguments[@"transactionID"];
        BOOL performCallBack = [call.arguments[@"performCallBack"] isEqualToString:@"YES"];
        InternalCallBackHandler *callBackHandler = [[InternalCallBackHandler alloc] initWithTransactionID:transactionID
            channel:(performCallBack ? _fgChannel : nil) configEpoch:_configEpoch];
        [Approov fetchApproovToken:^(ApproovTokenFetchResult *tokenFetchResult) {
            [callBackHandler postWithTokenFetchResult:tokenFetchResult];
        } :call.arguments[@"url"]];
        if (!performCallBack) {
            @synchronized(_activeCallBackHandlers) {
                [_activeCallBackHandlers setObject:callBackHandler forKey:transactionID];
            }
        }
        result(nil);
    } else if ([@"fetchSecureString" isEqualToString:call.method]) {
        NSString *transactionID = call.arguments[@"transactionID"];
        NSString *newDef = nil;
        if (call.arguments[@"newDef"] != [NSNull null])
            newDef = call.arguments[@"newDef"];
        BOOL performCallBack = [call.arguments[@"performCallBack"] isEqualToString:@"YES"];
        InternalCallBackHandler *callBackHandler = [[InternalCallBackHandler alloc] initWithTransactionID:transactionID
            channel:(performCallBack ? _fgChannel : nil) configEpoch:_configEpoch];
        [Approov fetchSecureString:^(ApproovTokenFetchResult *tokenFetchResult) {
            [callBackHandler postWithTokenFetchResult:tokenFetchResult];
        } :call.arguments[@"key"] :newDef];
        if (!performCallBack) {
            @synchronized(_activeCallBackHandlers) {
                [_activeCallBackHandlers setObject:callBackHandler forKey:transactionID];
            }
        }
        result(nil);
    } else if ([@"fetchCustomJWT" isEqualToString:call.method]) {
        NSString *transactionID = call.arguments[@"transactionID"];
        BOOL performCallBack = [call.arguments[@"performCallBack"] isEqualToString:@"YES"];
        InternalCallBackHandler *callBackHandler = [[InternalCallBackHandler alloc] initWithTransactionID:transactionID
            channel:(performCallBack ? _fgChannel : nil) configEpoch:_configEpoch];
        [Approov fetchCustomJWT:^(ApproovTokenFetchResult *tokenFetchResult) {
            [callBackHandler postWithTokenFetchResult:tokenFetchResult];
        } :call.arguments[@"payload"]];
        if (!performCallBack) {
            @synchronized(_activeCallBackHandlers) {
                [_activeCallBackHandlers setObject:callBackHandler forKey:transactionID];
            }
        }
        result(nil);
    } else if ([@"waitForFetchValue" isEqualToString:call.method]) {
        NSString *transactionID = call.arguments[@"transactionID"];
        InternalCallBackHandler *callBackHandler = nil;
        @synchronized(_activeCallBackHandlers) {
            callBackHandler = [_activeCallBackHandlers objectForKey:transactionID];
        }
        if (callBackHandler == nil) {
        result([FlutterError errorWithCode:[NSString stringWithFormat:@"%d", -1]
            message:@"ApproovService has no active fetch"
            details:@"No active fetch for transaction ID"]);
        } else {
            @synchronized(_activeCallBackHandlers) {
                [_activeCallBackHandlers removeObjectForKey:transactionID];
            }
            result([callBackHandler getResult]);
        }
    } else {
        result(FlutterMethodNotImplemented);
    }
}

@end
