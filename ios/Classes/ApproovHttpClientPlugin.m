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
@interface HostCertificatesFetcher: NSObject<NSURLSessionTaskDelegate>

/**
 * Initialize ready to fetch certificates for a host.
 *
 * @param transactionID is the transaction ID to use for the fetch
 * @param channel is the FlutterMethodChannel to use for the communication with Flutter
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

// NSString of the transaction ID for the fetch
@property NSString *transactionID;

// FlutterMethodChannel to use for the communication with Flutter
@property FlutterMethodChannel *channel;

// NSURLSession to use for the certificate fetch
@property NSURLSession *session;

// Host certificates that were fetched
@property NSArray<FlutterStandardTypedData *> *hostCertificates;

@end

// Implementation of the HostCertificatesFetcher which obtains certificate chains for particular domains in order to implement the pinning.
@implementation HostCertificatesFetcher

// see interface for documentation
- (nullable instancetype)initWithTransactionID:(NSString *)transactionID channel:(FlutterMethodChannel *)channel
{
    self = [super init];
    if (self) {
        // hold the parameters for when the request is made
        _transactionID = transactionID;
        _channel = channel;

        // create the Session for the subsequent request
        NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        sessionConfig.timeoutIntervalForResource = FETCH_CERTIFICATES_TIMEOUT;
        _session = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:nil];
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
            // create a dicitonary for returning the results
            NSMutableDictionary *results = [NSMutableDictionary dictionary];
            results[@"TransactionID"] = _transactionID;

            // we expect error cancelled because URLSession:task:didReceiveChallenge:completionHandler: always deliberately
            // fails the challenge because we don't need the request to succeed to retrieve the certificates
            if (error == nil) {
                // if no error occurred, the certificate check of the NSURLSessionTaskDelegate protocol has not been called.
                // Don't provide any host certificates.
                results[@"Error"] = @"Failed to get host certificates";
            } else if (error.code != NSURLErrorCancelled) {
                // if an error other than NSURLErrorCancelled occurred, don't return any host certificates
                results[@"Error"] = [NSString stringWithFormat:@"Failed to get host certificates with error: %@",
                    error.localizedDescription];
            } else {
                // the host certificates have been collected by the URLSession:task:didReceiveChallenge:completionHandler: method
                results[@"Certificates"] = _hostCertificates;
            }

            // send the results back to the Flutter layer but we can only do this on the main thread
            dispatch_async(dispatch_get_main_queue(), ^{
               [_channel invokeMethod:@"response" arguments:results];
            });
        }];

    // Make the request
    [certFetchTask resume];
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

@interface ApproovHttpClientPlugin()

// The method channel to use for the communication with Flutter
@property FlutterMethodChannel *channel;

// Provides any prior initial configuration supplied, to allow a reinitialization caused by
// a hot restart if the configuration is the same
@property NSString *initializedConfig;

@end

// ApproovHttpClientPlugin provides the bridge to the Approov SDK itself. Methods are initiated using the
// MethodChannel to call various methods within the SDK. A facility is also provided to probe the certificates
// presented on any particular URL to implement the pinning.
@implementation ApproovHttpClientPlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
    FlutterMethodChannel *channel = [[FlutterMethodChannel alloc]
                 initWithName: @"approov_service_flutter_httpclient"
              binaryMessenger: [registrar messenger]
                        codec: [FlutterStandardMethodCodec sharedInstance]];
    ApproovHttpClientPlugin* instance = [[ApproovHttpClientPlugin alloc] init];
    instance.channel = channel;
    [registrar addMethodCallDelegate:instance channel:channel];
}

// Provides string mappings for the token fetch status with strings that are compatible with the common dart layer. This
// uses the Android style.
//
// @param approovTokenFetchStatus the fetch status from the iOS Approov SDK
// @return string representation of the status
+ (nonnull NSString *)stringFromApproovTokenFetchStatus:(ApproovTokenFetchStatus)approovTokenFetchStatus
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

- (void)handleMethodCall:(FlutterMethodCall *)call result:(FlutterResult)result {
    if ([@"initialize" isEqualToString:call.method]) {
        NSError* error = nil;
        NSString *initialConfig = call.arguments[@"initialConfig"];
        NSString *comment = nil;
        if (call.arguments[@"comment"] != [NSNull null])
            comment = call.arguments[@"comment"];
        else
            comment = @"";
        // check if initialization is permitted: no previous config or a
        // comment starting with "reinit"
        if ((_initializedConfig != nil) && ![comment hasPrefix:@"reinit"]) {
            result([FlutterError errorWithCode:[NSString stringWithFormat:@"%d", -1]
                message:@"ApproovService layer already initialized"
                details:@"The ApproovService may only be reinitialized in specific circumstances"]);
            return;
        }
        if ((_initializedConfig == nil) || ![_initializedConfig isEqualToString:initialConfig]) {
            // this is a new config or a reinitialization
            NSString *updateConfig = nil;
            if (call.arguments[@"updateConfig"] != [NSNull null])
                updateConfig = call.arguments[@"updateConfig"];
            [Approov initialize:initialConfig updateConfig:updateConfig comment:comment error:&error];
            if (error != nil) {
                // Check if the error message contains "Approov SDK already initialised"
                if ([error.localizedDescription rangeOfString:@"Approov SDK already initialised" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    NSLog(@"ApproovService: Ignoring initialization error in Approov SDK: %@", error.localizedDescription);
                } else {
                    result([FlutterError errorWithCode:[NSString stringWithFormat:@"%ld", (long)error.code]
                                            message:error.domain
                                            details:error.localizedDescription]);
                    return;
                }
            }
            _initializedConfig = initialConfig;
            result(nil);
        } else {
            // the previous initialization is compatible
            result(nil);
        }
    } else if ([@"fetchConfig" isEqualToString:call.method]) {
        result([Approov fetchConfig]);
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
        result([Approov getMessageSignature:call.arguments[@"message"]]);
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
            HostCertificatesFetcher *certFetcher = [[HostCertificatesFetcher alloc] initWithTransactionID:transactionID channel:_channel];
            [certFetcher fetchWithURL:url];
            result(nil);
        }
    } else if ([@"fetchApproovToken" isEqualToString:call.method]) {
        NSString *transactionID = call.arguments[@"transactionID"];
        [Approov fetchApproovToken:^(ApproovTokenFetchResult *tokenFetchResult) {
            // collect the results from the token fetch
            NSMutableDictionary *results = [NSMutableDictionary dictionary];
            results[@"TransactionID"] = transactionID;
            results[@"TokenFetchStatus"] = [ApproovHttpClientPlugin stringFromApproovTokenFetchStatus:tokenFetchResult.status];
            results[@"Token"] = tokenFetchResult.token;
            results[@"ARC"] = tokenFetchResult.ARC;
            results[@"RejectionReasons"] = tokenFetchResult.rejectionReasons;
            results[@"IsConfigChanged"] = [NSNumber numberWithBool:tokenFetchResult.isConfigChanged];
            results[@"IsForceApplyPins"] = [NSNumber numberWithBool:tokenFetchResult.isForceApplyPins];
            results[@"MeasurementConfig"] = tokenFetchResult.measurementConfig;
            results[@"LoggableToken"] = tokenFetchResult.loggableToken;

            // send the results back to the Flutter layer but we can only do this on the main thread
            dispatch_async(dispatch_get_main_queue(), ^{
               [_channel invokeMethod:@"response" arguments:results];
            });
        } :call.arguments[@"url"]];
        result(nil);
    } else if ([@"fetchSecureString" isEqualToString:call.method]) {
        NSString *transactionID = call.arguments[@"transactionID"];
        NSString *newDef = nil;
        if (call.arguments[@"newDef"] != [NSNull null])
            newDef = call.arguments[@"newDef"];
        [Approov fetchSecureString:^(ApproovTokenFetchResult *tokenFetchResult) {
            // collect the results from the secure string fetch
            NSMutableDictionary *results = [NSMutableDictionary dictionary];
            results[@"TransactionID"] = transactionID;
            results[@"TokenFetchStatus"] = [ApproovHttpClientPlugin  stringFromApproovTokenFetchStatus:tokenFetchResult.status];
            results[@"Token"] = tokenFetchResult.token;
            if (tokenFetchResult.secureString != nil)
               results[@"SecureString"] = tokenFetchResult.secureString;
            results[@"ARC"] = tokenFetchResult.ARC;
            results[@"RejectionReasons"] = tokenFetchResult.rejectionReasons;
            results[@"IsConfigChanged"] = [NSNumber numberWithBool:tokenFetchResult.isConfigChanged];
            results[@"IsForceApplyPins"] = [NSNumber numberWithBool:tokenFetchResult.isForceApplyPins];
            results[@"LoggableToken"] = tokenFetchResult.loggableToken;

            // send the results back to the Flutter layer but we can only do this on the main thread
            dispatch_async(dispatch_get_main_queue(), ^{
               [_channel invokeMethod:@"response" arguments:results];
            });
        } :call.arguments[@"key"] :newDef];
        result(nil);
    } else if ([@"fetchCustomJWT" isEqualToString:call.method]) {
        NSString *transactionID = call.arguments[@"transactionID"];
        [Approov fetchCustomJWT:^(ApproovTokenFetchResult *tokenFetchResult) {
            // collect the results from the custom JWT fetch
            NSMutableDictionary *results = [NSMutableDictionary dictionary];
            results[@"TransactionID"] = transactionID;
            results[@"TokenFetchStatus"] = [ApproovHttpClientPlugin stringFromApproovTokenFetchStatus:tokenFetchResult.status];
            results[@"Token"] = tokenFetchResult.token;
            results[@"ARC"] = tokenFetchResult.ARC;
            results[@"RejectionReasons"] = tokenFetchResult.rejectionReasons;
            results[@"IsConfigChanged"] = [NSNumber numberWithBool:tokenFetchResult.isConfigChanged];
            results[@"IsForceApplyPins"] = [NSNumber numberWithBool:tokenFetchResult.isForceApplyPins];
            results[@"LoggableToken"] = tokenFetchResult.loggableToken;

            // send the results back to the Flutter layer but we can only do this on the main thread
            dispatch_async(dispatch_get_main_queue(), ^{
               [_channel invokeMethod:@"response" arguments:results];
            });
        } :call.arguments[@"payload"]];
        result(nil);
    } else {
        result(FlutterMethodNotImplemented);
    }
}

@end
