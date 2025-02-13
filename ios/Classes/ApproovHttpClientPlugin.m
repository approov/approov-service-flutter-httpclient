/**
* Copyright 2022 CriticalBlue Ltd.
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
 */
- (nullable instancetype)init;

/**
 * Fetches the certificates for a host by setting up an HTTPS GET request and harvests the certificates
 * that are obtained by the NSURLSessionTaskDelegate protocol. The certificates can then be obtained
 * with a getCertificates call. Note that the certificate fetching is done in the background so this
 * constructor will return immediately.
 *
 * @param url is the URL to be used for the lookup
 */
- (void)fetchWithURL:(NSURL *_Nonnull)url;

/**
 * Get the host certificates for the URL. This methods waits until the certficates are available.
 *
 * @return the host certificates or nil if there was an error
 */
- (NSArray<FlutterStandardTypedData *> *)getCertificates;

// NSURLSession to use for the certificate fetch
@property NSURLSession *session;

// Semaphore for waiting on the certificate fetch to complete
@property dispatch_semaphore_t certFetchComplete;

// Any error that occurred during the certificate fetch
@property NSError *certFetchError;

// Host certificates that were fetched
@property NSArray<FlutterStandardTypedData *> *hostCertificates;

@end

// Implementation of the HostCertificatesFetcher which obtains certificate chains for particular domains in order to implement the pinning.
@implementation HostCertificatesFetcher

// see interface for documentation
- (nullable instancetype)init
{
    self = [super init];
    if (self) {
        // Create the Session
        NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        sessionConfig.timeoutIntervalForResource = FETCH_CERTIFICATES_TIMEOUT;
        NSOperationQueue *queue = [[NSOperationQueue alloc] init];
        queue.qualityOfService = NSQualityOfServiceUserInteractive;
        _session = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:queue];

        // Set up a semaphore so we can detect when the request completed
        _certFetchComplete = dispatch_semaphore_create(0);
    }
    return self;
}

// see interface for documentation
- (void)fetchWithURL:(NSURL *_Nonnull)url
{
    // Create the request
    NSMutableURLRequest *certFetchRequest = [NSMutableURLRequest requestWithURL:url];
    [certFetchRequest setTimeoutInterval:FETCH_CERTIFICATES_TIMEOUT];
    [certFetchRequest setHTTPMethod:@"GET"];

    // Get session task to issue the request, write back any error on completion and signal the semaphore
    // to indicate that it is complete
    NSURLSessionDataTask *certFetchTask = [_session dataTaskWithRequest:certFetchRequest
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error)
        {
            self.certFetchError = error;
            dispatch_semaphore_signal(self.certFetchComplete);
        }];

    // Make the request
    certFetchTask.priority = NSURLSessionTaskPriorityHigh;
    [certFetchTask resume];
}

// Collect the host certificates using the certificate check of the NSURLSessionTaskDelegate protocol
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    // Ignore any requests that are not related to server trust
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
        return;

    // Check we have a server trust
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    if (!serverTrust) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // Check the validity of the server trust
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

    // Collect all the certs in the chain
    CFIndex certCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray<FlutterStandardTypedData *> *certs = [NSMutableArray arrayWithCapacity:(NSUInteger)certCount];
    for (int certIndex = 0; certIndex < certCount; certIndex++) {
        // Get the chain certificate - note that this function is deprecated from iOS 15 but the
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

    // Set the host certs to be returned from fetchCertificates
    _hostCertificates = certs;

    // Fail the challenge as we only wanted the certificates
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

// see interface for documentation
- (NSArray<FlutterStandardTypedData *> *)getCertificates {
    // Wait on the semaphore which shows when the network request is completed - note we do not use
    // a timeout here since the NSURLSessionTask has its own timeouts
    dispatch_semaphore_wait(_certFetchComplete, DISPATCH_TIME_FOREVER);

    // We expect error cancelled because URLSession:task:didReceiveChallenge:completionHandler: always deliberately
    // fails the challenge because we don't need the request to succeed to retrieve the certificates
    if (!_certFetchError) {
        // If no error occurred, the certificate check of the NSURLSessionTaskDelegate protocol has not been called.
        // Don't return any host certificates.
        NSLog(@"Failed to get host certificates\n");
        return nil;
    }
    else if (_certFetchError.code != NSURLErrorCancelled) {
        // If an error other than NSURLErrorCancelled occurred, don't return any host certificates
        NSLog(@"Failed to get host certificates: Error: %@\n", _certFetchError.localizedDescription);
        return nil;
    }
    else {
        // The host certificates have been collected by the URLSession:task:didReceiveChallenge:completionHandler: method
        return _hostCertificates;
    }
}

@end

@interface ApproovHttpClientPlugin()

// Provides any prior initial configuration supplied, to allow a reinitialization caused by
// a hot restart if the configuration is the same
@property NSString *initializedConfig;

// Provides a map from the host name of any certificate prefetchers that are currently in flight
@property NSMutableDictionary<NSString *, HostCertificatesFetcher *> *certPrefetchers;

@end

// ApproovHttpClientPlugin provides the bridge to the Approov SDK itself. Methods are initiated using the
// MethodChannel to call various methods within the SDK. A facility is also provided to probe the certificates
// presented on any particular URL to implement the pinning. Note that the MethodChannel must run on a background
// thread since it makes blocking calls.
@implementation ApproovHttpClientPlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
    NSObject<FlutterTaskQueue>* taskQueue = [[registrar messenger] makeBackgroundTaskQueue];
    FlutterMethodChannel* channel = [[FlutterMethodChannel alloc]
                 initWithName: @"approov_service_flutter_httpclient"
              binaryMessenger: [registrar messenger]
                        codec: [FlutterStandardMethodCodec sharedInstance]
                    taskQueue: taskQueue];
    ApproovHttpClientPlugin* instance = [[ApproovHttpClientPlugin alloc] init];
    instance.certPrefetchers = [[NSMutableDictionary alloc] init];
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
        if ((_initializedConfig == nil) || ![_initializedConfig isEqualToString:initialConfig] || (call.arguments[@"comment"] != [NSNull null])) {
            // only actually initialize if we haven't before, if there is a change in the
            // configuration provided or thi is a new renitialization
            NSString *updateConfig = nil;
            if (call.arguments[@"updateConfig"] != [NSNull null])
                updateConfig = call.arguments[@"updateConfig"];
            NSString *comment = nil;
            if (call.arguments[@"comment"] != [NSNull null])
                comment = call.arguments[@"comment"];
            [Approov initialize:initialConfig updateConfig:updateConfig comment:comment error:&error];
            if (error == nil) {
                _initializedConfig = initialConfig;
                result(nil);
            } else {
                result([FlutterError errorWithCode:[NSString stringWithFormat:@"%ld", (long)error.code]
                    message:error.domain details:error.localizedDescription]);
            }
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
     } else if ([@"fetchApproovToken" isEqualToString:call.method]) {
        [Approov fetchApproovToken:^(ApproovTokenFetchResult *tokenFetchResult) {} :call.arguments[@"url"]];
        result(nil);
    } else if ([@"fetchApproovTokenAndWait" isEqualToString:call.method]) {
        ApproovTokenFetchResult *tokenFetchResult = [Approov fetchApproovTokenAndWait:call.arguments[@"url"]];
        NSMutableDictionary *tokenFetchResultMap = [NSMutableDictionary dictionary];
        tokenFetchResultMap[@"TokenFetchStatus"] = [ApproovHttpClientPlugin stringFromApproovTokenFetchStatus:tokenFetchResult.status];
        tokenFetchResultMap[@"Token"] = tokenFetchResult.token;
        tokenFetchResultMap[@"ARC"] = tokenFetchResult.ARC;
        tokenFetchResultMap[@"RejectionReasons"] = tokenFetchResult.rejectionReasons;
        tokenFetchResultMap[@"IsConfigChanged"] = [NSNumber numberWithBool:tokenFetchResult.isConfigChanged];
        tokenFetchResultMap[@"IsForceApplyPins"] = [NSNumber numberWithBool:tokenFetchResult.isForceApplyPins];
        tokenFetchResultMap[@"MeasurementConfig"] = tokenFetchResult.measurementConfig;
        tokenFetchResultMap[@"LoggableToken"] = tokenFetchResult.loggableToken;
        result((NSDictionary*)tokenFetchResultMap);
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
    } else if ([@"prefetchHostCertificates" isEqualToString:call.method]) {
        NSString *urlString = call.arguments[@"url"];
        NSURL *url = [NSURL URLWithString:urlString];
        if (url == nil) {
            result([FlutterError errorWithCode:[NSString stringWithFormat:@"%d", -1]
                message:NSURLErrorDomain
                details:[NSString stringWithFormat:@"Prefetch host certificates invalid URL: %@", urlString]]);
        } else {
            HostCertificatesFetcher *certPrefetcher = _certPrefetchers[url.host];
            if (certPrefetcher == nil) {
                certPrefetcher = [[HostCertificatesFetcher alloc] init];
                [certPrefetcher fetchWithURL:url];
                _certPrefetchers[url.host] = certPrefetcher;
            };
            result(nil);
        }
    } else if ([@"fetchHostCertificates" isEqualToString:call.method]) {
        NSString *urlString = call.arguments[@"url"];
        NSURL *url = [NSURL URLWithString:urlString];
        if (url == nil) {
            result([FlutterError errorWithCode:[NSString stringWithFormat:@"%d", -1]
                message:NSURLErrorDomain
                details:[NSString stringWithFormat:@"Fetch host certificates invalid URL: %@", urlString]]);
        } else {
            HostCertificatesFetcher *certPrefetcher = _certPrefetchers[url.host];
            if (certPrefetcher == nil) {
                NSLog(@"No certificate prefetch was performed for: %@\n", urlString);
                certPrefetcher = [[HostCertificatesFetcher alloc] init];
                [certPrefetcher fetchWithURL:url];
            }
            else {
                [_certPrefetchers removeObjectForKey:url.host];
            }
            result([certPrefetcher getCertificates]);
        }
    } else if ([@"fetchSecureStringAndWait" isEqualToString:call.method]) {
        NSString *newDef = nil;
        if (call.arguments[@"newDef"] != [NSNull null])
            newDef = call.arguments[@"newDef"];
        ApproovTokenFetchResult *tokenFetchResult = [Approov fetchSecureStringAndWait:call.arguments[@"key"] :newDef];
        NSMutableDictionary *fetchResultMap = [NSMutableDictionary dictionary];
        fetchResultMap[@"TokenFetchStatus"] = [ApproovHttpClientPlugin  stringFromApproovTokenFetchStatus:tokenFetchResult.status];
        fetchResultMap[@"Token"] = tokenFetchResult.token;
        if (tokenFetchResult.secureString != nil)
            fetchResultMap[@"SecureString"] = tokenFetchResult.secureString;
        fetchResultMap[@"ARC"] = tokenFetchResult.ARC;
        fetchResultMap[@"RejectionReasons"] = tokenFetchResult.rejectionReasons;
        fetchResultMap[@"IsConfigChanged"] = [NSNumber numberWithBool:tokenFetchResult.isConfigChanged];
        fetchResultMap[@"IsForceApplyPins"] = [NSNumber numberWithBool:tokenFetchResult.isForceApplyPins];
        fetchResultMap[@"LoggableToken"] = tokenFetchResult.loggableToken;
        result((NSDictionary*)fetchResultMap);
    } else if ([@"fetchCustomJWTAndWait" isEqualToString:call.method]) {
        ApproovTokenFetchResult *tokenFetchResult = [Approov fetchCustomJWTAndWait:call.arguments[@"payload"]];
        NSMutableDictionary *tokenFetchResultMap = [NSMutableDictionary dictionary];
        tokenFetchResultMap[@"TokenFetchStatus"] = [ApproovHttpClientPlugin stringFromApproovTokenFetchStatus:tokenFetchResult.status];
        tokenFetchResultMap[@"Token"] = tokenFetchResult.token;
        tokenFetchResultMap[@"ARC"] = tokenFetchResult.ARC;
        tokenFetchResultMap[@"RejectionReasons"] = tokenFetchResult.rejectionReasons;
        tokenFetchResultMap[@"IsConfigChanged"] = [NSNumber numberWithBool:tokenFetchResult.isConfigChanged];
        tokenFetchResultMap[@"IsForceApplyPins"] = [NSNumber numberWithBool:tokenFetchResult.isForceApplyPins];
        tokenFetchResultMap[@"LoggableToken"] = tokenFetchResult.loggableToken;
        result((NSDictionary*)tokenFetchResultMap);
    } else {
        result(FlutterMethodNotImplemented);
    }
}

@end
