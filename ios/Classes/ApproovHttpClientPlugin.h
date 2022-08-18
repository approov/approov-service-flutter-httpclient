#import <Flutter/Flutter.h>

@interface ApproovHttpClientPlugin: NSObject<FlutterPlugin>

// Provides any prior initial configuration supplied, to allow a reinitialization caused by
// a hot restart if the configuration is the same
@property NSString *initializedConfig;

@end
