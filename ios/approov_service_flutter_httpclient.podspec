Pod::Spec.new do |s|
    s.name             = 'approov_service_flutter_httpclient'
    s.version          = '3.5.5'
    s.summary          = 'Flutter plugin for accessing Approov SDK attestation services.'
    s.description      = <<-DESC
  A Flutter plugin using mobile API protection provided by the Approov SDK. If the provided Approov SDK is configured to protect an API, then the plugin will automatically set up pinning and add relevant headers for any request to the API.
                         DESC
    s.homepage         = 'https://github.com/approov/approov_service_flutter_httpclient'
    s.license          = { :type => 'MIT', :file => '../LICENSE' }
    s.author           = { 'Approov Ltd' => 'support@approov.io' }
    s.source           = { :http => 'https://github.com/approov/approov-service-flutter-httpclient' }
    #s.documentation_url = 'https://pub.dev/packages/approov-service-flutter-httpclient'
    s.source_files = 'Classes/**/*'
    s.public_header_files = 'Classes/**/*.h'
    s.dependency 'Flutter'
    s.dependency 'approov-ios-sdk', '~> 3.5.3'
    s.platform = :ios, '11.0'
    # Flutter.framework does not contain an i386 slice.
    s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
    #s.pod_target_xcconfig = { 'VALID_ARCHS' => 'arm64 x86_64' }
    s.xcconfig = { 'OTHER_LDFLAGS' => '$(inherited) -framework Approov', 'ENABLE_BITCODE' => 'NO' }
  end
