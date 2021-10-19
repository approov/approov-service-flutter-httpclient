Pod::Spec.new do |s|
    s.name             = 'battery_plus'
    s.version          = '0.0.3'
    s.summary          = 'Flutter plugin for accessing Approov SDK attestation services.'
    s.description      = <<-DESC
  A Flutter plugin using mobile API protection provided by the Approov SDK.
                         DESC
    s.homepage         = 'https://github.com/flutter/plugins'
    s.license          = { :type => 'BSD', :file => '../LICENSE' }
    s.author           = { 'CriticalBlue' => 'ivol@criticalblue.com' }
    s.source           = { :http => 'https://github.com/approov/approov-service-flutter-httpclient' }
    #s.documentation_url = 'https://pub.dev/packages/battery_plus'
    s.source_files = 'Classes/**/*'
    s.public_header_files = 'Classes/**/*.h'
    s.dependency 'Flutter'
    s.dependency 'approov-ios-sdk' ~> 2.7.0
    s.platform = :ios, '10.0'
    # Flutter.framework does not contain an i386 slice.
    s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
    #s.pod_target_xcconfig = { 'VALID_ARCHS' => 'arm64 armv7 x86_64' }
    s.xcconfig = { 'OTHER_LDFLAGS' => '$(inherited) -framework Approov', 'ENABLE_BITCODE' => 'NO' }
  end