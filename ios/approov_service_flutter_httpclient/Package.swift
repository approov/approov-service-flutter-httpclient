// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "approov_service_flutter_httpclient",
    platforms: [
        .iOS("11.0")
    ],
    products: [
        .library(name: "approov-service-flutter-httpclient", targets: ["approov_service_flutter_httpclient"])
    ],
    dependencies: [
        .package(url: "https://github.com/approov/approov-ios-sdk.git", "3.5.3"..<"3.6.0")
    ],
    targets: [
        .target(
            name: "approov_service_flutter_httpclient",
            dependencies: [
                .product(name: "Approov", package: "approov-ios-sdk")
            ],
            cSettings: [
                .headerSearchPath("include/approov_service_flutter_httpclient")
            ]
        )
    ]
)
