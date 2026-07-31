// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Sentinel",
    platforms: [
        .macOS(.v14)
    ],
    targets: [
        .executableTarget(
            name: "Sentinel",
            path: "Sources/Sentinel",
            swiftSettings: [
                .unsafeFlags(["-parse-as-library"])
            ]
        )
    ]
)
