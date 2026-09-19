// swift-tools-version: 5.9
import PackageDescription
import Foundation

let projectRoot = URL(fileURLWithPath: #file).deletingLastPathComponent().deletingLastPathComponent().path

let package = Package(
    name: "CrexMacOS",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "CrexApp", targets: ["CrexApp"])
    ],
    targets: [
        .target(
            name: "CrexCoreC",
            path: "Sources/CrexCoreC",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "CrexApp",
            dependencies: ["CrexCoreC"],
            path: "Sources/CrexApp",
            linkerSettings: [
                .unsafeFlags([
                    "-L\(projectRoot)/target/debug",
                    "-lcrex_core"
                ])
            ]
        )
    ]
)
