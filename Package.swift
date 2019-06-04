// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

// We depend on Bsd.
var dependencies: [Package.Dependency] = []
#if os(Linux) // But only on Linux
dependencies.append(.package(url: "https://github.com/TaborKelly/Bsd.git", .upToNextMinor(from: "0.1.0")))
#endif

let package = Package(
    name: "Bcrypt",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "Bcrypt",
            targets: ["Bcrypt"]),
    ],
    dependencies: dependencies,
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "Bcrypt",
            dependencies: []),
        .testTarget(
            name: "BcryptTests",
            dependencies: ["Bcrypt"]),
    ]
)
