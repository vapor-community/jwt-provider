// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "JWTProvider",
    products: [
    	.library(name: "JWTProvider", targets: ["JWTProvider"]),
    ],
    dependencies: [
        // JSON Web Tokens in Swift by @siemensikkema.
        .package(url:"https://github.com/vapor/jwt.git", .upToNextMajor(from: "2.0.0")),

        // Middleware and conveniences for using Auth in Vapor.
        .package(url:"https://github.com/vapor/auth-provider.git", .upToNextMajor(from: "1.0.0")),

        // A web framework and server for Swift that works on macOS and Ubuntu.
        .package(url: "https://github.com/vapor/vapor.git", .upToNextMajor(from: "2.2.0"))
    ],
    targets: [
    	.target(name: "JWTProvider", dependencies: ["JWT", "AuthProvider", "Vapor"]),
    	.testTarget(name: "JWTProviderTests", dependencies: ["JWTProvider"])
    ]
)
