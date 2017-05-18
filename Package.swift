import PackageDescription

let package = Package(
    name: "JWTProvider",
    dependencies: [
        // JSON Web Tokens in Swift by @siemensikkema.
    	.Package(url:"https://github.com/vapor/jwt.git", majorVersion: 2),

    	// Middleware and conveniences for using Auth in Vapor.
    	.Package(url:"https://github.com/vapor/auth-provider.git", majorVersion: 2),

    	// A web framework and server for Swift that works on macOS and Ubuntu.
    	.Package(url: "https://github.com/vapor/vapor.git", majorVersion: 2),
    ]
)
