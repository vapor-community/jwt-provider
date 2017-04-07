import PackageDescription

let package = Package(
    name: "JWTProvider",
    dependencies: [
        // JSON Web Tokens in Swift by @siemensikkema.
    	.Package(url:"https://github.com/vapor/jwt.git", Version(2,0,0, prereleaseIdentifiers: ["beta"])),

    	// Middleware and conveniences for using Auth in Vapor.
    	.Package(url:"https://github.com/vapor/auth-provider.git", Version(1,0,0, prereleaseIdentifiers: ["beta"])),

    	// A web framework and server for Swift that works on macOS and Ubuntu.
    	.Package(url: "https://github.com/vapor/vapor.git", Version(2,0,0, prereleaseIdentifiers: ["beta"]))
    ]
)
