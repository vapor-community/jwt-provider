import PackageDescription

let package = Package(
    name: "VaporJWT",
    dependencies: [
    	.Package(url:"https://github.com/vapor/jwt.git", majorVersion: 0, minor: 8),
    	.Package(url: "https://github.com/vapor/vapor.git", Version(2, 0, 0, prereleaseIdentifiers: ["alpha"]))
    ]
)
