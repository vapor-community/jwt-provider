import PackageDescription

let package = Package(
    name: "VaporJWT",
    dependencies: [
    	.Package(url:"https://github.com/vapor/jwt.git", majorVersion: 0),
    	.Package(url:"https://github.com/vapor/vapor.git", majorVersion: 1),
    ]
)
