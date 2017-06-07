import XCTest
import Vapor
@testable import JWTProvider

class ProviderTests: XCTestCase {

    static let allTests = [
        ("testBootWithJWKS", testBootWithJWKS),
        ("testBootWithJWKSURL", testBootWithJWKSURL),
        ("testBootWithJWTSigner", testBootWithJWTSigner),
        ("testBootWithoutProvider", testBootWithoutProvider)
    ]

    func testBootWithJWKS() throws {

        var config = try Config(arguments: ["vapor", "serve", "--env=test"])
        try config.set("jwks.keys", [JSON()])

        try config.addProvider(JWTProvider.Provider.self)

        let drop = try Droplet(config: config, middleware: [])

        XCTAssertNotNil(drop.signers)
        XCTAssertNil(drop.jwksURL)
    }

    func testBootWithJWKSURL() throws {

        var config = try Config(arguments: ["vapor", "serve", "--env=test"])
        try config.set("jwt.jwks-url", "http://localhost/jwks.json")

        try config.addProvider(JWTProvider.Provider.self)

        let drop = try Droplet(config: config, middleware: [])

        XCTAssertNil(drop.signers)
        XCTAssertEqual(drop.jwksURL, "http://localhost/jwks.json")
    }

    func testBootWithJWTSigner() throws {

        var config = try Config(arguments: ["vapor", "serve", "--env=test"])
        try config.set("jwt.signer.kid", "1234")
        try config.set("jwt.signer.type", "unsigned")

        try config.addProvider(JWTProvider.Provider.self)

        let drop = try Droplet(config: config, middleware: [])

        XCTAssertNotNil(drop.signers)
        XCTAssertNotNil(drop.signers?["1234"])
        XCTAssertNil(drop.jwksURL)
    }

    func testBootWithoutProvider() throws {

        let config = try Config(arguments: ["vapor", "serve", "--env=test"])
        let drop = try Droplet(config: config, middleware: [])

        XCTAssertNil(drop.signers)
        XCTAssertNil(drop.jwksURL)
    }
}
