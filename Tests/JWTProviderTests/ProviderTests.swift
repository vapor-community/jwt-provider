import XCTest
import Vapor
@testable import JWTProvider

class ProviderTests: XCTestCase {

    static let allTests = [
        ("testBootWithJWKSURL", testBootWithJWKSURL),
        ("testBootWithJWTSigner", testBootWithJWTSigner),
        ("testBootWithJWTSigners", testBootWithJWTSigners),
        ("testBootWithoutProvider", testBootWithoutProvider)
    ]

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
        try config.set("jwt.signer.type", "unsigned")

        try config.addProvider(JWTProvider.Provider.self)

        let drop = try Droplet(config: config, middleware: [])

        XCTAssertNotNil(drop.signers)
        XCTAssertNotNil(drop.signers?[jwtLegacySignerKey])
        XCTAssertNil(drop.jwksURL)
    }

    func testBootWithJWTSigners() throws {

        var config = try Config(arguments: ["vapor", "serve", "--env=test"])
        try config.set("jwt.signers", [
                "1234": Config(["type": "unsigned"]),
                "5678": Config(["type": "unsigned"])
            ])

        try config.addProvider(JWTProvider.Provider.self)

        let drop = try Droplet(config: config, middleware: [])

        XCTAssertNotNil(drop.signers)
        XCTAssertEqual(drop.signers?.count, 2)
        XCTAssertNotNil(drop.signers?["1234"])
        XCTAssertNotNil(drop.signers?["5678"])
        XCTAssertNil(drop.jwksURL)
    }

    func testBootWithoutProvider() throws {

        let config = try Config(arguments: ["vapor", "serve", "--env=test"])
        let drop = try Droplet(config: config, middleware: [])

        XCTAssertNil(drop.signers)
        XCTAssertNil(drop.jwksURL)
    }
}
