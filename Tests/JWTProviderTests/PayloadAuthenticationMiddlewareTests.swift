import XCTest
import JSON
import Vapor
import Transport
import HTTP
import JWT
@testable import JWTProvider

class PayloadAuthenticationMiddlewareTests: XCTestCase {

    static let allTests = [
        ("testAuthenticateWithLegacySigner", testAuthenticateWithLegacySigner),
        ("testAuthenticateWithNotIdentifiedToken", testAuthenticateWithNotIdentifiedToken),
        ("testAuthenticateWithIdentifiedToken", testAuthenticateWithIdentifiedToken),
        ("testAuthenticateWithIdentifiedTokenWithNoMatchingSigner", testAuthenticateWithIdentifiedTokenWithNoMatchingSigner),
        ("testAuthenticateWithJWKSURL", testAuthenticateWithJWKSURL),
    ]

    func testAuthenticateWithLegacySigner() throws {

        let signer = Unsigned()
        let jwt = try JWT(payload: JSON(), signer: signer)

        let request = Request(
            method: .get,
            uri: "http://localhost/test",
            headers: [HeaderKey.authorization: "Bearer \(try jwt.createToken())"]
        )

        let middleware = PayloadAuthenticationMiddleware<MockUser>(signer)

        _ = try middleware.respond(to: request, chainingTo: MockResponder())
    }

    func testAuthenticateWithNotIdentifiedToken() throws {

        let signers = ["1234": Unsigned(), "5678": Unsigned()]
        let jwt = try JWT(payload: JSON(), signer: signers["1234"]!)

        let request = Request(
            method: .get,
            uri: "http://localhost/test",
            headers: [HeaderKey.authorization: "Bearer \(try jwt.createToken())"]
        )

        let middleware = PayloadAuthenticationMiddleware<MockUser>(signers)

        XCTAssertThrowsError(try middleware.respond(to: request, chainingTo: MockResponder()), "noVerifiedJWT") { error in
            XCTAssertEqual(error as? JWTProviderError, JWTProviderError.noVerifiedJWT)
        }
    }

    func testAuthenticateWithIdentifiedToken() throws {

        let signers = ["1234": Unsigned(), "5678": Unsigned()]
        let jwt = try JWT(additionalHeaders: [KeyIDHeader(identifier: "1234")], payload: JSON(), signer: signers["1234"]!)

        let request = Request(
            method: .get,
            uri: "http://localhost/test",
            headers: [HeaderKey.authorization: "Bearer \(try jwt.createToken())"]
        )

        let middleware = PayloadAuthenticationMiddleware<MockUser>(signers)

        _ = try middleware.respond(to: request, chainingTo: MockResponder())
    }

    func testAuthenticateWithIdentifiedTokenWithNoMatchingSigner() throws {

        let signers = ["1234": Unsigned(), "5678": Unsigned()]
        let jwt = try JWT(additionalHeaders: [KeyIDHeader(identifier: "9999")], payload: JSON(), signer: Unsigned())

        let request = Request(
            method: .get,
            uri: "http://localhost/test",
            headers: [HeaderKey.authorization: "Bearer \(try jwt.createToken())"]
        )

        let middleware = PayloadAuthenticationMiddleware<MockUser>(signers)

        XCTAssertThrowsError(try middleware.respond(to: request, chainingTo: MockResponder()), "noJWTSigner") { error in
            XCTAssertEqual(error as? JWTProviderError, JWTProviderError.noJWTSigner)
        }
    }

    func testAuthenticateWithJWKSURL() throws {

        let privateSigner = try JWKSignerFactory(jwk: PayloadAuthenticationMiddlewareTests.privateJWK).makeSigner()

        let jwt = try JWT(additionalHeaders: [KeyIDHeader(identifier: "1234")], payload: JSON(), signer: privateSigner)

        let mockClientFactory = MockClientFactory(Response(
            status: .ok,
            headers: [HeaderKey.contentType: "application/json"],
            body: PayloadAuthenticationMiddlewareTests.publicJWKS
            ))

        let request = Request(
            method: .get,
            uri: "http://localhost/test",
            headers: [HeaderKey.authorization: "Bearer \(try jwt.createToken())"]
        )

        let middleware = PayloadAuthenticationMiddleware<MockUser>("http://my.domain.com/well-known/jwks.json", clientFactory: mockClientFactory)

        _ = try middleware.respond(to: request, chainingTo: MockResponder())
    }
}

extension PayloadAuthenticationMiddlewareTests {

    struct MockResponder: Responder {

        func respond(to request: Request) throws -> Response {
            return Response(status: .ok)
        }
    }

    struct MockUser: PayloadAuthenticatable, JSONInitializable {

        typealias PayloadType = MockUser

        static func authenticate(_ payload: PayloadType) throws -> MockUser {
            return try MockUser(json: JSON())
        }

        init(json: JSON) throws {
            
        }
    }

    class MockClientFactory: ClientFactoryProtocol {

        let defaultProxy: Proxy? = nil

        init(_ response: Response) {
            self.response = response
        }

        func makeClient(hostname: String, port: Transport.Port, securityLayer: SecurityLayer, proxy: Proxy?) throws -> ClientProtocol {
            fatalError()
        }

        var response: Response?

        func respond(to request: Request) throws -> Response {
            return self.response ?? Response(status: .ok)
        }
    }

    static var privateJWK: JSON {
        return try! JSON(bytes: "{\"kty\":\"RSA\",\"d\":\"L4z0tz7QWE0aGuOA32YqCSnrSYKdBTPFDILCdfHonzfP7WMPibz4jWxu_FzNk9s4Dh-uN2lV3NGW10pAsnqffD89LtYanRjaIdHnLW_PFo5fEL2yltK7qMB9hO1JegppKCfoc79W4-dr-4qy1Op0B3npOP-DaUYlNamfDmIbQW32UKeJzdGIn-_ryrBT7hQW6_uHLS2VFPPk0rNkPPKZYoNaqGnJ0eaFFF-dFwiThXIpPz--dxTAL8xYf275rjG8C9lh6awOfJSIdXMVuQITWf62E0mSQPR2-219bShMKriDYcYLbT3BJEgOkRBBHGuHo9R5TN298anxZqV1u5jtUQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"1234\",\"alg\":\"RS256\",\"n\":\"gWu7yhI35FScdKARYboJoAm-T7yJfJ9JTvAok_RKOJYcL8oLIRSeLqQX83PPZiWdKTdXaiGWntpDu6vW7VAb-HWPF6tNYSLKDSmR3sEu2488ibWijZtNTCKOSb_1iAKAI5BJ80LTqyQtqaKzT0XUBtMsde8vX1nKI05UxujfTX3kqUtkZgLv1Yk1ZDpUoLOWUTtCm68zpjtBrPiN8bU2jqCGFyMyyXys31xFRzz4MyJ5tREHkQCzx0g7AvW0ge_sBTPQ2U6NSkcZvQyDbfDv27cMUHij1Sjx16SY9a2naTuOgamjtUzyClPLVpchX-McNyS0tjdxWY_yRL9MYuw4AQ\"}")
    }

    static var publicJWKS: JSON {
        return try! JSON(bytes: "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"1234\",\"alg\":\"RS256\",\"n\":\"gWu7yhI35FScdKARYboJoAm-T7yJfJ9JTvAok_RKOJYcL8oLIRSeLqQX83PPZiWdKTdXaiGWntpDu6vW7VAb-HWPF6tNYSLKDSmR3sEu2488ibWijZtNTCKOSb_1iAKAI5BJ80LTqyQtqaKzT0XUBtMsde8vX1nKI05UxujfTX3kqUtkZgLv1Yk1ZDpUoLOWUTtCm68zpjtBrPiN8bU2jqCGFyMyyXys31xFRzz4MyJ5tREHkQCzx0g7AvW0ge_sBTPQ2U6NSkcZvQyDbfDv27cMUHij1Sjx16SY9a2naTuOgamjtUzyClPLVpchX-McNyS0tjdxWY_yRL9MYuw4AQ\"}]}")
    }
}
