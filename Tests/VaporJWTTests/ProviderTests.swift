import XCTest
@testable import VaporJWT

class ProviderTests: XCTestCase {
    static var allTests = [
        ("testExample", testExample),
    ]

    func testExample() {
        let error = AuthError.invalidBearerAuthorization()

        switch error {
        case AuthError.noAuthorizationHeader():
            print("foo")
        case AuthError.invalidJWT():
            print("bar")
        default: break
        }
    }
}
