/// Errors thrown during the parsing, creation
/// and verification of JWT tokens by this package.
public struct AuthError: Swift.Error {
    public let code: Int
    public let reasonPhrase: String
    public let origin: Swift.Error?

    init(code: Int, reasonPhrase: String, origin: Swift.Error?) {
        self.code = code
        self.reasonPhrase = reasonPhrase
        self.origin = origin
    }

    public static func noAuthorizationHeader(_ origin: Swift.Error? = nil) -> Error {
        return self.init(
            code: 1,
            reasonPhrase: "No authorization header",
            origin: origin
        )
    }

    public static func invalidBearerAuthorization(_ origin: Swift.Error? = nil) -> Error {
        return self.init(
            code: 2,
            reasonPhrase: "Malformed bearer in authorization header",
            origin: origin
        )
    }

    public static func invalidJWT(_ origin: Swift.Error? = nil) -> Error {
        return self.init(
            code: 3,
            reasonPhrase: "Invalid JWT",
            origin: origin
        )
    }

    public static func invalidJWTSignature(_ origin: Swift.Error? = nil) -> Error {
        return self.init(
            code: 4,
            reasonPhrase: "Invalid JWT signature",
            origin: origin
        )
    }

    public static func invalidJWTPayload(_ origin: Swift.Error? = nil) -> Error {
        return self.init(
            code: 5,
            reasonPhrase: "Invalid JWT Payload",
            origin: origin
        )
    }

    public static func jwtSignatureFailed(_ origin: Swift.Error? = nil) -> Error {
        return self.init(
            code: 6,
            reasonPhrase: "Signature failed verification",
            origin: origin
        )
    }

    public static func loginFailed(_ origin: Swift.Error? = nil) -> Error {
        return self.init(
            code: 7,
            reasonPhrase: "Login failed",
            origin: origin
        )
    }
}

extension AuthError: Equatable {
    public static func ==(lhs: AuthError, rhs: AuthError) -> Bool {
        return lhs.code == rhs.code
    }
}

extension AuthError: CustomStringConvertible {
    public var description: String {
        let message: String

        if let origin = origin {
            message = "\(reasonPhrase): \(origin)"
        } else {
            message = reasonPhrase
        }

        return "JWT authentication failure: \(message)"
    }
}
