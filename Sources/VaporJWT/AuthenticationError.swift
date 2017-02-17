/// Errors thrown during the parsing, creation
/// and verification of JWT tokens by this module.
public enum AuthenticationError: Error {
    case noAuthorizationHeader
    case invalidBearerAuthorization
    case invalidJWT(origin: Error)
    case invalidJWTSignature(origin: Error)
    case invalidJWTPayload(origin: Error)
    case jwtSignatureVerificationFailed
    case loginFailed(origin: Error)
    case unspecified(Error)
}

extension AuthenticationError: CustomStringConvertible {
    public var description: String {
        let reason: String

        switch self {
        case .noAuthorizationHeader:
            reason = "No authorization header"
        case .invalidBearerAuthorization:
            reason = "Malformed bearer in authorization header"
        case .invalidJWT(let origin):
            reason = "Invalid JWT: \(origin)"
        case .invalidJWTSignature(let origin):
            reason = "Invalid JWT signature: \(origin)"
        case .invalidJWTPayload(let origin):
            reason = "Invalid JWT payload: \(origin)"
        case .jwtSignatureVerificationFailed:
            reason = "JWT signature failed verification"
        case .loginFailed(let origin):
            reason = "Login failed: \(origin)"
        case .unspecified(let error):
            reason = "\(error)"
        }
        
        return "JWT authentication failure: \(reason)"
    }
}

