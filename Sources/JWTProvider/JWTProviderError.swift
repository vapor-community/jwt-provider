import Vapor
import HTTP

public enum JWTProviderError: Error {
    case noVerifiedJWT
    case noJWTSigner
    case noJWKSURL
}

extension JWTProviderError: AbortError {
    public var status: Status {
        switch self {
        case .noJWTSigner, .noJWKSURL:
            return .internalServerError
        case .noVerifiedJWT:
            return .forbidden
        }
    }
}

extension JWTProviderError: Debuggable {
    public var reason: String {
        switch self {
        case .noVerifiedJWT:
            return "No verified JWT"
        case .noJWTSigner, .noJWKSURL:
            return "No JWT signer"
        }
    }
    
    public var identifier: String {
        switch self {
        case .noJWTSigner:
            return "noJWTSigner"
        case .noVerifiedJWT:
            return "noVerifiedJWT"
        case .noJWKSURL:
            return "noJWKSURL"
        }
    }
    
    public var possibleCauses: [String] {
        return []
    }
    
    public var suggestedFixes: [String] {
        return []
    }
}
