import Vapor
import HTTP

public enum JWTProviderError: Error {
    case noVerifiedJWT
    case noJWTSigner
}

extension JWTProviderError: AbortError {
    public var status: Status {
        switch self {
        case .noJWTSigner:
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
        case .noJWTSigner:
            return "No JWT signer"
        }
    }
    
    public var identifier: String {
        switch self {
        case .noJWTSigner:
            return "noJWTSigner"
        case .noVerifiedJWT:
            return "noVerifiedJWT"
        }
    }
    
    public var possibleCauses: [String] {
        return []
    }
    
    public var suggestedFixes: [String] {
        return []
    }
}
