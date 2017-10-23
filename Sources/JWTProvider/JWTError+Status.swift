import Vapor
import HTTP
import JWT


extension JWTError: AbortError {
   public var status: Status {
        switch self {
        case .incorrectNumberOfSegments,
             .incorrectPayloadForClaimVerification,
             .missingAlgorithm,
             .missingClaim,
             .wrongAlgorithm,
             .verificationFailedForClaim,
             .signatureVerificationFailed:
            return .unauthorized
        default:
            return .internalServerError
        }
    }
}

extension JWTError: Debuggable {
    public var reason: String {
        return self.description
    }

    public var identifier: String {
        return self.description
    }

    public var possibleCauses: [String] {
        return []
    }

    public var suggestedFixes: [String] {
        return []
    }
}

