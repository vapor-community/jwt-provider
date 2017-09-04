import Foundation
import JWT
import JSON

public struct JWKSignerFactory: SignerFactory {
    private enum JSONKey: String {
        case alg
        case kid
        case kty
        case d
        case n
        case e
    }

    public let jwk: JSON

    public init(jwk: JSON) {
        self.jwk = jwk
    }

    public func makeSigner() throws -> Signer {

        let kty = (try jwk.get(JSONKey.kty.rawValue) as String).lowercased()

        let alg = (try jwk.get(JSONKey.alg.rawValue) as String).lowercased()

        switch kty {
        case "rsa":

            let key: RSAKey

            if let n: String = try jwk.get(JSONKey.n.rawValue), let e: String = try jwk.get(JSONKey.e.rawValue) {
                key = try RSAKey(n: n, e: e, d: try? jwk.get(JSONKey.d.rawValue))
            } else {
                throw JWKSignerFactoryError.missingSigningKey
            }

            switch alg {
            case "rs256":
                return RS256(rsaKey: key)
            case "rs384":
                return RS384(rsaKey: key)
            case "rs512":
                return RS512(rsaKey: key)
            default:
                throw JWKSignerFactoryError.unsupportedSignerAlgorithm(alg)
            }
        default:
            throw JWKSignerFactoryError.unsupportedSignerType(kty)
        }
    }
}

public enum JWKSignerFactoryError: Swift.Error {
    case missingSigningKey
    case unsupportedSignerType(String)
    case unsupportedSignerAlgorithm(String)
}
