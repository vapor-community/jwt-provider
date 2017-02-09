import JWT
import Vapor

/// creation of JWT signers from various
/// possible `jwt.json` configurations
extension Provider {
    static func make(type: String, fromConfig config: [String: Polymorphic]) throws -> Signer {
        let signer: Signer

        switch type.lowercased() {
        case "unsigned":
            signer = Unsigned()
        case "hmac":
            signer = try make(fromConfig: config) as HMACSigner
        case "rsa":
            signer = try make(fromConfig: config) as RSASigner
        case "esdca":
            signer = try make(fromConfig: config) as ECDSASigner
        default:
            throw ConfigError.invalidSignerType()
        }

        return signer
    }

    static func make(fromConfig config: [String: Polymorphic]) throws -> HMACSigner {
        guard let algorithm = config["algorithm"]?.string else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.algorithm", type: String.self)
        }

        guard let key = config["key"]?.string else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.key", type: String.self)
        }

        let signerType: HMACSigner.Type

        switch algorithm.lowercased() {
        case "hs256":
            signerType = HS256.self
        case "hs384":
            signerType = HS384.self
        case "hs512":
            signerType = HS512.self
        default:
            throw ConfigError.invalidSignerAlgorithm()
        }

        return signerType.init(key: key.bytes)
    }

    static func make(fromConfig config: [String: Polymorphic]) throws -> RSASigner {
        guard let algorithm = config["algorithm"]?.string else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.algorithm", type: String.self)
        }

        guard let key = config["key"]?.string else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.key", type: Dictionary<String, Any>.self)
        }

        let signerType: RSASigner.Type

        switch algorithm.lowercased() {
        case "rs256":
            signerType = RS256.self
        case "rs384":
            signerType = RS384.self
        case "rs512":
            signerType = RS512.self
        default:
            throw ConfigError.invalidSignerAlgorithm()
        }

        return signerType.init(key: key.base64Decoded)
    }

    static func make(fromConfig config: [String: Polymorphic]) throws -> ECDSASigner {
        guard let algorithm = config["algorithm"]?.string else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.algorithm", type: String.self)
        }

        guard let key = config["key"]?.string else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.key", type: String.self)
        }

        let signerType: ECDSASigner.Type

        switch algorithm.lowercased() {
        case "hs256":
            signerType = ES256.self
        case "hs384":
            signerType = ES384.self
        case "hs512":
            signerType = ES512.self
        default:
            throw ConfigError.invalidSignerAlgorithm()
        }
        
        return signerType.init(key: key.bytes)
    }
}
