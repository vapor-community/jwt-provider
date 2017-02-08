import Vapor
import JWT

/// Adds required JWT objects to your application
/// like token Signers
public final class Provider: Vapor.Provider {
    public let signer: Signer
    public init(signer: Signer) {
        self.signer = signer
    }

    /// Parses a `jwt.json` config file to create
    /// the JWT objects
    public convenience init(config: Config) throws {
        guard let jwt = config["jwt"]?.object else {
            throw ConfigError.noJWTConfigFile()
        }

        guard let signer = jwt["signer"]?.object else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer", type: Dictionary<String, Any>.self)
        }

        guard let signerType = signer["type"]?.string else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.type", type: String.self)

        }

        switch signerType.lowercased() {
        case "unsigned":
            self.init(signer: Unsigned())
        case "hmac":
            guard let algorithm = signer["algorithm"]?.string else {
                throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.algorithm", type: String.self)
            }

            guard let key = signer["key"]?.string else {
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
                throw ConfigError.invalidHMACSignerAlgorithm()
            }

            let signer = signerType.init(key: key.bytes)

            self.init(signer: signer)
        case "rsa":
            guard let algorithm = signer["algorithm"]?.string else {
                throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.algorithm", type: String.self)
            }

            guard let key = signer["key"]?.string else {
                throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.key.private", type: String.self)
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
                throw ConfigError.invalidHMACSignerAlgorithm()
            }

            let signer = signerType.init(key: key.base64Decoded)

            self.init(signer: signer)
        default:
            throw ConfigError.invalidSignerType()
        }

    }

    /// Called to prepare the Droplet.
    public func boot(_ drop: Droplet) {
        drop.setJWTSigner(signer)
    }

    /// Called after the Droplet has completed
    /// initialization and all provided items
    /// have been accepted.
    public func afterInit(_ drop: Droplet) {

    }

    /// Called before the Droplet begins serving
    /// which is @noreturn.
    public func beforeRun(_ drop: Droplet) {

    }
}
