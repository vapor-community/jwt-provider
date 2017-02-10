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
            struct NoJWTConfig: Error, CustomStringConvertible {
                var description = "No `jwt.json` config file found."
            }
            throw ConfigError.unspecified(NoJWTConfig())
        }

        guard let signerConfig = jwt["signer"]?.object else {
            throw ConfigError.missing(key: ["signer"], file: "jwt", desiredType: Dictionary<String, Any>.self)
        }

        guard let signerType = signerConfig["type"]?.string else {
            throw ConfigError.missing(key: ["signer", "type"], file: "jwt", desiredType: String.self)
        }

        let signer: Signer

        switch signerType {
        case "unsigned":
            signer = Unsigned()
        case "hmac":
            guard let algorithm = signerConfig["algorithm"]?.string else {
                throw ConfigError.missing(key: ["signer", "algorithm"], file: "jwt", desiredType: String.self)
            }

            guard let key = signerConfig["key"]?.string else {
                throw ConfigError.missing(key: ["signer", "key"], file: "jwt", desiredType: String.self)
            }

            guard let hmac = Provider.hmacAlgorithm(from: algorithm) else {
                throw ConfigError.unsupported(value: algorithm, key: ["signer", "algorithm"], file: "jwt")
            }

            signer = hmac.init(key: key.bytes)
        case "rsa":
            guard let algorithm = signerConfig["algorithm"]?.string else {
                throw ConfigError.missing(key: ["signer", "algorithm"], file: "jwt", desiredType: String.self)
            }

            guard let key = signerConfig["key"]?.string else {
                throw ConfigError.missing(key: ["signer", "key"], file: "jwt", desiredType: String.self)
            }

            guard let hmac = Provider.rsaAlgorithm(from: algorithm) else {
                throw ConfigError.unsupported(value: algorithm, key: ["signer", "algorithm"], file: "jwt")
            }

            signer = hmac.init(key: key.bytes.base64Decoded)
        case "esdca":
            guard let algorithm = signerConfig["algorithm"]?.string else {
                throw ConfigError.missing(key: ["signer", "algorithm"], file: "jwt", desiredType: String.self)
            }

            guard let key = signerConfig["key"]?.string else {
                throw ConfigError.missing(key: ["signer", "key"], file: "jwt", desiredType: String.self)
            }

            guard let hmac = Provider.ecdsaAlgorithm(from: algorithm) else {
                throw ConfigError.unsupported(value: algorithm, key: ["signer", "algorithm"], file: "jwt")
            }

            signer = hmac.init(key: key.bytes)
        default:
            throw ConfigError.unsupported(value: signerType, key: ["signer", "type"], file: "jwt")
        }

        self.init(signer: signer)
    }

    /// Called to prepare the Droplet.
    public func boot(_ drop: Droplet) {
        drop.set(signer)
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

/// creation of JWT signers from various
/// possible `jwt.json` configurations
extension Provider {
    static func hmacAlgorithm(from string: String) -> HMACSigner.Type? {
        switch string {
        case "hs256":
            return HS256.self
        case "hs384":
            return HS384.self
        case "hs512":
            return HS512.self
        default:
            return nil
        }
    }

    static func rsaAlgorithm(from string: String) -> RSASigner.Type? {
        switch string {
        case "rs256":
            return RS256.self
        case "rs384":
            return RS384.self
        case "rs512":
            return RS512.self
        default:
            return nil
        }
    }

    static func ecdsaAlgorithm(from string: String) -> ECDSASigner.Type? {
        switch string {
        case "es256":
            return ES256.self
        case "es384":
            return ES384.self
        case "es512":
            return ES512.self
        default:
            return nil
        }
    }
}
