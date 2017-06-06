import Vapor
import JWT

/// Adds required JWT objects to your application
/// like token Signers
public final class Provider: Vapor.Provider {

    public static let repositoryName = "jwt-provider"
    
    public let signers: [String: Signer]

    public init(signers: [String: Signer]) {
        self.signers = signers
    }

    public convenience init(config: Config) throws {

        if let jwks = config["jwks"]?.object {
            self.init(signers: try Provider.signers(jwks: jwks))
        } else if let jwt = config["jwt"]?.object {
            self.init(signers: try Provider.signer(jwt: jwt))
        } else {
            throw ConfigError.missingFile("jwt")
        }
    }
    
    public func boot(_ config: Config) throws { }

    /// Called to prepare the Droplet.
    public func boot(_ drop: Droplet) {
        drop.signers = self.signers
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

fileprivate extension Provider {

    /**
     Parses a JSON Web Key Set `jwks.json` config file to create the JWT objects
     */
    fileprivate static func signers(jwks: [String: Config]) throws -> [String: Signer] {

        guard let keys = jwks["keys"]?.array else {
            throw ConfigError.missing(key: ["keys"], file: "jwks", desiredType: Array<Any>.self)
        }

        let jwkeys = keys.flatMap({ try? JSONWebKey(json: JSON($0)) })

        var signers = [String: Signer]()

        for jwk in jwkeys {

            guard let signer = try? jwk.makeSigner() else {
                continue
            }

            signers[jwk.kid] = signer
        }

        return signers
    }

    /**
     Parses a `jwt.json` config file to create the JWT objects
     */
    fileprivate static func signer(jwt: [String: Config]) throws -> [String: Signer] {

        guard let signerConfig = jwt["signer"]?.object else {
            throw ConfigError.missing(key: ["signer"], file: "jwt", desiredType: Dictionary<String, Any>.self)
        }

        guard let kid = signerConfig["kid"]?.string else {
            throw ConfigError.missing(key: ["kid"], file: "jwt", desiredType: String.self)
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

            let bytes = key.makeBytes()

            switch algorithm {
            case "hs256":
                signer = HS256(key: bytes)
            case "hs384":
                signer = HS384(key: bytes)
            case "hs512":
                signer = HS512(key: bytes)
            default:
                throw ConfigError.unsupported(value: algorithm, key: ["signer", "algorithm"], file: "jwt")
            }
        case "rsa":
            guard let algorithm = signerConfig["algorithm"]?.string else {
                throw ConfigError.missing(key: ["signer", "algorithm"], file: "jwt", desiredType: String.self)
            }

            guard let key = signerConfig["key"]?.string else {
                throw ConfigError.missing(key: ["signer", "key"], file: "jwt", desiredType: String.self)
            }

            let bytes = key.makeBytes().base64Decoded

            switch algorithm {
            case "rs256":
                signer = try RS256(key: bytes)
            case "rs384":
                signer = try RS384(key: bytes)
            case "rs512":
                signer = try RS512(key: bytes)
            default:
                throw ConfigError.unsupported(value: algorithm, key: ["signer", "algorithm"], file: "jwt")
            }
        case "esdca":
            guard let algorithm = signerConfig["algorithm"]?.string else {
                throw ConfigError.missing(key: ["signer", "algorithm"], file: "jwt", desiredType  : String.self)
            }

            guard let key = signerConfig["key"]?.string else {
                throw ConfigError.missing(key: ["signer", "key"], file: "jwt", desiredType: String.self)
            }

            let bytes = key.makeBytes()

            switch algorithm {
            case "es256":
                signer = ES256(key: bytes)
            case "es384":
                signer = ES384(key: bytes)
            case "es512":
                signer = ES512(key: bytes)
            default:
                throw ConfigError.unsupported(value: algorithm, key: ["signer", "algorithm"], file: "jwt")
            }
        default:
            throw ConfigError.unsupported(value: signerType, key: ["signer", "type"], file: "jwt")
        }
        
        return [kid: signer]
    }
}
