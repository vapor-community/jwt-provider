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

        guard let signerConfig = jwt["signer"]?.object else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer", type: Dictionary<String, Any>.self)
        }

        guard let signerType = signerConfig["type"]?.string else {
            throw ConfigError.jwtConfigMissingRequiredKey(key: "signer.type", type: String.self)
        }

        let signer: Signer = try Provider.make(type: signerType, fromConfig: signerConfig)
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
