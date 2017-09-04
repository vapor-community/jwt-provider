import Vapor
import JWT

/// Adds required JWT objects to your application
/// like token Signers
public final class Provider: Vapor.Provider {
    public static let repositoryName = "jwt-provider"

    public let jwksURL: String?
    public let signers: SignerMap?

    public init(signers: SignerMap) {
        self.jwksURL = nil
        self.signers = signers
    }

    public init(jwksURL: String) {
        self.jwksURL = jwksURL
        self.signers = nil
    }

    public convenience init(config: Config) throws {

        guard let jwt = config["jwt"] else {
            throw ConfigError.missingFile("jwt")
        }

        // There should always be at least one signer or a jwks URL
        if let signers = try SignerMap(jwt: jwt) {
            self.init(signers: signers)
        } else if let jwksURL = jwt["jwks-url"]?.string {
            self.init(jwksURL: jwksURL)
        } else {
            throw ConfigError.missing(key: ["jwks-url' or 'signers"], file: "jwt", desiredType: String.self)
        }
    }
    
    public func boot(_ config: Config) throws {
        config.signers = signers
        config.jwksURL = self.jwksURL
    }

    public func boot(_ drop: Droplet) throws { }

    public func beforeRun(_ drop: Droplet) { }
}
