import Vapor
import JWT

/// Adds required JWT objects to your application
/// like token Signers
public final class Provider: Vapor.Provider {

    public static let repositoryName = "jwt-provider"
    
    private let signers: SignerMap?

    private let jwksURL: String?

    public init(signers: SignerMap) {
        self.signers = signers
        self.jwksURL = nil
    }

    public init(jwksURL: String) {
        self.jwksURL = jwksURL
        self.signers = nil
    }

    public convenience init(config: Config) throws {

        if let jwks = config["jwks"] {
            self.init(signers: try SignerMap(jwks: JSON(jwks)))
        } else if let jwt = config["jwt"] {

            if let jwksURL = jwt["jwks-url"]?.string {
                self.init(jwksURL: jwksURL)
            } else {
                self.init(signers: try SignerMap(jwt: JSON(jwt)))
            }
        } else {
            throw ConfigError.missingFile("jwt")
        }
    }
    
    public func boot(_ config: Config) throws { }

    /// Called to prepare the Droplet.
    public func boot(_ drop: Droplet) {
        drop.signers = self.signers
        drop.jwksURL = self.jwksURL
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
