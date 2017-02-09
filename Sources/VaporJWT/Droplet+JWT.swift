import Vapor
import JWT

private let jwtSignerKey = "jwtSigner"

extension Droplet {
    /// Returns the main JWT signer
    /// or throws an error if not properly configured
    public func jwtSigner() throws -> Signer {
        guard let signer = storage[jwtSignerKey] as? Signer else {
            throw ConfigError.noSigner()
        }

        return signer
    }

    /// Used internally to set the droplet's
    /// main JWT signer
    internal func set(_ signer: Signer) {
        storage[jwtSignerKey] = signer
    }
}
