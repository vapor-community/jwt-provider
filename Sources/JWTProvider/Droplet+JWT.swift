import Vapor
import JWT

private let jwtSignerKey = "jwt-provider:signer"

extension Droplet {
    /// Returns the main JWT signer
    /// or throws an error if not properly configured
    public func signer() throws -> Signer {
        guard let signer = storage[jwtSignerKey] as? Signer else {
            throw JWTProviderError.noJWTSigner
        }

        return signer
    }

    /// Used internally to set the droplet's
    /// main JWT signer
    internal func set(_ signer: Signer) {
        storage[jwtSignerKey] = signer
    }
}
