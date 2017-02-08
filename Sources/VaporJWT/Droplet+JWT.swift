import Vapor
import JWT

extension Droplet {
    /// Returns the main JWT signer
    /// or throws an error if not properly configured
    public func jwtSigner() throws -> Signer {
        guard let signer = storage["jwtSigner"] as? Signer else {
            throw ConfigError.noSigner()
        }

        return signer
    }

    /// Verifies the signature of a JWT
    /// using the droplet's main JWT signer
    public func verifySignature(_ jwt: JWT) throws {
        let signer = try jwtSigner()
        try jwt.verify(using: signer)
    }

    /// Used internally to set the droplet's
    /// main JWT signer
    internal func setJWTSigner(_ signer: Signer) {
        storage["jwtSigner"] = signer
    }
}
