import JWT
import Vapor

private let jwtSignerKey = "jwt-provider:signer"

extension Config {
    public internal(set) var signer: Signer? {
        get { return storage[jwtSignerKey] as? Signer }
        set { storage[jwtSignerKey] = newValue }
    }

    /// Returns the main JWT signer
    /// or throws an error if not properly configured
    public func assertSigner() throws -> Signer {
        guard let signer = self.signer else {
            throw JWTProviderError.noJWTSigner
        }

        return signer
    }
}
