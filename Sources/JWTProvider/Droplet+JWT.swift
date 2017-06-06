import Vapor
import JWT

private let jwtSignersKey = "jwt-provider:signers"

extension Droplet {
    public internal(set) var signers: [String: Signer]? {
        get { return storage[jwtSignersKey] as? [String: Signer] }
        set { storage[jwtSignersKey] = newValue }
    }
    
    /// Returns the JWT signers
    /// or throws an error if not properly configured
    public func assertSigners() throws -> [String: Signer] {
        guard let signers = self.signers else {
            throw JWTProviderError.noJWTSigner
        }

        return signers
    }
}
