import Vapor
import JWT

private let jwtSignersKey = "jwt-provider:signers"

extension Droplet {
    public internal(set) var signers: SignerMap? {
        get { return storage[jwtSignersKey] as? SignerMap }
        set { storage[jwtSignersKey] = newValue }
    }
    
    /// Returns the JWT signers
    /// or throws an error if not properly configured
    public func assertSigners() throws -> SignerMap {
        guard let signers = self.signers else {
            throw JWTProviderError.noJWTSigner
        }

        return signers
    }
}

private let jwtJWKSURL = "jwt-provider:jwks-url"

extension Droplet {
    public internal(set) var jwksURL: String? {
        get { return storage[jwtJWKSURL] as? String }
        set { storage[jwtJWKSURL] = newValue }
    }

    /// Returns the JWKS URL
    /// or throws an error if not properly configured
    public func assertJWKSURL() throws -> String {
        guard let jwksURL = self.jwksURL else {
            throw JWTProviderError.noJWKSURL
        }

        return jwksURL
    }
}
