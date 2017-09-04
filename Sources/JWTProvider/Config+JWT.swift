import JWT
import Vapor

// MARK: Signer map access

private let jwtSignersKey = "jwt-provider:signers"

extension Config {
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

    /// Returns the JWT signer with the supplied identifier key
    public func assertSigner(kid: String) throws -> Signer {
        let signers = try assertSigners()
        guard let signer = signers[kid] else {
            throw JWTProviderError.noJWTSigner
        }
        return signer
    }
}

// MARK: JSON Web Key Set (JWKS) URL access

private let jwtJWKSURLKey = "jwt-provider:jwks-url"

extension Config {
    
    /// Returns the JWKS URL
    public internal(set) var jwksURL: String? {
        get { return storage[jwtJWKSURLKey] as? String }
        set { storage[jwtJWKSURLKey] = newValue }
    }

    /// Returns the JWKS URL
    /// or throws an error if not properly configured
    public func assertJWKSURL() throws -> String {
        guard let jwksURL = jwksURL else {
            throw JWTProviderError.noJWTSigner
        }

        return jwksURL
    }
}
