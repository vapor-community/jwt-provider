import Vapor
import JWT

let jwtLegacySignerKey = "jwtLegacySignerKey"

extension Droplet {
    @available(*, deprecated, message: "Use signers instead.")
    public internal(set) var signer: Signer? {
        get { return self.signers?[jwtLegacySignerKey] }
        set {
            if let signer = newValue {

                if self.signers != nil {
                    self.signers?[jwtLegacySignerKey] = signer
                } else {
                    self.signers = [jwtLegacySignerKey: signer]
                }
            } else {
                self.signers?[jwtLegacySignerKey] = nil
            }
        }
    }

    /// Returns the JWT signer
    /// or throws an error if not properly configured
    @available(*, deprecated, message: "Use assertSigners instead.")
    public func assertSigner() throws -> Signer {
        guard let signer = self.signer else {
            throw JWTProviderError.noJWTSigner
        }

        return signer
    }
}

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
