// `Signer`s used to be stored on the `Droplet`'s storage.
// They have since been moved to `Config` to enable access
// to signers in `Configinitializable` objects
// (eg. `Providers`).
// This file makes sure the `Signer`s can still be accessed
// through from the Droplet.

import JWT
import Vapor

// MARK: Signer map access (via Config)

extension Droplet {

    /// Returns the JWT signers
    public internal(set) var signers: SignerMap? {
        get { return config.signers }
        set { config.signers = newValue }
    }
    
    /// Returns the JWT signers
    /// or throws an error if not properly configured
    public func assertSigners() throws -> SignerMap {
        return try config.assertSigners()
    }

    /// Returns the JWT signer with the supplied identifier key
    public func assertSigner(kid: String) throws -> Signer {
        return try config.assertSigner(kid: kid)
    }
}

// MARK: JSON Web Key Set (JWKS) URL access (via Config)

extension Droplet {

    /// Returns the JWKS URL
    public internal(set) var jwksURL: String? {
        get { return config.jwksURL }
        set { config.jwksURL = newValue }
    }

    /// Returns the JWKS URL
    /// or throws an error if not properly configured
    public func assertJWKSURL() throws -> String {
        return try config.assertJWKSURL()
    }
}
