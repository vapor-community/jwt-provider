import JWT
import Vapor

extension Droplet {

    /// Returns the JWT signer
    @available(*, deprecated, message: "Use signers instead.")
    public internal(set) var signer: Signer? {
        get { return signers?.legacySigner }
        set {
            if let signer = newValue {
                if signers != nil {
                    signers?.legacySigner = signer
                } else {
                    signers = SignerMap(legacySigner: signer)
                }
            } else {
                signers?.legacySigner = nil
            }
        }
    }

    /// Returns the main JWT signer
    /// or throws an error if not properly configured
    public func assertSigner() throws -> Signer {
        // NB. duplicated code from `signer` is necessary
        // to prevent deprecation warning
        guard let signer = signers?.legacySigner else {
            throw JWTProviderError.noJWTSigner
        }

        return signer
    }
}
