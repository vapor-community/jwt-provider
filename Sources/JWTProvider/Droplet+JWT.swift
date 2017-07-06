import JWT
import Vapor

extension Droplet {
    public internal(set) var signer: Signer? {
        get { return config.signer }
        set { config.signer = newValue }
    }

    /// Returns the main JWT signer
    /// or throws an error if not properly configured
    public func assertSigner() throws -> Signer {
        return try config.assertSigner()
    }
}
