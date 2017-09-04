import JWT
import Vapor

extension Provider {
    @available(*, deprecated, message: "Use signers instead.")
    public var signer: Signer {
        if let legacySigner = signers?.legacySigner {
            return legacySigner
        } else if let signer = signers?.first?.value {
            return signer
        } else {
            fatalError("Trying to access a legacy signer when none has been specified.")
        }
    }

    @available(*, deprecated, message: "Use init(signers: SignerMap) instead.")
    public convenience init(signer: Signer) {
        self.init(signers: SignerMap(legacySigner: signer))
    }
}
