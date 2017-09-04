import JWT

private let jwtLegacySignerKey = "jwt-providers:legacy-signer"

internal extension Dictionary where Key == String, Value == Signer {
    internal init(legacySigner: Signer) {
        self = [jwtLegacySignerKey: legacySigner]
    }

    var legacySigner: Signer? {
        get {
            return self[jwtLegacySignerKey]
        }
        set {
            self[jwtLegacySignerKey] = newValue
        }
    }
}
