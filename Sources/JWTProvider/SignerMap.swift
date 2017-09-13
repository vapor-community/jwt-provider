import Foundation
import Vapor
import JWT

/// Key: kid, Value: signer
public typealias SignerMap = [String: Signer]

public extension Dictionary where Key == String, Value == Signer {

    public init(jwks: JSON) throws {

        guard let keys = jwks["keys"]?.array else {
            throw SignerMapError.missingKey("keys")
        }

        var map = SignerMap()

        for key in keys {

            guard let kid: String = try key.get("kid"),
                let signer = try? JWKSignerFactory(jwk: key).makeSigner()
            else {
                continue
            }

            map[kid] = signer
        }

        self = map
    }

    public init?(jwt: Config) throws {
        if let signersConfig = jwt["signers"]?.object {

            var map = SignerMap()

            guard !signersConfig.isEmpty else {
                throw SignerMapError.noSigners
            }

            for (kid, signerConfig) in signersConfig {
                let signer = try JWTConfigSignerFactory(signerConfig: signerConfig).makeSigner()
                map[kid] = signer
            }

            self = map

        } else if let signerConfig = jwt["signer"] {

            // Legacy
            let signer = try JWTConfigSignerFactory(signerConfig: signerConfig).makeSigner()

            self = SignerMap(legacySigner: signer)

        } else {
            return nil
        }
    }
}

public enum SignerMapError: Swift.Error {
    case missingKey(String)
    case noSigners
}
