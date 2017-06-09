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

        var map = [String: Signer]()

        for key in keys {

            guard let kid: String = try key.get("kid"),
                let signer = try? JSONWebKeySignerFactory(jwk: key).makeSigner()
                else {
                    continue
            }

            map[kid] = signer
        }

        self = map
    }

    public init?(jwt: Config) throws {

        if let signersConfig = jwt["signers"]?.array {

            var map = SignerMap()

            guard !signersConfig.isEmpty else {
                throw SignerMapError.noSigners
            }

            for signerConfig in signersConfig {

                let signer = try JWTConfigSignerFactory(signerConfig: signerConfig).makeSigner()

                guard let kid = signerConfig["kid"]?.string else {
                    throw ConfigError.missing(key: ["signers.kid"], file: "jwt", desiredType: String.self)
                }

                map[kid] = signer
            }

            self = map

        } else if let signerConfig = jwt["signer"] {

            // Legacy
            let signer = try JWTConfigSignerFactory(signerConfig: signerConfig).makeSigner()

            self = [jwtLegacySignerKey: signer]

        } else {
            return nil
        }
    }
}

public enum SignerMapError: Swift.Error {
    case missingKey(String)
    case noSigners
}
