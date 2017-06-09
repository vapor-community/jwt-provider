import Foundation
import JWT
import Vapor

public struct JWTConfigSignerFactory: SignerFactory {

    public let signerConfig: Config

    public init(signerConfig: Config) {
        self.signerConfig = signerConfig
    }

    public func makeSigner() throws -> Signer {

        guard let signerType = signerConfig["type"]?.string else {
            throw ConfigError.missing(key: ["signer", "type"], file: "jwt", desiredType: String.self)
        }

        let signer: Signer

        switch signerType {
        case "unsigned":
            signer = Unsigned()
        case "hmac":
            guard let algorithm = signerConfig["algorithm"]?.string else {
                throw ConfigError.missing(key: ["signer", "algorithm"], file: "jwt", desiredType: String.self)
            }

            guard let key = signerConfig["key"]?.string else {
                throw ConfigError.missing(key: ["signer", "key"], file: "jwt", desiredType: String.self)
            }

            let bytes = key.makeBytes()

            switch algorithm {
            case "hs256":
                signer = HS256(key: bytes)
            case "hs384":
                signer = HS384(key: bytes)
            case "hs512":
                signer = HS512(key: bytes)
            default:
                throw ConfigError.unsupported(value: algorithm, key: ["signer", "algorithm"], file: "jwt")
            }
        case "rsa":
            guard let algorithm = signerConfig["algorithm"]?.string else {
                throw ConfigError.missing(key: ["signer", "algorithm"], file: "jwt", desiredType: String.self)
            }

            guard let key = signerConfig["key"]?.string else {
                throw ConfigError.missing(key: ["signer", "key"], file: "jwt", desiredType: String.self)
            }

            let bytes = key.makeBytes().base64Decoded

            switch algorithm {
            case "rs256":
                signer = try RS256(key: bytes)
            case "rs384":
                signer = try RS384(key: bytes)
            case "rs512":
                signer = try RS512(key: bytes)
            default:
                throw ConfigError.unsupported(value: algorithm, key: ["signer", "algorithm"], file: "jwt")
            }
        case "esdca":
            guard let algorithm = signerConfig["algorithm"]?.string else {
                throw ConfigError.missing(key: ["signer", "algorithm"], file: "jwt", desiredType  : String.self)
            }

            guard let key = signerConfig["key"]?.string else {
                throw ConfigError.missing(key: ["signer", "key"], file: "jwt", desiredType: String.self)
            }

            let bytes = key.makeBytes()

            switch algorithm {
            case "es256":
                signer = ES256(key: bytes)
            case "es384":
                signer = ES384(key: bytes)
            case "es512":
                signer = ES512(key: bytes)
            default:
                throw ConfigError.unsupported(value: algorithm, key: ["signer", "algorithm"], file: "jwt")
            }
        default:
            throw ConfigError.unsupported(value: signerType, key: ["signer", "type"], file: "jwt")
        }

        return signer
    }
}
