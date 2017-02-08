/// Errors that can take place during the config
/// of required JWT entities such as the signer
public struct ConfigError: Swift.Error {
    var code: Int
    var reasonPhrase: String

    static func noJWTConfigFile() -> ConfigError {
        return ConfigError(code: 1, reasonPhrase: "No jwt.json config file found")
    }

    static func jwtConfigMissingRequiredKey(key: String, type: Any.Type) -> ConfigError {
        return ConfigError(code: 2, reasonPhrase: "jwt.json config requires key '\(key)' of type \(type)")
    }

    static func invalidHMACSignerAlgorithm() -> ConfigError {
        return ConfigError(code: 3, reasonPhrase: "Unsupported hmac algorithm specified in jwt.json")
    }

    static func invalidSignerType() -> ConfigError {
        return ConfigError(code: 4, reasonPhrase: "Unsupported signer.type specified in jwt.json")
    }

    static func noSigner() -> ConfigError {
        return ConfigError(code: 5, reasonPhrase: "JWT signer not properly configured.")
    }
}
