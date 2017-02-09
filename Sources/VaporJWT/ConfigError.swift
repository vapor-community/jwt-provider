/// Errors that can take place during the config
/// of required JWT entities such as the signer
public struct ConfigError: Swift.Error {
    let code: Int
    let reasonPhrase: String

    public static func noJWTConfigFile() -> ConfigError {
        return ConfigError(code: 1, reasonPhrase: "No jwt.json config file found")
    }

    public static func jwtConfigMissingRequired(key: String, ofType type: Any.Type) -> ConfigError {
        return ConfigError(code: 2, reasonPhrase: "jwt.json config requires key '\(key)' of type \(type)")
    }

    public static func invalidSignerAlgorithm() -> ConfigError {
        return ConfigError(code: 3, reasonPhrase: "Unsupported signer algorithm specified in jwt.json")
    }

    public static func invalidSignerType() -> ConfigError {
        return ConfigError(code: 4, reasonPhrase: "Unsupported signer.type specified in jwt.json")
    }

    public static func noSigner() -> ConfigError {
        return ConfigError(code: 5, reasonPhrase: "JWT signer not properly configured.")
    }
}

extension ConfigError: Equatable {
    public static func ==(lhs: ConfigError, rhs: ConfigError) -> Bool {
        return lhs.code == rhs.code
    }
}

extension ConfigError: CustomStringConvertible {
    public var description: String {
        return "JWT config failure: \(reasonPhrase)"
    }
}
