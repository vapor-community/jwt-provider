import JSON
import Authentication

/// Types conforming to this protocol can be 
/// authenticated with some specified payload type
/// Use this in conjunction with VaporJWT.AuthenticationMiddleware
public protocol PayloadAuthenticatable: Authenticatable {
    /// Any NodeInitializable type representing
    /// the payload in the JWT
    associatedtype PayloadType: JSONInitializable

    /// Authenticates Self using the Payload
    /// returning an instance of Self to be logged in 
    static func authenticate(_ payload: PayloadType) throws -> Self
}
