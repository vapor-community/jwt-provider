import Node
import Auth

/// Types conforming to this protocol
/// can be stored as payloads in JWTs
public protocol Payload: NodeConvertible {
    func makeCredentials() throws -> Auth.Credentials
}
