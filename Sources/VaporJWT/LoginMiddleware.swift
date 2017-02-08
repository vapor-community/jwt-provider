import Vapor
import JWT
import HTTP
import Node

/// Parses JWT and creates an ephemeral session,
/// logging the user in with credentials from the token.
public final class LoginMiddleware: Middleware {
    let signer: Signer
    let payloadType: Payload.Type

    public init(
        signer: Signer,
        payloadType: Payload.Type
    ) {
        self.signer = signer
        self.payloadType = payloadType
    }

    public func respond(to req: Request, chainingTo next: Responder) throws -> Response {
        let token = try req.jwt(verifyUsing: signer)
        
        // extract the expected identifier from the payload
        let payload: Payload
        do {
            payload = try payloadType.init(node: token.payload)
        } catch {
            throw AuthError.invalidJWTPayload(error)
        }

        // Log the user in with an Identifier credential
        // This amounts to fetching the user from the DB
        do {
            let credentials = try payload.makeCredentials()
            try req.auth.login(credentials, persist: false)
        } catch {
            throw AuthError.loginFailed(error)
        }

        return try next.respond(to: req)
    }
}
