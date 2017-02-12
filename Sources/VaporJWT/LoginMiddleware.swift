import Vapor
import JWT
import HTTP
import Node

/// Parses JWT and creates an ephemeral session,
/// logging the user in with credentials from the token.
public final class LoginMiddleware: Middleware {
    let signer: Signer
    let payloadType: Payload.Type
    let claims: [Claim]

    /// Create a LoginMiddleware specifying
    /// the JWT signer and type of payload
    /// that will be stored in the JWT
    public init(
        signer: Signer,
        payloadType: Payload.Type,
        claims: [Claim] = []
    ) {
        self.signer = signer
        self.payloadType = payloadType
        self.claims = claims
    }

    public func respond(to req: Request, chainingTo next: Responder) throws -> Response {
        let jwt = try req.jwt(verifyUsing: signer)

        let payload: Payload
        do {
            // verify that the JWT fulfills the requirements
            // expressed in our claims
            try jwt.verifyClaims(claims)

            // extract the expected identifier from the payload
            payload = try payloadType.init(node: jwt.payload)
        } catch {
            throw AuthError.invalidJWTPayload(origin: error)
        }

        // Log the user in with an Identifier credential
        // This amounts to fetching the user from the DB
        do {
            let credentials = try payload.makeCredentials()
            try req.auth.login(credentials, persist: false)
        } catch {
            throw AuthError.loginFailed(origin: error)
        }

        return try next.respond(to: req)
    }
}
