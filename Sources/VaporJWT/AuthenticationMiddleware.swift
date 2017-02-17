import Vapor
import JWT
import HTTP
import Node
import Authentication
import VaporAuth

/// Parses JWT and creates an ephemeral session,
/// logging the user in with credentials from the token.
public final class AuthenticationMiddleware<U: PayloadAuthenticatable>: Middleware {
    let signer: Signer
    let claims: [Claim]

    /// Create a LoginMiddleware specifying
    /// the JWT signer and type of payload
    /// that will be stored in the JWT
    public init(
        signer: Signer,
        userType: U.Type = U.self,
        claims: [Claim] = []
    ) {
        self.signer = signer
        self.claims = claims
    }

    public func respond(to req: Request, chainingTo next: Responder) throws -> Response {
        let jwt = try req.jwt(verifyUsing: signer)
        
        // extract the expected identifier from the payload
        let payload: U.Payload
        do {
            // verify that the JWT fulfills the requirements
            // expressed in our claims
            try jwt.verifyClaims(claims)

            // create Payload type from the raw payload
            payload = try U.Payload.init(node: jwt.payload)
        } catch {
            throw AuthenticationError.invalidJWTPayload(origin: error)
        }

        // Log the user in with an Identifier credential
        // This amounts to fetching the user from the DB
        do {
            let u = try U.authenticate(payload)
            req.auth.authenticate(u)
        } catch {
            throw AuthenticationError.loginFailed(origin: error)
        }

        return try next.respond(to: req)
    }
}
