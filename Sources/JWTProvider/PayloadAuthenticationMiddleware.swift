import Vapor
import JWT
import HTTP
import Node
import Authentication
import AuthProvider

/// Parses JWT and creates an ephemeral session,
/// logging the user in with credentials from the token.
public final class PayloadAuthenticationMiddleware<U: PayloadAuthenticatable>: Middleware {
    let signer: Signer
    let claims: [Claim]

    /// Create a LoginMiddleware specifying
    /// the JWT signer and type of payload
    /// that will be stored in the JWT
    public init(
        _ signer: Signer,
        _ claims: [Claim] = [],
        _ userType: U.Type = U.self
    ) {
        self.signer = signer
        self.claims = claims
    }

    public func respond(to req: Request, chainingTo next: Responder) throws -> Response {
        // if the user has already been authenticated
        // by a previous middleware, continue
        if req.auth.isAuthenticated(U.self) {
            return try next.respond(to: req)
        }

        // verify the jwt against the signer and claims
        let jwt = try req.jwt(verifyUsing: signer, and: claims)

        // create Payload type from the raw payload
        let payload = try U.PayloadType.init(json: jwt.payload)

        // Log the user in with an Identifier credential
        // This amounts to fetching the user from the DB
        let u = try U.authenticate(payload)
        req.auth.authenticate(u)

        return try next.respond(to: req)
    }
}
