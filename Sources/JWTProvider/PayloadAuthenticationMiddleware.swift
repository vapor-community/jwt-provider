import Vapor
import JWT
import HTTP
import Node
import Authentication
import AuthProvider

/// Parses JWT and creates an ephemeral session,
/// logging the user in with credentials from the token.
public final class PayloadAuthenticationMiddleware<U: PayloadAuthenticatable>: Middleware {
    internal private(set) var signers: [String: Signer]
    let claims: [Claim]
    let jwksURL: String?

    /// Create a LoginMiddleware specifying
    /// the JWT signers and type of payload
    /// that will be stored in the JWT
    public init(
        _ signers: [String: Signer],
        _ claims: [Claim] = [],
        _ userType: U.Type = U.self
    ) {
        self.signers = signers
        self.claims = claims
    }

    public init(
        _ jwksURL: String? = nil,
        _ claims: [Claim] = [],
        _ userType: U.Type = U.self
        ) {
        self.signers = [String: Signer]()
        self.jwksURL = jwksURL
        self.claims = claims
    }

    public func respond(to req: Request, chainingTo next: Responder) throws -> Response {
        // if the user has already been authenticated
        // by a previous middleware, continue
        if req.auth.isAuthenticated(U.self) {
            return try next.respond(to: req)
        }

        let jwt = try req.parseJWT()

        if let kid = jwt.headers["kid"]?.string, self.jwksURL != nil {

            // Verify using only the signers with matching kid
            _ = try req.jwt(verifyUsing: try self.signer(for: kid), and: claims)

        } else {
            // Try to use all the signers until one matches
            var verified = false

            for signer in signers.values {

                do {
                    _ = try req.jwt(verifyUsing: signer, and: claims)
                    verified = true
                    break
                } catch {
                    continue
                }
            }

            guard verified else {
                throw JWTProviderError.noJWTSigner
            }
        }



        // create Payload type from the raw payload
        let payload = try U.PayloadType.init(json: jwt.payload)

        // Log the user in with an Identifier credential
        // This amounts to fetching the user from the DB
        let u = try U.authenticate(payload)
        req.auth.authenticate(u)

        return try next.respond(to: req)
    }

    private func signer(for kid: String) throws -> Signer {

        if let signer = self.signers[kid] {
            return signer
        }

        /* GET jwks */

        if true /* signer */ {

        } else {
            throw JWTProviderError.noJWTSigner
        }
    }
}
