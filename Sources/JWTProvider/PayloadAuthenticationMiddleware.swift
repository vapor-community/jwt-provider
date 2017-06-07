import Vapor
import JWT
import HTTP
import Node
import Authentication
import AuthProvider

/// Parses JWT and creates an ephemeral session,
/// logging the user in with credentials from the token.
public final class PayloadAuthenticationMiddleware<U: PayloadAuthenticatable>: Middleware {
    internal private(set) var signers: SignerMap
    let claims: [Claim]
    let jwksURL: String?

    /// Create a LoginMiddleware specifying
    /// the JWT signers and type of payload
    /// that will be stored in the JWT
    public init(
        _ signer: Signer,
        _ claims: [Claim] = [],
        _ userType: U.Type = U.self
        ) {
        self.signers = ["none": signer]
        self.claims = claims
        self.jwksURL = nil
    }

    public init(
        _ signers: SignerMap,
        _ claims: [Claim] = [],
        _ userType: U.Type = U.self
    ) {
        self.signers = signers
        self.claims = claims
        self.jwksURL = nil
    }

    public init(
        _ jwksURL: String,
        _ claims: [Claim] = [],
        _ userType: U.Type = U.self
        ) {
        self.signers = SignerMap()
        self.claims = claims
        self.jwksURL = jwksURL
    }

    public func respond(to req: Request, chainingTo next: Responder) throws -> Response {
        // if the user has already been authenticated
        // by a previous middleware, continue
        if req.auth.isAuthenticated(U.self) {
            return try next.respond(to: req)
        }

        let jwt = try req.parseJWT()

        let filteredSigners = try self.signers(for: jwt)

        // Try to use all the signers until one matches
        var verified = false

        for signer in filteredSigners {

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

        // create Payload type from the raw payload
        let payload = try U.PayloadType.init(json: jwt.payload)

        // Log the user in with an Identifier credential
        // This amounts to fetching the user from the DB
        let u = try U.authenticate(payload)
        req.auth.authenticate(u)

        return try next.respond(to: req)
    }

    // Identify which signers to use to verify the signature
    private func signers(for jwt: JWT) throws -> [Signer] {

        if let legacySigner = self.signers["_legacy"] {
            // Legacy signer, ignore any kid
            return [legacySigner]
        }

        guard let kid = jwt.keyIdentifier else {
            // The token doesn't include a kid, try to verify using all the signers
            return Array(self.signers.values)
        }

        if let signer = self.signers[kid] {
            // We have a signer with that kid cached
            return [signer]
        } else if let jwksURL = self.jwksURL {
            // We don't have any signer cached with that kid, but we have a jwks url

            // Get remote jwks.json
            guard let jwks = try EngineClientFactory().get(jwksURL).json else {
                throw JWTProviderError.noJWTSigner
            }

            // Update cache
            self.signers = try SignerMap(jwks: jwks)

            // Search again
            guard let signer = self.signers[kid] else {
                throw JWTProviderError.noJWTSigner
            }

            return [signer]

        } else {
            throw JWTProviderError.noJWTSigner
        }
    }
}
