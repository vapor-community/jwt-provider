import HTTP
import JWT

extension Request {
    /// Parses and returns a JWT from the request
    /// if one exists.
    /// The JWT will also be verified with the supplied
    /// signer.
    public func jwt(verifyUsing signer: Signer) throws -> JWT {
        // Try to get the authorization header
        guard let authHeader = auth.header else {
            throw AuthenticationError.noAuthorizationHeader
        }

        // Try to retrieve the bearer token
        guard let bearer = authHeader.bearer else {
            throw AuthenticationError.invalidBearerAuthorization
        }

        // Parse the bearer string into a JWT
        let jwt: JWT
        do {
            jwt = try JWT(token: bearer.string)
        } catch {
            throw AuthenticationError.invalidJWT(origin: error)
        }

        try jwt.verify(using: signer)

        return jwt
    }
}

extension JWT {
    /// Verifies the JWT with a given signer
    /// and throws `AuthError`s on failure
    public func verify(using signer: Signer) throws {
        // Verify the integrity and authenticity of the JWT
        do {
            try verifySignature(using: signer)
        } catch JWTError.signatureVerificationFailed {
            throw AuthenticationError.jwtSignatureVerificationFailed
        } catch {
            throw AuthenticationError.invalidJWTSignature(origin: error)
        }
    }
}
