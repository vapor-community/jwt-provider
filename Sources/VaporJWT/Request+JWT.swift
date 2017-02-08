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
            throw AuthError.noAuthorizationHeader()
        }

        // Try to retrieve the bearer token
        guard let bearer = authHeader.bearer else {
            throw AuthError.invalidBearerAuthorization()
        }

        // Parse the bearer string into a JWT
        let token: JWT
        do {
            token = try JWT(token: bearer.string)
        } catch {
            throw AuthError.invalidJWT(error)
        }

        try token.verify(using: signer)

        return token
    }
}

extension JWT {
    /// Verifies the JWT with a given signer
    /// and throws `AuthError`s on failure
    public func verify(using signer: Signer) throws {
        // Verify the integrity and authenticity of the JWT
        let signaturePassed: Bool
        do {
            signaturePassed = try verifySignature(using: signer)
        } catch {
            throw AuthError.invalidJWTSignature(error)
        }

        guard signaturePassed else {
            throw AuthError.jwtSignatureFailed()
        }
    }
}
