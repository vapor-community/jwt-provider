import HTTP
import JWT
import Authentication

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
        let jwt = try JWT(token: bearer.string)
        try jwt.verifySignature(using: signer)

        return jwt
    }
}
